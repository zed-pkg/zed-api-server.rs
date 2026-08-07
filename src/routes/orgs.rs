//! Namespace claiming.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use fiducia_client::{FiduciaClient, LockHandle, LockOptions};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait,
    PaginatorTrait, QueryFilter, SqlErr, Statement, TransactionTrait,
};
use uuid::Uuid;
use zed_interfaces::manifest::is_slug;
use zed_interfaces::registry::{ClaimOrgRequest, ClaimOrgResponse};

use crate::auth::require_token;
use crate::entities::org;
use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;

/// Outer distributed lock for a token's claim: cross-replica FIFO queueing on
/// `zed-api/org-claim/{token_id}`. FAIL-OPEN by design — the advisory xact
/// lock inside the claim transaction is the correctness guarantee; fiducia
/// adds fair queueing across replicas and lock observability. A short TTL is
/// the crash backstop; release is best-effort.
async fn fiducia_org_claim_guard(
    state: &AppState,
    token_id: Uuid,
) -> Option<(Arc<FiduciaClient>, LockHandle)> {
    let client = state.fiducia.clone()?;
    let key = format!("zed-api/org-claim/{token_id}");
    let acquired = tokio::task::spawn_blocking(move || {
        let opts = LockOptions {
            ttl_ms: 15_000,
            max_wait: Duration::from_secs(5),
            ..LockOptions::default()
        };
        client
            .acquire_lock_handle(&[key.as_str()], opts)
            .map(|handle| (client, handle))
    })
    .await;
    match acquired {
        Ok(Ok(pair)) => Some(pair),
        Ok(Err(err)) => {
            tracing::warn!(
                "fiducia org-claim lock unavailable, relying on pg advisory lock: {err}"
            );
            None
        }
        Err(join_err) => {
            tracing::warn!("fiducia org-claim lock task failed: {join_err}");
            None
        }
    }
}

fn release_fiducia_guard(guard: Option<(Arc<FiduciaClient>, LockHandle)>) {
    if let Some((client, handle)) = guard {
        tokio::task::spawn_blocking(move || {
            if let Err(err) = client.release_lock(&handle) {
                tracing::warn!(
                    "fiducia org-claim release failed (lease TTL is the backstop): {err:?}"
                );
            }
        });
    }
}

pub async fn claim_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ClaimOrgRequest>,
) -> ApiResult<Json<ClaimOrgResponse>> {
    let token = require_token(&state.db, &headers).await?;
    if !is_slug(&request.slug) {
        return Err(ApiErr::bad_request(
            "invalid_slug",
            "org slugs are lowercase letters, digits, and hyphens",
        ));
    }
    if let Some(existing) = org::Entity::find()
        .filter(org::Column::Slug.eq(&request.slug))
        .one(&state.db)
        .await?
    {
        if token.org_id == Some(existing.id) {
            return Ok(Json(ClaimOrgResponse {
                slug: request.slug,
                created: false,
            }));
        }
        return Err(ApiErr::conflict(
            "org_taken",
            format!("org `{}` is already claimed", request.slug),
        ));
    }
    // The quota check has no unique-index backstop ("≤ K rows per token" is
    // inexpressible as a constraint), so the count and the insert must be one
    // critical section. Two layers, per docs: an OUTER fiducia lock queueing
    // claims for this token across replicas, and INSIDE it a Postgres
    // advisory xact lock owning correctness even if fiducia is down.
    let fiducia_guard = fiducia_org_claim_guard(&state, token.id).await;
    let outcome = claim_org_serialized(&state, &token, &request).await;
    release_fiducia_guard(fiducia_guard);
    outcome
}

async fn claim_org_serialized(
    state: &AppState,
    token: &crate::entities::token::Model,
    request: &ClaimOrgRequest,
) -> ApiResult<Json<ClaimOrgResponse>> {
    let txn = state.db.begin().await?;
    // Advisory lock, xact-scoped (auto-released on commit/rollback/crash),
    // keyed per token — mirrors the zed-sync outbox pattern. Postgres only;
    // the sqlite used in unit tests is single-connection and needs none.
    if state.db.get_database_backend() == DbBackend::Postgres {
        txn.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_advisory_xact_lock(hashtext($1))",
            [format!("zed-api:org-claim:{}", token.id).into()],
        ))
        .await?;
    }
    // Squatting quota: org-scoped tokens may only claim a bounded number of
    // namespaces; admin tokens (org_id = None) are exempt.
    if token.org_id.is_some() {
        let claimed = org::Entity::find()
            .filter(org::Column::CreatedByToken.eq(token.id))
            .count(&txn)
            .await?;
        if claimed >= state.max_orgs_per_token {
            return Err(ApiErr {
                status: StatusCode::FORBIDDEN,
                code: "org_quota_exceeded",
                message: format!(
                    "this token has already claimed {claimed} orgs (limit {}); contact the registry operator",
                    state.max_orgs_per_token
                ),
            });
        }
    }
    let new_org_id = Uuid::new_v4();
    let insert = org::ActiveModel {
        id: ActiveValue::Set(new_org_id),
        slug: ActiveValue::Set(request.slug.clone()),
        created_at: ActiveValue::Set(Utc::now()),
        created_by_token: ActiveValue::Set(Some(token.id)),
    }
    .insert(&txn)
    .await;
    if let Err(err) = insert {
        // A concurrent claim can win the unique `slug` index between the check
        // above and this insert; that is the same conflict as an already-claimed
        // org, not an internal error (M6).
        if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
            return Err(ApiErr::conflict(
                "org_taken",
                format!("org `{}` is already claimed", request.slug),
            ));
        }
        return Err(err.into());
    }
    txn.commit().await?;
    // Recorded against the newly created org, after commit (best-effort; see
    // `audit`) so the trail shows who first took the namespace.
    crate::audit::record(
        &state.db,
        new_org_id,
        token,
        zed_interfaces::registry::AuditAction::OrgClaim,
        request.slug.clone(),
        None,
    )
    .await;
    Ok(Json(ClaimOrgResponse {
        slug: request.slug.clone(),
        created: true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, EntityTrait, Schema,
    };

    use crate::auth::hash_token;
    use crate::config::{StorageConfig, TagPolicy};
    use crate::entities::token;
    use crate::storage::ArtifactStore;
    use crate::verify::TagVerifier;

    async fn test_state() -> Arc<AppState> {
        let mut opts = ConnectOptions::new("sqlite::memory:".to_string());
        opts.max_connections(1)
            .min_connections(1)
            .sqlx_logging(false);
        let db: DatabaseConnection = Database::connect(opts).await.unwrap();
        let backend = db.get_database_backend();
        let schema = Schema::new(backend);
        for stmt in [
            schema.create_table_from_entity(org::Entity),
            schema.create_table_from_entity(token::Entity),
        ] {
            db.execute(backend.build(&stmt)).await.unwrap();
        }
        let dir = std::env::temp_dir().join(format!("zed-api-org-test-{}", Uuid::new_v4()));
        Arc::new(AppState {
            db,
            store: ArtifactStore::from_config(&StorageConfig::Local {
                dir: dir.to_string_lossy().to_string(),
            })
            .await
            .unwrap(),
            verifier: TagVerifier::new(TagPolicy::Off),
            public_base_url: "http://localhost:8080".to_string(),
            max_orgs_per_token: 5,
            fiducia: None,
            rate_limiter: None,
        })
    }

    async fn seed_token(db: &DatabaseConnection, plaintext: &str, org_id: Option<Uuid>) -> Uuid {
        let id = Uuid::new_v4();
        token::ActiveModel {
            id: ActiveValue::Set(id),
            name: ActiveValue::Set("t".to_string()),
            token_hash: ActiveValue::Set(hash_token(plaintext)),
            org_id: ActiveValue::Set(org_id),
            role: ActiveValue::Set("owner".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            expires_at: ActiveValue::Set(None),
            revoked_at: ActiveValue::Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    fn bearer(plaintext: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {plaintext}").parse().unwrap(),
        );
        headers
    }

    /// M6: claiming an org already owned by a different token is a clean 409
    /// `org_taken`, never a 500.
    #[tokio::test]
    async fn claiming_a_taken_org_conflicts() {
        let state = test_state().await;
        let token_a = seed_token(&state.db, "admin_a", None).await;
        let _token_b = seed_token(&state.db, "admin_b", None).await;
        org::ActiveModel {
            id: ActiveValue::Set(Uuid::new_v4()),
            slug: ActiveValue::Set("acme".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            created_by_token: ActiveValue::Set(Some(token_a)),
        }
        .insert(&state.db)
        .await
        .unwrap();

        let err = claim_org(
            State(state.clone()),
            bearer("admin_b"),
            Json(ClaimOrgRequest {
                slug: "acme".to_string(),
            }),
        )
        .await
        .expect_err("claiming a taken org must fail");
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.code, "org_taken");
    }

    /// The squatting quota is enforced atomically inside the claim
    /// transaction: the (K+1)th claim by one token is a clean 403.
    #[tokio::test]
    async fn org_quota_is_enforced() {
        let state = test_state().await;
        let org_id = Uuid::new_v4();
        seed_token(&state.db, "scoped", Some(org_id)).await;

        for i in 0..5 {
            let resp = claim_org(
                State(state.clone()),
                bearer("scoped"),
                Json(ClaimOrgRequest {
                    slug: format!("org-{i}"),
                }),
            )
            .await
            .expect("claims under the quota succeed");
            assert!(resp.0.created);
        }
        let err = claim_org(
            State(state.clone()),
            bearer("scoped"),
            Json(ClaimOrgRequest {
                slug: "one-too-many".to_string(),
            }),
        )
        .await
        .expect_err("the claim over the quota must fail");
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.code, "org_quota_exceeded");
        assert_eq!(
            org::Entity::find().all(&state.db).await.unwrap().len(),
            5,
            "no org row is created past the quota"
        );
    }

    /// A brand-new slug is claimed successfully.
    #[tokio::test]
    async fn claiming_a_free_org_succeeds() {
        let state = test_state().await;
        seed_token(&state.db, "admin_a", None).await;

        let resp = claim_org(
            State(state.clone()),
            bearer("admin_a"),
            Json(ClaimOrgRequest {
                slug: "acme".to_string(),
            }),
        )
        .await
        .expect("claiming a free org succeeds");
        assert!(resp.0.created);
        assert_eq!(
            org::Entity::find().all(&state.db).await.unwrap().len(),
            1,
            "exactly one org row is created"
        );
    }
}
