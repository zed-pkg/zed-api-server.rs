//! Yank (or restore) a published version. Yanked versions stay downloadable
//! for existing lockfiles but are hidden from resolution and search.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use sea_orm::{ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, QueryFilter};
use zed_interfaces::registry::{YankRequest, YankResponse};

use crate::auth::require_token;
use crate::entities::version;
use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;

use super::{find_org, find_package};

pub async fn yank(
    State(state): State<Arc<AppState>>,
    Path((org_slug, name, ver)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(request): Json<YankRequest>,
) -> ApiResult<Json<YankResponse>> {
    let token = require_token(&state.db, &headers).await?;
    let org_row = find_org(&state, &org_slug).await?;
    // Yank/un-yank is a mutation of published state: same authority as publish.
    // Route through the shared authorizer so scope AND role stay enforced here
    // (a reader token must not be able to yank or restore versions) and cannot
    // drift apart from the publish path.
    crate::rbac::authorize_publish(
        token.org_id,
        crate::rbac::Role::parse(&token.role),
        org_row.id,
    )?;
    let pkg = find_package(&state, &org_row, &name).await?;
    let row = version::Entity::find()
        .filter(version::Column::PackageId.eq(pkg.id))
        .filter(version::Column::Version.eq(&ver))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiErr::not_found("version"))?;

    let mut active: version::ActiveModel = row.into();
    active.yanked = ActiveValue::Set(request.yanked);
    let updated = active.update(&state.db).await?;

    tracing::info!(org = %org_slug, name = %name, version = %ver, yanked = updated.yanked, "yank state changed");
    crate::audit::record(
        &state.db,
        org_row.id,
        &token,
        if updated.yanked {
            zed_interfaces::registry::AuditAction::Yank
        } else {
            zed_interfaces::registry::AuditAction::Unyank
        },
        format!("{org_slug}/{name}@{ver}"),
        None,
    )
    .await;
    Ok(Json(YankResponse {
        org: org_slug,
        name,
        version: ver,
        yanked: updated.yanked,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sea_orm::{
        ActiveValue, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, EntityTrait,
        Schema,
    };
    use uuid::Uuid;

    use crate::auth::hash_token;
    use crate::config::{StorageConfig, TagPolicy};
    use crate::entities::{org, package, token, version};
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
            schema.create_table_from_entity(package::Entity),
            schema.create_table_from_entity(version::Entity),
            schema.create_table_from_entity(crate::entities::audit_log::Entity),
        ] {
            db.execute(backend.build(&stmt)).await.unwrap();
        }
        let dir = std::env::temp_dir().join(format!("zed-api-yank-test-{}", Uuid::new_v4()));
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

    /// Seed org `acme` + package `acme/http-kit@1.0.0`, and a scoped token with
    /// `role`. Returns the token plaintext.
    async fn seed(state: &AppState, role: &str) -> String {
        let org_id = Uuid::new_v4();
        let pkg_id = Uuid::new_v4();
        let plaintext = format!("zpkg_{role}_{}", Uuid::new_v4().simple());
        org::ActiveModel {
            id: ActiveValue::Set(org_id),
            slug: ActiveValue::Set("acme".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            created_by_token: ActiveValue::Set(None),
        }
        .insert(&state.db)
        .await
        .unwrap();
        token::ActiveModel {
            id: ActiveValue::Set(Uuid::new_v4()),
            name: ActiveValue::Set("t".to_string()),
            token_hash: ActiveValue::Set(hash_token(&plaintext)),
            org_id: ActiveValue::Set(Some(org_id)),
            role: ActiveValue::Set(role.to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            expires_at: ActiveValue::Set(None),
            revoked_at: ActiveValue::Set(None),
        }
        .insert(&state.db)
        .await
        .unwrap();
        package::ActiveModel {
            id: ActiveValue::Set(pkg_id),
            org_id: ActiveValue::Set(org_id),
            name: ActiveValue::Set("http-kit".to_string()),
            description: ActiveValue::Set(None),
            vcs: ActiveValue::Set("git".to_string()),
            repo_url: ActiveValue::Set("https://github.com/acme/http-kit".to_string()),
            version_scheme: ActiveValue::Set("semver".to_string()),
            tags: ActiveValue::Set(serde_json::json!([])),
            created_at: ActiveValue::Set(Utc::now()),
        }
        .insert(&state.db)
        .await
        .unwrap();
        version::ActiveModel {
            id: ActiveValue::Set(Uuid::new_v4()),
            package_id: ActiveValue::Set(pkg_id),
            version: ActiveValue::Set("1.0.0".to_string()),
            sha256: ActiveValue::Set("a".repeat(64)),
            size: ActiveValue::Set(10),
            format: ActiveValue::Set("tar.gz".to_string()),
            vcs_tag: ActiveValue::Set("v1.0.0".to_string()),
            vcs_commit: ActiveValue::Set(None),
            artifact_key: ActiveValue::Set("artifacts/aaa.tar.gz".to_string()),
            yanked: ActiveValue::Set(false),
            published_at: ActiveValue::Set(Utc::now()),
        }
        .insert(&state.db)
        .await
        .unwrap();
        plaintext
    }

    fn bearer(plaintext: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {plaintext}").parse().unwrap(),
        );
        headers
    }

    fn call(
        state: &Arc<AppState>,
        headers: HeaderMap,
        yanked: bool,
    ) -> impl std::future::Future<Output = ApiResult<Json<YankResponse>>> {
        yank(
            State(state.clone()),
            Path(("acme".into(), "http-kit".into(), "1.0.0".into())),
            headers,
            Json(YankRequest { yanked }),
        )
    }

    async fn is_yanked(state: &AppState) -> bool {
        {
            version::Entity::find()
                .one(&state.db)
                .await
                .unwrap()
                .unwrap()
                .yanked
        }
    }

    /// A reader-scoped token must not be able to yank (or restore): yank is a
    /// mutation and requires a publishing role, exactly like publish.
    #[tokio::test]
    async fn reader_token_cannot_yank() {
        let state = test_state().await;
        let reader = seed(&state, "reader").await;

        let err = call(&state, bearer(&reader), true)
            .await
            .expect_err("reader must be forbidden from yanking");
        assert_eq!(err.code, "insufficient_role");
        assert!(
            !is_yanked(&state).await,
            "the version must remain un-yanked"
        );
    }

    /// Publisher and owner roles may yank and restore.
    #[tokio::test]
    async fn publisher_can_yank_and_restore() {
        let state = test_state().await;
        let publisher = seed(&state, "publisher").await;

        let resp = call(&state, bearer(&publisher), true).await.unwrap();
        assert!(resp.0.yanked);
        assert!(is_yanked(&state).await);

        let resp = call(&state, bearer(&publisher), false).await.unwrap();
        assert!(!resp.0.yanked);
        assert!(!is_yanked(&state).await);
    }

    /// A token scoped to a different org is unauthorized regardless of role
    /// (checked before role, so the message is `unauthorized`, not a role hint).
    #[tokio::test]
    async fn cross_org_token_cannot_yank() {
        let state = test_state().await;
        let _local = seed(&state, "owner").await;
        // A token owned by an unrelated org.
        let foreign_plaintext = format!("zpkg_foreign_{}", Uuid::new_v4().simple());
        let foreign_org = Uuid::new_v4();
        org::ActiveModel {
            id: ActiveValue::Set(foreign_org),
            slug: ActiveValue::Set("other".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            created_by_token: ActiveValue::Set(None),
        }
        .insert(&state.db)
        .await
        .unwrap();
        token::ActiveModel {
            id: ActiveValue::Set(Uuid::new_v4()),
            name: ActiveValue::Set("foreign".to_string()),
            token_hash: ActiveValue::Set(hash_token(&foreign_plaintext)),
            org_id: ActiveValue::Set(Some(foreign_org)),
            role: ActiveValue::Set("owner".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            expires_at: ActiveValue::Set(None),
            revoked_at: ActiveValue::Set(None),
        }
        .insert(&state.db)
        .await
        .unwrap();

        let err = call(&state, bearer(&foreign_plaintext), true)
            .await
            .expect_err("cross-org yank must fail");
        assert_eq!(err.code, "unauthorized");
        assert!(!is_yanked(&state).await);
    }

    /// A successful yank/restore leaves an audit record naming the actor and
    /// the exact version, and a *denied* attempt leaves none (zed-docs #7).
    #[tokio::test]
    async fn yank_is_audited_and_denials_are_not() {
        use crate::entities::audit_log;
        let state = test_state().await;
        let publisher = seed(&state, "publisher").await;

        let _ = call(&state, bearer(&publisher), true).await.unwrap();
        let rows = audit_log::Entity::find().all(&state.db).await.unwrap();
        assert_eq!(rows.len(), 1, "one audit row after a yank");
        assert_eq!(rows[0].action, "yank");
        assert_eq!(rows[0].subject, "acme/http-kit@1.0.0");
        assert_eq!(rows[0].actor_role, "publisher");
        assert_eq!(rows[0].actor_token_name, "t");

        // Restoring records the inverse action, not another `yank`.
        let _ = call(&state, bearer(&publisher), false).await.unwrap();
        let actions: Vec<String> = audit_log::Entity::find()
            .all(&state.db)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.action)
            .collect();
        assert!(actions.contains(&"unyank".to_string()), "got {actions:?}");

        // A refused yank must not be recorded as if it happened.
        let before = audit_log::Entity::find()
            .all(&state.db)
            .await
            .unwrap()
            .len();
        let reader = seed_reader(&state).await;
        call(&state, bearer(&reader), true).await.unwrap_err();
        let after = audit_log::Entity::find()
            .all(&state.db)
            .await
            .unwrap()
            .len();
        assert_eq!(before, after, "a denied mutation must not be audited");
    }

    /// Add a second, reader-scoped token to the already-seeded `acme` org.
    async fn seed_reader(state: &AppState) -> String {
        let org_id = org::Entity::find()
            .one(&state.db)
            .await
            .unwrap()
            .unwrap()
            .id;
        let plaintext = format!("zpkg_reader_{}", Uuid::new_v4().simple());
        token::ActiveModel {
            id: ActiveValue::Set(Uuid::new_v4()),
            name: ActiveValue::Set("r".to_string()),
            token_hash: ActiveValue::Set(hash_token(&plaintext)),
            org_id: ActiveValue::Set(Some(org_id)),
            role: ActiveValue::Set("reader".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            expires_at: ActiveValue::Set(None),
            revoked_at: ActiveValue::Set(None),
        }
        .insert(&state.db)
        .await
        .unwrap();
        plaintext
    }
}
