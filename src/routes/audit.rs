//! Read an org's audit log (zed-docs issue #7, governance).
//!
//! Owner-only: the trail names which token performed each mutation, so it is
//! not information a `publisher`/`reader` token should be able to enumerate.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;
use zed_interfaces::registry::{AuditAction, AuditEntry, AuditIntegrityResponse, AuditLogResponse};

use crate::auth::require_token;
use crate::entities::audit_log;
use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;

use super::find_org;

/// Newest-first page size when the caller doesn't ask, and the hard ceiling.
/// Bounded so a long-lived org cannot be used to force an unbounded response.
const DEFAULT_LIMIT: u64 = 100;
const MAX_LIMIT: u64 = 1000;
/// Ceiling on how many entries one verification walks. The chain has to be
/// read in order, so this bounds the work a single request can demand; the
/// response reports how many were checked.
const MAX_VERIFY_ROWS: u64 = 50_000;

#[derive(Debug, Default, Deserialize)]
pub struct AuditQuery {
    limit: Option<u64>,
    /// Restrict to one action (`publish`, `yank`, `unyank`, `org_claim`).
    action: Option<String>,
    /// Page backwards: only entries with a lower `seq` than this.
    before: Option<i64>,
}

pub async fn get_audit_log(
    State(state): State<Arc<AppState>>,
    Path(org_slug): Path<String>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> ApiResult<Json<AuditLogResponse>> {
    let token = require_token(&state.db, &headers).await?;
    let org_row = find_org(&state, &org_slug).await?;
    crate::rbac::authorize_manage(
        token.org_id,
        crate::rbac::Role::parse(&token.role),
        org_row.id,
    )?;

    // Reject an unknown action rather than silently returning everything: a
    // typo'd filter that looks like it worked is how an operator concludes
    // "nothing happened" when plenty did.
    if let Some(action) = &query.action
        && AuditAction::parse(action).is_none()
    {
        return Err(ApiErr::bad_request(
            "invalid_action",
            format!("unknown action `{action}`; expected publish, yank, unyank, or org_claim"),
        ));
    }

    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let mut find = audit_log::Entity::find().filter(audit_log::Column::OrgId.eq(org_row.id));
    if let Some(action) = &query.action {
        find = find.filter(audit_log::Column::Action.eq(action.clone()));
    }
    if let Some(before) = query.before {
        find = find.filter(audit_log::Column::Seq.lt(before));
    }
    // Order by seq, not time: seq is the chain's own total order, and two
    // entries can share a timestamp at the database's resolution.
    let rows = find
        .order_by_desc(audit_log::Column::Seq)
        .order_by_desc(audit_log::Column::At)
        .limit(limit)
        .all(&state.db)
        .await?;

    Ok(Json(AuditLogResponse {
        org: org_slug,
        entries: rows.into_iter().map(to_entry).collect(),
    }))
}

fn to_entry(r: audit_log::Model) -> AuditEntry {
    AuditEntry {
        at: r.at.to_rfc3339(),
        action_kind: AuditAction::parse(&r.action),
        action: r.action,
        subject: r.subject,
        actor_token_name: r.actor_token_name,
        actor_role: r.actor_role,
        detail: r.detail,
        seq: r.seq.max(0) as u64,
        entry_hash: r.entry_hash,
        prev_hash: r.prev_hash,
    }
}

/// Walk the org's chain and report whether it is intact.
///
/// This is the server checking itself, which is necessary but not sufficient:
/// the digest input lives in `zed-interfaces` precisely so an operator can
/// recompute the chain independently and compare an externally recorded
/// `head_hash`, which is what also catches truncation of the whole tail.
pub async fn verify_audit_log(
    State(state): State<Arc<AppState>>,
    Path(org_slug): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<AuditIntegrityResponse>> {
    let token = require_token(&state.db, &headers).await?;
    let org_row = find_org(&state, &org_slug).await?;
    crate::rbac::authorize_manage(
        token.org_id,
        crate::rbac::Role::parse(&token.role),
        org_row.id,
    )?;

    let rows = audit_log::Entity::find()
        .filter(audit_log::Column::OrgId.eq(org_row.id))
        .order_by_asc(audit_log::Column::Seq)
        .limit(MAX_VERIFY_ROWS)
        .all(&state.db)
        .await?;
    let report = crate::audit::verify_chain(&rows);

    Ok(Json(AuditIntegrityResponse {
        org: org_slug,
        intact: report.intact,
        entries_checked: report.entries_checked,
        first_bad_seq: report.first_bad_seq.map(|s| s.max(0) as u64),
        problem: report.problem.map(|p| p.as_str().to_string()),
        head_hash: report.head_hash,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sea_orm::{
        ActiveModelTrait, ActiveValue, ConnectOptions, ConnectionTrait, Database,
        DatabaseConnection, Schema,
    };
    use uuid::Uuid;
    use zed_interfaces::registry::AuditAction;

    use crate::auth::hash_token;
    use crate::config::{StorageConfig, TagPolicy};
    use crate::entities::{org, token};
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
            schema.create_table_from_entity(audit_log::Entity),
        ] {
            db.execute(backend.build(&stmt)).await.unwrap();
        }
        let dir = std::env::temp_dir().join(format!("zed-api-audit-test-{}", Uuid::new_v4()));
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
            // Unit tests call handlers directly and must not be throttled.
            rate_limiter: None,
        })
    }

    /// Seed org `acme` plus a token scoped to it with `role`; returns
    /// (org_id, token plaintext).
    async fn seed(state: &AppState, role: &str) -> (Uuid, String) {
        let org_id = Uuid::new_v4();
        org::ActiveModel {
            id: ActiveValue::Set(org_id),
            slug: ActiveValue::Set("acme".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            created_by_token: ActiveValue::Set(None),
        }
        .insert(&state.db)
        .await
        .unwrap();
        let plaintext = format!("zpkg_{role}_{}", Uuid::new_v4().simple());
        token::ActiveModel {
            id: ActiveValue::Set(Uuid::new_v4()),
            name: ActiveValue::Set(format!("{role}-token")),
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
        (org_id, plaintext)
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
        limit: Option<u64>,
    ) -> impl std::future::Future<Output = ApiResult<Json<AuditLogResponse>>> {
        query_call(
            state,
            headers,
            AuditQuery {
                limit,
                ..Default::default()
            },
        )
    }

    fn query_call(
        state: &Arc<AppState>,
        headers: HeaderMap,
        query: AuditQuery,
    ) -> impl std::future::Future<Output = ApiResult<Json<AuditLogResponse>>> {
        get_audit_log(
            State(state.clone()),
            Path("acme".to_string()),
            Query(query),
            headers,
        )
    }

    fn verify_call(
        state: &Arc<AppState>,
        headers: HeaderMap,
    ) -> impl std::future::Future<Output = ApiResult<Json<AuditIntegrityResponse>>> {
        verify_audit_log(State(state.clone()), Path("acme".to_string()), headers)
    }

    /// Append `count` correctly chained rows through the production append
    /// path, so tests exercise real hashes rather than hand-written ones.
    async fn append_rows(state: &AppState, actions: &[AuditAction]) {
        let actor = token::Entity::find().one(&state.db).await.unwrap().unwrap();
        let org_id = org::Entity::find()
            .one(&state.db)
            .await
            .unwrap()
            .unwrap()
            .id;
        for (i, action) in actions.iter().enumerate() {
            crate::audit::record(
                &state.db,
                org_id,
                &actor,
                *action,
                format!("acme/http-kit@1.0.{i}"),
                None,
            )
            .await;
        }
    }

    /// The audit log names who acted, so only an `owner` (or admin) may read it.
    #[tokio::test]
    async fn audit_log_is_owner_only() {
        for role in ["publisher", "reader"] {
            let state = test_state().await;
            let (_org, plaintext) = seed(&state, role).await;
            let err = call(&state, bearer(&plaintext), None)
                .await
                .expect_err("non-owner must not read the audit log");
            assert_eq!(err.code, "insufficient_role", "role {role}");
        }
        // An owner can.
        let state = test_state().await;
        let (_org, owner) = seed(&state, "owner").await;
        assert!(call(&state, bearer(&owner), None).await.is_ok());
    }

    #[tokio::test]
    async fn missing_token_is_unauthorized() {
        let state = test_state().await;
        let _ = seed(&state, "owner").await;
        let err = call(&state, HeaderMap::new(), None)
            .await
            .expect_err("no bearer token must be rejected");
        assert_eq!(err.code, "unauthorized");
    }

    /// Entries come back newest-first, carry the acting token's identity, and
    /// parse into a known action kind.
    #[tokio::test]
    async fn entries_are_newest_first_and_name_the_actor() {
        let state = test_state().await;
        let (_org_id, owner) = seed(&state, "owner").await;
        append_rows(
            &state,
            &[AuditAction::Publish, AuditAction::Yank, AuditAction::Unyank],
        )
        .await;

        let resp = call(&state, bearer(&owner), None).await.unwrap().0;
        assert_eq!(resp.org, "acme");
        let kinds: Vec<_> = resp.entries.iter().map(|e| e.action_kind).collect();
        assert_eq!(
            kinds,
            vec![
                Some(AuditAction::Unyank),
                Some(AuditAction::Yank),
                Some(AuditAction::Publish)
            ],
            "newest first"
        );
        assert_eq!(resp.entries[0].actor_token_name, "owner-token");
        assert_eq!(resp.entries[0].actor_role, "owner");
        // The chain is surfaced to the caller so it can be checked client-side.
        assert_eq!(resp.entries[0].seq, 3);
        assert_eq!(resp.entries[2].seq, 1);
        assert!(!resp.entries[0].entry_hash.is_empty());
        assert_eq!(
            resp.entries[0].prev_hash.as_deref(),
            Some(resp.entries[1].entry_hash.as_str()),
            "each entry must link to its predecessor"
        );
        assert_eq!(
            resp.entries[2].prev_hash, None,
            "the first entry has no predecessor"
        );
    }

    /// `limit` is honored and clamped, so a huge org can't force a huge body.
    #[tokio::test]
    async fn limit_is_honored_and_clamped() {
        let state = test_state().await;
        let (_org, owner) = seed(&state, "owner").await;
        append_rows(&state, &[AuditAction::Publish; 5]).await;

        let two = call(&state, bearer(&owner), Some(2)).await.unwrap().0;
        assert_eq!(two.entries.len(), 2);
        // 0 clamps up to 1 rather than returning nothing or erroring.
        let zero = call(&state, bearer(&owner), Some(0)).await.unwrap().0;
        assert_eq!(zero.entries.len(), 1);
        // Absurd limits clamp to MAX_LIMIT instead of being rejected.
        let huge = call(&state, bearer(&owner), Some(u64::MAX))
            .await
            .unwrap()
            .0;
        assert_eq!(huge.entries.len(), 5);
    }

    /// Filtering narrows to one action; an unknown action is refused rather
    /// than silently ignored, which would read as "nothing ever happened".
    #[tokio::test]
    async fn action_filter_narrows_and_rejects_unknown() {
        let state = test_state().await;
        let (_org, owner) = seed(&state, "owner").await;
        append_rows(
            &state,
            &[
                AuditAction::Publish,
                AuditAction::Yank,
                AuditAction::Publish,
            ],
        )
        .await;

        let yanks = query_call(
            &state,
            bearer(&owner),
            AuditQuery {
                action: Some("yank".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .0;
        assert_eq!(yanks.entries.len(), 1);
        assert_eq!(yanks.entries[0].action, "yank");

        let err = query_call(
            &state,
            bearer(&owner),
            AuditQuery {
                action: Some("yankk".into()),
                ..Default::default()
            },
        )
        .await
        .expect_err("a typo'd filter must not silently match everything");
        assert_eq!(err.code, "invalid_action");
    }

    /// `before` pages backwards through the chain by seq.
    #[tokio::test]
    async fn before_cursor_pages_backwards() {
        let state = test_state().await;
        let (_org, owner) = seed(&state, "owner").await;
        append_rows(&state, &[AuditAction::Publish; 5]).await;

        let first = query_call(
            &state,
            bearer(&owner),
            AuditQuery {
                limit: Some(2),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            first.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![5, 4]
        );

        let next = query_call(
            &state,
            bearer(&owner),
            AuditQuery {
                limit: Some(2),
                before: Some(first.entries.last().unwrap().seq as i64),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            next.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![3, 2],
            "the cursor must not repeat or skip an entry"
        );
    }

    /// An untouched chain verifies, and the head hash is the newest entry.
    #[tokio::test]
    async fn verify_reports_an_intact_chain() {
        let state = test_state().await;
        let (_org, owner) = seed(&state, "owner").await;
        append_rows(&state, &[AuditAction::Publish, AuditAction::Yank]).await;

        let report = verify_call(&state, bearer(&owner)).await.unwrap().0;
        assert!(report.intact, "{report:?}");
        assert_eq!(report.entries_checked, 2);
        assert_eq!(report.problem, None);

        let newest = call(&state, bearer(&owner), Some(1)).await.unwrap().0;
        assert_eq!(
            report.head_hash.as_deref(),
            Some(newest.entries[0].entry_hash.as_str())
        );
    }

    /// Editing a stored row through the database — exactly what an attacker or
    /// a careless operator would do — must be detected.
    #[tokio::test]
    async fn verify_detects_an_edited_row() {
        let state = test_state().await;
        let (_org, owner) = seed(&state, "owner").await;
        append_rows(&state, &[AuditAction::Publish; 3]).await;

        let row = audit_log::Entity::find()
            .filter(audit_log::Column::Seq.eq(2))
            .one(&state.db)
            .await
            .unwrap()
            .unwrap();
        let mut edited: audit_log::ActiveModel = row.into();
        edited.subject = ActiveValue::Set("acme/backdoor@9.9.9".to_string());
        edited.update(&state.db).await.unwrap();

        let report = verify_call(&state, bearer(&owner)).await.unwrap().0;
        assert!(!report.intact, "a rewritten subject must not verify");
        assert_eq!(report.first_bad_seq, Some(2));
        assert_eq!(report.problem.as_deref(), Some("hash_mismatch"));
    }

    /// Deleting a row leaves a gap the walk reports.
    #[tokio::test]
    async fn verify_detects_a_deleted_row() {
        let state = test_state().await;
        let (_org, owner) = seed(&state, "owner").await;
        append_rows(&state, &[AuditAction::Publish; 4]).await;

        audit_log::Entity::delete_many()
            .filter(audit_log::Column::Seq.eq(2))
            .exec(&state.db)
            .await
            .unwrap();

        let report = verify_call(&state, bearer(&owner)).await.unwrap().0;
        assert!(!report.intact, "a deleted entry must not verify");
        assert_eq!(report.problem.as_deref(), Some("sequence_gap"));
        assert_eq!(report.first_bad_seq, Some(2));
    }

    /// Verification is owner-only for the same reason the log is.
    #[tokio::test]
    async fn verify_is_owner_only() {
        for role in ["publisher", "reader"] {
            let state = test_state().await;
            let (_org, scoped) = seed(&state, role).await;
            let err = verify_call(&state, bearer(&scoped))
                .await
                .expect_err("non-owner must not verify the chain");
            assert_eq!(err.code, "insufficient_role", "role {role}");
        }
    }

    /// An unrecognized stored action still reads back (forward compatibility):
    /// the raw string survives and `action_kind` is simply absent.
    #[tokio::test]
    async fn unknown_action_strings_survive_a_read() {
        let state = test_state().await;
        let (org_id, owner) = seed(&state, "owner").await;
        audit_log::ActiveModel {
            id: ActiveValue::Set(Uuid::new_v4()),
            org_id: ActiveValue::Set(org_id),
            at: ActiveValue::Set(Utc::now()),
            action: ActiveValue::Set("transfer_ownership".to_string()),
            subject: ActiveValue::Set("acme".to_string()),
            actor_token_id: ActiveValue::Set(None),
            actor_token_name: ActiveValue::Set("t".to_string()),
            actor_role: ActiveValue::Set("admin".to_string()),
            detail: ActiveValue::Set(None),
            seq: ActiveValue::Set(0),
            entry_hash: ActiveValue::Set(String::new()),
            prev_hash: ActiveValue::Set(None),
        }
        .insert(&state.db)
        .await
        .unwrap();
        let resp = call(&state, bearer(&owner), None).await.unwrap().0;
        assert_eq!(resp.entries[0].action, "transfer_ownership");
        assert_eq!(resp.entries[0].action_kind, None);
    }
}
