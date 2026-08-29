//! Read-only storage observability.
//!
//! Two questions, answered the same way on every backend:
//!
//! * `GET /v1/storage/status` — which store is live, is it answering, and how
//!   much does the registry believe is in it?
//! * `GET /v1/storage/artifacts/{sha256}` — does the store actually hold this
//!   artifact, and does it agree with the registry about it?
//!
//! Nothing here writes, deletes, or presigns. The console built on these routes
//! is a window, not a control panel, which is what makes it safe to show to
//! anyone who can already read the registry.
//!
//! Usage totals come from the registry database, not from listing the bucket.
//! A `LIST` over an artifact prefix is billed per thousand keys and grows
//! without bound; the same numbers are already in Postgres, are free to
//! aggregate, and are identical whichever provider is configured. Listing would
//! also give the *store's* view, when the useful question for an operator is
//! whether the store still matches what the registry promises — which is what
//! the per-artifact route answers exactly, for one object at a time.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::{Extension, Json};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Statement};
use zed_interfaces::manifest::is_sha256_hex;

use crate::auth::require_token;
use crate::entities::version;
use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;
use crate::storage_report::{
    StorageLimits, StorageStatus, StorageUsage, object_report, redact_backend_error,
};

/// Now, as an RFC 3339 UTC string. The one impure helper in this module.
fn observed_at() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// `GET /v1/storage/status`
///
/// Requires a token. The payload names a bucket and an endpoint host, which is
/// operator configuration rather than public registry data, so it is not served
/// anonymously — but it never contains a credential, so any valid token is
/// enough and no role check applies.
pub async fn status(
    State(state): State<Arc<AppState>>,
    Extension(limits): Extension<StorageLimits>,
    headers: HeaderMap,
) -> ApiResult<Json<StorageStatus>> {
    let _token = require_token(&state.db, &headers).await?;

    // Two independent effects, neither allowed to fail the report: a store that
    // is down is precisely what this route exists to say out loud, and a usage
    // rollup that could not be computed is reported as zero rather than as a
    // 500 that hides the backend's state.
    let health = state.store.probe().await;
    let usage = usage_from_registry(&state).await.unwrap_or_else(|error| {
        tracing::warn!(%error, "storage usage rollup failed; reporting zeroes");
        StorageUsage::default()
    });

    Ok(Json(StorageStatus::new(
        state.storage_backend.clone(),
        health,
        usage,
        limits,
        observed_at(),
    )))
}

/// `GET /v1/storage/artifacts/{sha256}`
///
/// Reconciles one artifact: what the registry recorded against what the store
/// reports right now. A digest with no registry record is a 404 — this route
/// deliberately cannot be used to probe arbitrary keys in the bucket.
pub async fn artifact(
    State(state): State<Arc<AppState>>,
    Path(sha256): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<crate::storage_report::StorageObjectReport>> {
    let _token = require_token(&state.db, &headers).await?;

    // Validated before it can reach a storage key. Digests are the only thing
    // this route accepts, and they are hex.
    if !is_sha256_hex(&sha256) {
        return Err(ApiErr::bad_request(
            "invalid_digest",
            "artifact digest must be 64 lowercase hex characters",
        ));
    }

    let row = version::Entity::find()
        .filter(version::Column::Sha256.eq(&sha256))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiErr::not_found("artifact"))?;

    let head = match state.store.head(&row.artifact_key).await {
        Ok(head) => head,
        Err(error) => {
            // The store could not be asked. That is not "the object is
            // missing", so it is reported as a backend failure rather than
            // silently downgraded to a reconciliation verdict.
            return Err(ApiErr::service_unavailable(
                "storage_unavailable",
                redact_backend_error(&format!("{error}")),
            ));
        }
    };

    Ok(Json(object_report(
        row.artifact_key,
        row.sha256,
        row.size.max(0) as u64,
        head,
        observed_at(),
    )))
}

/// Aggregate what the registry believes is stored.
///
/// Distinct digests, not rows: two versions that published byte-identical
/// artifacts share one object, and counting both would overstate storage by the
/// size of the duplicate.
async fn usage_from_registry(state: &AppState) -> anyhow::Result<StorageUsage> {
    let backend = state.db.get_database_backend();
    let statement = Statement::from_string(
        backend,
        "SELECT COUNT(*) AS artifact_count, \
                COALESCE(SUM(size), 0) AS total_bytes, \
                COALESCE(MAX(size), 0) AS largest_bytes \
         FROM (SELECT DISTINCT sha256, size FROM version) AS distinct_artifacts",
    );
    let row = state
        .db
        .query_one(statement)
        .await?
        .ok_or_else(|| anyhow::anyhow!("storage usage query returned no row"))?;

    let artifact_count: i64 = row.try_get_by("artifact_count").unwrap_or_default();
    let total_bytes: i64 = row.try_get_by("total_bytes").unwrap_or_default();
    let largest_bytes: i64 = row.try_get_by("largest_bytes").unwrap_or_default();

    Ok(StorageUsage {
        artifact_count: artifact_count.max(0) as u64,
        total_bytes: total_bytes.max(0) as u64,
        largest_bytes: largest_bytes.max(0) as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_report::{Reconciliation, StorageBackend, StorageHealth};

    #[test]
    fn a_digest_that_is_not_hex_never_becomes_a_storage_key() {
        let rejected = [
            "../../etc/passwd".to_owned(),
            "artifacts/abc.tar.gz".to_owned(),
            "ABCDEF".to_owned(),
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
        ];
        for candidate in &rejected {
            assert!(!is_sha256_hex(candidate), "{candidate} must be rejected");
        }
        assert!(is_sha256_hex(&"a".repeat(64)));
    }

    #[test]
    fn the_status_payload_names_the_backend_without_a_credential() {
        let status = StorageStatus::new(
            StorageBackend::object_store(
                "zed-artifacts",
                "auto",
                Some("https://key:secret@abc.r2.cloudflarestorage.com"),
                false,
            ),
            StorageHealth::Reachable { latency_ms: 12 },
            StorageUsage {
                artifact_count: 2,
                total_bytes: 300,
                largest_bytes: 200,
            },
            StorageLimits {
                max_artifact_bytes: 100,
                max_buffered_artifact_bytes: 100,
            },
            observed_at(),
        );
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("cloudflare-r2"), "{json}");
        assert!(!json.contains("secret"), "{json}");
    }

    #[test]
    fn a_missing_object_reconciles_as_missing_not_as_an_error() {
        let report = object_report(
            "artifacts/abc.tar.gz".to_owned(),
            "abc".to_owned(),
            10,
            None,
            observed_at(),
        );
        assert_eq!(report.reconciliation, Reconciliation::Missing);
    }

    #[test]
    fn observed_at_is_rfc3339_utc() {
        let stamp = observed_at();
        assert!(stamp.ends_with('Z'), "{stamp}");
        assert!(
            chrono::DateTime::parse_from_rfc3339(&stamp).is_ok(),
            "{stamp}"
        );
    }
}
