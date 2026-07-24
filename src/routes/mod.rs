//! HTTP layer. The router is assembled here; one submodule per resource
//! holds the handlers. Route path patterns live here as constants and are
//! checked against the `zed-interfaces` URL helpers in tests, so the server
//! and every client cannot disagree on the URL scheme.

mod artifacts;
mod orgs;
mod packages;
mod publish;
mod search;
mod yank;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderValue, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use zed_interfaces::artifact::ArtifactFormat;

use crate::entities::{org, package, version};
use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;

pub const ROUTE_PACKAGE: &str = "/v1/packages/{org}/{name}";
pub const ROUTE_VERSION: &str = "/v1/packages/{org}/{name}/versions/{version}";
pub const ROUTE_YANK: &str = "/v1/packages/{org}/{name}/versions/{version}/yank";
pub const ROUTE_ARTIFACT: &str = "/v1/artifacts/{sha256}";
pub const ROUTE_SEARCH: &str = "/v1/search";
pub const ROUTE_ORGS: &str = "/v1/orgs";
pub const ROUTE_FILES: &str = "/v1/files/{org}/{name}/{version}/{*path}";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_IN_FLIGHT_REQUESTS: usize = 512;
/// Body cap for the non-publish endpoints, which only accept small JSON
/// (`claim_org`, `yank`) or no body at all. Publish overrides this with the
/// artifact-sized limit.
const JSON_BODY_LIMIT: usize = 64 * 1024;
/// Default memory budget (bytes) for concurrently buffered artifact reads.
/// `get_file` (and the local-storage `get_artifact` path) materialize a whole
/// archive — up to `max_artifact_bytes` — in RAM. Bounding the number of such
/// reads in flight keeps peak memory near this budget instead of
/// `MAX_IN_FLIGHT_REQUESTS × max_artifact_bytes` (which trivially OOMs a
/// memory-limited pod). Override with `ZED_ARTIFACT_SERVE_MEMORY_BUDGET_BYTES`.
const DEFAULT_ARTIFACT_SERVE_BUDGET: usize = 256 * 1024 * 1024;

/// How many artifact-buffering requests may run at once, given the per-read
/// worst case (`max_artifact_bytes`) and the memory budget. At least 1, and
/// never more than the global in-flight cap.
fn artifact_serve_concurrency(max_artifact_bytes: usize) -> usize {
    let budget = std::env::var("ZED_ARTIFACT_SERVE_MEMORY_BUDGET_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_ARTIFACT_SERVE_BUDGET);
    (budget / max_artifact_bytes.max(1))
        .clamp(1, MAX_IN_FLIGHT_REQUESTS)
}

pub fn router(state: Arc<AppState>, max_artifact_bytes: usize) -> Router {
    // The two endpoints that buffer a whole artifact in memory get their own,
    // tighter concurrency limit so they can't exhaust pod memory even while
    // the global limit still admits cheap JSON requests.
    let artifact_routes = Router::new()
        .route(ROUTE_ARTIFACT, get(artifacts::get_artifact))
        .route(ROUTE_FILES, get(artifacts::get_file))
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            artifact_serve_concurrency(max_artifact_bytes),
        ));

    // Only publish carries an artifact body; every other endpoint takes a
    // small JSON document (or none). The 100 MB publish limit applied
    // globally would let a client stream ~100 MB at the cheap JSON endpoints,
    // so scope the large limit to publish and default the rest to 64 KiB.
    let publish_route = Router::new()
        .route(ROUTE_VERSION, get(packages::get_version).put(publish::publish))
        .layer(DefaultBodyLimit::max(max_artifact_bytes));

    Router::new()
        .route("/healthz", get(healthz))
        .route(ROUTE_PACKAGE, get(packages::get_package))
        .route(ROUTE_YANK, post(yank::yank))
        .route(ROUTE_SEARCH, get(search::search))
        .route(ROUTE_ORGS, post(orgs::claim_org))
        .merge(artifact_routes)
        .layer(DefaultBodyLimit::max(JSON_BODY_LIMIT))
        .merge(publish_route)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        // Later layers wrap earlier ones: the timeout covers time spent
        // queued on the concurrency limit, and the header is set on every
        // response, including timeouts.
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            MAX_IN_FLIGHT_REQUESTS,
        ))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .with_state(state)
}

async fn healthz(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let db_ok = state.db.ping().await.is_ok();
    Json(serde_json::json!({ "ok": true, "db": db_ok }))
}

// Shared query helpers used by more than one handler submodule.

pub(super) async fn find_org(state: &AppState, slug: &str) -> ApiResult<org::Model> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    org::Entity::find()
        .filter(org::Column::Slug.eq(slug))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiErr::not_found("org"))
}

pub(super) async fn find_package(
    state: &AppState,
    org_row: &org::Model,
    name: &str,
) -> ApiResult<package::Model> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    package::Entity::find()
        .filter(package::Column::OrgId.eq(org_row.id))
        .filter(package::Column::Name.eq(name))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiErr::not_found("package"))
}

pub(super) fn sort_versions_desc(versions: &mut [String]) {
    // Tolerant of calendar/foreign version spellings (zed-docs issue #3).
    zed_interfaces::version::sort_desc(versions);
}

/// Parse the stored `format` column ("tar.gz" / "zip") back into the shared
/// enum; unknown spellings fall back to the default (tar.gz).
pub(super) fn artifact_format(format: &str) -> ArtifactFormat {
    serde_json::from_value(serde_json::Value::String(format.to_string())).unwrap_or_default()
}

pub(super) fn version_metadata(
    state: &AppState,
    org: &str,
    name: &str,
    row: &version::Model,
) -> zed_interfaces::registry::VersionMetadata {
    zed_interfaces::registry::VersionMetadata {
        org: org.to_string(),
        name: name.to_string(),
        version: row.version.clone(),
        sha256: row.sha256.clone(),
        size: row.size as u64,
        format: artifact_format(&row.format),
        vcs_tag: row.vcs_tag.clone(),
        vcs_commit: row.vcs_commit.clone(),
        download_url: format!(
            "{}{}",
            state.public_base_url,
            zed_interfaces::registry::artifact_path(&row.sha256)
        ),
        published_at: row.published_at.to_rfc3339(),
        yanked: row.yanked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TagPolicy;
    use crate::storage::ArtifactStore;
    use crate::verify::TagVerifier;
    use axum::http::StatusCode;
    use tower::util::ServiceExt;

    /// Route patterns must line up with the URL helpers every client uses.
    #[test]
    fn routes_match_contract_paths() {
        let fill = |pattern: &str| {
            pattern
                .replace("{org}", "acme")
                .replace("{name}", "http-kit")
                .replace("{version}", "1.2.0")
                .replace("{sha256}", "abc")
                .replace("{*path}", "dist/style.css")
        };
        use zed_interfaces::registry as r;
        assert_eq!(fill(ROUTE_PACKAGE), r::package_path("acme", "http-kit"));
        assert_eq!(
            fill(ROUTE_VERSION),
            r::version_path("acme", "http-kit", "1.2.0")
        );
        assert_eq!(fill(ROUTE_YANK), r::yank_path("acme", "http-kit", "1.2.0"));
        assert_eq!(fill(ROUTE_ARTIFACT), r::artifact_path("abc"));
        assert_eq!(ROUTE_SEARCH, r::search_path());
        assert_eq!(ROUTE_ORGS, r::orgs_path());
        assert_eq!(
            fill(ROUTE_FILES),
            r::file_path("acme", "http-kit", "1.2.0", "dist/style.css")
        );
    }

    #[tokio::test]
    async fn healthz_works_without_a_database() {
        let dir = std::env::temp_dir().join("zed-api-test-store");
        let state = Arc::new(AppState {
            db: sea_orm::DatabaseConnection::Disconnected,
            store: ArtifactStore::from_config(&crate::config::StorageConfig::Local {
                dir: dir.to_string_lossy().to_string(),
            })
            .await
            .unwrap(),
            verifier: TagVerifier::new(TagPolicy::Off),
            public_base_url: "http://localhost:8080".to_string(),
            max_orgs_per_token: 5,
            fiducia: None,
        });
        let app = router(state, 1024 * 1024);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
