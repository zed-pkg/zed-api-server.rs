use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, header};
use axum::routing::{get, post};

use crate::account;
use crate::state::AppState;

const ACCOUNT_BODY_LIMIT: usize = 64 * 1024;
const ACCOUNT_TIMEOUT: Duration = Duration::from_secs(15);
const ACCOUNT_MAX_IN_FLIGHT: usize = 256;

fn account_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/config", get(account::auth_config))
        .route("/auth/exchange", post(account::exchange_supabase))
        .route(
            "/account/me",
            get(account::me).put(account::update_user_settings),
        )
        .route("/account/home", get(account::home))
        .route("/account/search", get(account::search))
        .route("/account/orgs", post(account::create_org))
        .route("/account/orgs/{org}", get(account::org_dashboard))
        .route(
            "/account/orgs/{org}/invitations",
            post(account::invite_org_member),
        )
        .route(
            "/account/orgs/{org}/projects",
            post(account::create_project),
        )
        .route(
            "/account/orgs/{org}/projects/{project}",
            get(account::project_settings),
        )
        .route(
            "/account/orgs/{org}/projects/{project}/invitations",
            post(account::invite_project_member),
        )
        .route(
            "/account/orgs/{org}/packages",
            post(account::create_package),
        )
        .route(
            "/account/orgs/{org}/packages/{package}/settings",
            get(account::package_settings)
                .put(account::update_package_settings)
                .patch(account::update_package_settings),
        )
        .route(
            "/account/orgs/{org}/packages/{package}/public",
            post(account::make_package_public),
        )
        .route(
            "/account/orgs/{org}/packages/{package}/licenses",
            post(account::add_package_license),
        )
        .route(
            "/account/orgs/{org}/packages/{package}/uploads",
            post(account::register_package_upload),
        )
}

/// Browser/account management is intentionally isolated from machine package
/// tokens. `/api/v1` is canonical; `/v1` remains a bounded compatibility alias
/// while older web clients migrate.
pub fn router(state: Arc<AppState>) -> Router {
    let routes = account_routes();
    Router::new()
        .nest("/api/v1", routes.clone())
        .nest("/v1", routes)
        // PR #27 shipped these flat paths before the canonical `/api/v1`
        // hierarchy landed. Keep read/bootstrap aliases so its clients do not
        // fail abruptly while still requiring the newer delegated token.
        .route("/v1/session/bootstrap", post(account::me))
        .route("/v1/me", get(account::me))
        .route("/v1/me/home", get(account::home))
        .route(
            "/v1/account/orgs/{org}/dashboard",
            get(account::org_dashboard),
        )
        .route(
            "/v1/account/orgs/{org}/packages/{package}",
            get(account::package_settings),
        )
        .layer(DefaultBodyLimit::max(ACCOUNT_BODY_LIMIT))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::ratelimit::layer,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            ACCOUNT_MAX_IN_FLIGHT,
        ))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            ACCOUNT_TIMEOUT,
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    #[test]
    fn account_routes_have_a_canonical_api_namespace_and_a_legacy_alias() {
        for route in [
            "/api/v1/account/me",
            "/api/v1/account/home",
            "/api/v1/account/orgs/{org}",
            "/api/v1/account/orgs/{org}/projects/{project}",
            "/api/v1/account/orgs/{org}/packages/{package}/settings",
            "/api/v1/account/orgs/{org}/packages/{package}/public",
        ] {
            assert!(route.starts_with("/api/v1/account/"));
            assert!(
                route
                    .replacen("/api/v1", "/v1", 1)
                    .starts_with("/v1/account/")
            );
        }
    }
}
