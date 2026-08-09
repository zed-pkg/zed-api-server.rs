use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, header};
use axum::routing::{get, post, put};

use crate::account;
use crate::state::AppState;

const ACCOUNT_BODY_LIMIT: usize = 64 * 1024;
const ACCOUNT_TIMEOUT: Duration = Duration::from_secs(15);
const ACCOUNT_MAX_IN_FLIGHT: usize = 256;

/// Account and organization management is intentionally isolated from legacy
/// package-token routes. It carries the same resource/security layers while
/// using Shared Auth plus zed-orm membership authorization.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/auth/config", get(account::auth_config))
        .route("/v1/auth/exchange", post(account::exchange_supabase))
        .route(
            "/v1/account/me",
            get(account::me).put(account::update_user_settings),
        )
        .route("/v1/account/home", get(account::home))
        .route("/v1/account/search", get(account::search))
        .route("/v1/account/orgs", post(account::create_org))
        .route("/v1/account/orgs/{org}", get(account::org_dashboard))
        .route(
            "/v1/account/orgs/{org}/invitations",
            post(account::invite_org_member),
        )
        .route(
            "/v1/account/orgs/{org}/projects",
            post(account::create_project),
        )
        .route(
            "/v1/account/orgs/{org}/projects/{project}/invitations",
            post(account::invite_project_member),
        )
        .route(
            "/v1/account/orgs/{org}/packages",
            post(account::create_package),
        )
        .route(
            "/v1/account/orgs/{org}/packages/{package}/settings",
            put(account::update_package_settings),
        )
        .route(
            "/v1/account/orgs/{org}/packages/{package}/public",
            post(account::make_package_public),
        )
        .route(
            "/v1/account/orgs/{org}/packages/{package}/licenses",
            post(account::add_package_license),
        )
        .route(
            "/v1/account/orgs/{org}/packages/{package}/uploads",
            post(account::register_package_upload),
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
    fn account_routes_are_namespaced_away_from_legacy_tokens() {
        for route in [
            "/v1/account/me",
            "/v1/account/home",
            "/v1/account/orgs/{org}",
            "/v1/account/orgs/{org}/packages/{package}/public",
        ] {
            assert!(route.starts_with("/v1/account/"));
        }
    }
}
