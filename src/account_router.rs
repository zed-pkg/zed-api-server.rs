use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, header};
use axum::routing::{get, post};

use crate::account;
use crate::state::AppState;

const ACCOUNT_BODY_LIMIT: usize = 64 * 1024;
const ACCOUNT_IN_FLIGHT_LIMIT: usize = 256;
const ACCOUNT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/session/bootstrap", post(account::bootstrap_session))
        .route("/v1/me", get(account::get_me).patch(account::update_me))
        .route("/v1/me/home", get(account::get_home))
        .route("/v1/account/orgs", post(account::create_org))
        .route(
            "/v1/account/orgs/{org}/dashboard",
            get(account::get_org_dashboard),
        )
        .route(
            "/v1/account/orgs/{org}/invitations",
            post(account::invite_org_member),
        )
        .route(
            "/v1/account/orgs/{org}/projects",
            post(account::create_project),
        )
        .route(
            "/v1/account/orgs/{org}/projects/{project}",
            get(account::get_project_settings),
        )
        .route(
            "/v1/account/orgs/{org}/projects/{project}/invitations",
            post(account::invite_project_member),
        )
        .route(
            "/v1/account/orgs/{org}/packages/{package}",
            get(account::get_package_settings).patch(account::update_package_settings),
        )
        .layer(DefaultBodyLimit::max(ACCOUNT_BODY_LIMIT))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            ACCOUNT_IN_FLIGHT_LIMIT,
        ))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            ACCOUNT_REQUEST_TIMEOUT,
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .with_state(state)
}
