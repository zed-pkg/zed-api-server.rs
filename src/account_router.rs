use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::account;
use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/session/bootstrap", post(account::bootstrap_session))
        .route(
            "/v1/me",
            get(account::get_me).patch(account::update_me),
        )
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
        .with_state(state)
}
