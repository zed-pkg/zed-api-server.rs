use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, header};
use axum::Json;
use sea_orm::DbErr;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zed_orm::models::{
    HomePageData, OrgDashboardData, OrgSummary, PackageSettingsInput, PackageSummary,
    ProjectSummary, UserSettingsInput, UserSummary,
};
use zed_orm::queries::{read, write};

use crate::error::{ApiErr, ApiResult};
use crate::shared_auth::{AuthenticatedSession, authenticate};
use crate::state::AppState;

#[derive(Debug, Deserialize, Default)]
pub struct HomeQuery {
    #[serde(default)]
    q: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrgRequest {
    slug: String,
    name: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateProjectRequest {
    slug: String,
    name: String,
}

#[derive(Debug, Deserialize)]
pub struct InvitationRequest {
    email: String,
    role: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePackageRequest {
    description: Option<String>,
    project_id: Option<uuid::Uuid>,
    visibility: String,
    #[serde(default)]
    config: Value,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    display_name: Option<String>,
    avatar_url: Option<String>,
    settings: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    id: uuid::Uuid,
    subject: String,
    email: Option<String>,
    display_name: Option<String>,
    avatar_url: Option<String>,
    settings: Value,
    aal: u8,
}

#[derive(Debug, Serialize)]
pub struct OrgResponse {
    id: uuid::Uuid,
    slug: String,
    name: String,
    description: Option<String>,
    role: String,
}

#[derive(Debug, Serialize)]
pub struct ProjectResponse {
    id: uuid::Uuid,
    org_id: uuid::Uuid,
    org_slug: String,
    slug: String,
    name: String,
    description: Option<String>,
    role: String,
}

#[derive(Debug, Serialize)]
pub struct PackageResponse {
    id: uuid::Uuid,
    org_id: uuid::Uuid,
    org_slug: String,
    project_id: Option<uuid::Uuid>,
    project_slug: Option<String>,
    name: String,
    description: Option<String>,
    visibility: String,
    repo_url: String,
    config: Value,
}

#[derive(Debug, Serialize)]
pub struct HomeResponse {
    user: Option<UserResponse>,
    orgs: Vec<OrgResponse>,
    projects: Vec<ProjectResponse>,
    packages: Vec<PackageResponse>,
    query: String,
}

#[derive(Debug, Serialize)]
pub struct DashboardResponse {
    org: OrgResponse,
    projects: Vec<ProjectResponse>,
    packages: Vec<PackageResponse>,
}

#[derive(Debug, Serialize)]
pub struct InvitationResponse {
    invitation_id: uuid::Uuid,
    email: String,
    role: String,
    /// One-time secret intended for the invitation delivery service. It is
    /// never stored in plaintext by the registry.
    token: String,
}

pub async fn bootstrap_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<UserResponse>> {
    let (session, user) = ensure_account(&state, &headers).await?;
    Ok(Json(user_response(user, session.aal)))
}

pub async fn get_me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<UserResponse>> {
    bootstrap_session(State(state), headers).await
}

pub async fn update_me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<UpdateUserRequest>,
) -> ApiResult<Json<UserResponse>> {
    require_mutation_origin(&headers)?;
    let (session, current) = ensure_account(&state, &headers).await?;
    validate_optional_text(request.display_name.as_deref(), 160, "display_name")?;
    validate_optional_url(request.avatar_url.as_deref(), "avatar_url")?;
    let updated = write::update_user_settings(
        &state.db,
        &session.identity.subject,
        UserSettingsInput {
            display_name: request.display_name,
            avatar_url: request.avatar_url,
            settings: request.settings.unwrap_or(current.settings),
        },
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(user_response(updated, session.aal)))
}

pub async fn get_home(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HomeQuery>,
) -> ApiResult<Json<HomeResponse>> {
    let (session, _) = ensure_account(&state, &headers).await?;
    let home = read::home_for_user(&state.db, &session.identity.subject, &query.q)
        .await
        .map_err(map_db_error)?;
    Ok(Json(home_response(home, session.aal)))
}

pub async fn get_org_dashboard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
) -> ApiResult<Json<DashboardResponse>> {
    let (session, _) = ensure_account(&state, &headers).await?;
    let dashboard = read::org_dashboard_for_user(&state.db, &session.identity.subject, &org_slug)
        .await
        .map_err(map_db_error)?
        .ok_or_else(|| ApiErr::not_found("organization dashboard"))?;
    Ok(Json(dashboard_response(dashboard)))
}

pub async fn create_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateOrgRequest>,
) -> ApiResult<Json<OrgResponse>> {
    require_mutation_origin(&headers)?;
    let (session, _) = ensure_account(&state, &headers).await?;
    validate_required_text(&request.name, 160, "name")?;
    let model = write::create_org(
        &state.db,
        &session.identity.subject,
        &request.slug,
        &request.name,
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(OrgResponse {
        id: model.id,
        slug: model.slug,
        name: model.name,
        description: model.description,
        role: "owner".into(),
    }))
}

pub async fn create_project(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Json(request): Json<CreateProjectRequest>,
) -> ApiResult<Json<ProjectResponse>> {
    require_mutation_origin(&headers)?;
    let (session, _) = ensure_account(&state, &headers).await?;
    validate_required_text(&request.name, 160, "name")?;
    let model = write::create_project(
        &state.db,
        &session.identity.subject,
        &org_slug,
        &request.slug,
        &request.name,
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(ProjectResponse {
        id: model.id,
        org_id: model.org_id,
        org_slug,
        slug: model.slug,
        name: model.name,
        description: model.description,
        role: "owner".into(),
    }))
}

pub async fn get_project_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, project_slug)): Path<(String, String)>,
) -> ApiResult<Json<ProjectResponse>> {
    let (session, _) = ensure_account(&state, &headers).await?;
    let project = read::project_for_user(
        &state.db,
        &session.identity.subject,
        &org_slug,
        &project_slug,
    )
    .await
    .map_err(map_db_error)?
    .ok_or_else(|| ApiErr::not_found("project"))?;
    Ok(Json(project_response(project)))
}

pub async fn invite_org_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Json(request): Json<InvitationRequest>,
) -> ApiResult<Json<InvitationResponse>> {
    require_mutation_origin(&headers)?;
    let (session, _) = ensure_account(&state, &headers).await?;
    let receipt = write::invite_org_member(
        &state.db,
        &session.identity.subject,
        &org_slug,
        &request.email,
        &request.role,
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(InvitationResponse {
        invitation_id: receipt.invitation_id,
        email: receipt.email,
        role: receipt.role,
        token: receipt.token,
    }))
}

pub async fn invite_project_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, project_slug)): Path<(String, String)>,
    Json(request): Json<InvitationRequest>,
) -> ApiResult<Json<InvitationResponse>> {
    require_mutation_origin(&headers)?;
    let (session, _) = ensure_account(&state, &headers).await?;
    let receipt = write::invite_project_member(
        &state.db,
        &session.identity.subject,
        &org_slug,
        &project_slug,
        &request.email,
        &request.role,
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(InvitationResponse {
        invitation_id: receipt.invitation_id,
        email: receipt.email,
        role: receipt.role,
        token: receipt.token,
    }))
}

pub async fn get_package_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, package_name)): Path<(String, String)>,
) -> ApiResult<Json<PackageResponse>> {
    let (session, _) = ensure_account(&state, &headers).await?;
    let package = read::package_for_user(
        &state.db,
        &session.identity.subject,
        &org_slug,
        &package_name,
    )
    .await
    .map_err(map_db_error)?
    .ok_or_else(|| ApiErr::not_found("package"))?;
    Ok(Json(package_response(package)))
}

pub async fn update_package_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, package_name)): Path<(String, String)>,
    Json(request): Json<UpdatePackageRequest>,
) -> ApiResult<Json<PackageResponse>> {
    require_mutation_origin(&headers)?;
    let (session, _) = ensure_account(&state, &headers).await?;
    validate_optional_text(request.description.as_deref(), 4_000, "description")?;
    let updated = write::update_package_settings(
        &state.db,
        &session.identity.subject,
        &org_slug,
        &package_name,
        PackageSettingsInput {
            description: request.description,
            project_id: request.project_id,
            visibility: request.visibility,
            config: request.config,
        },
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(PackageResponse {
        id: updated.id,
        org_id: updated.org_id,
        org_slug,
        project_id: updated.project_id,
        project_slug: None,
        name: updated.name,
        description: updated.description,
        visibility: updated.visibility,
        repo_url: updated.repo_url,
        config: updated.config,
    }))
}

async fn ensure_account(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(AuthenticatedSession, UserSummary)> {
    let session = authenticate(headers).await?;
    let user = write::ensure_user(&state.db, &session.identity)
        .await
        .map_err(map_db_error)?;
    Ok((session, user))
}

fn require_mutation_origin(headers: &HeaderMap) -> ApiResult<()> {
    if headers.contains_key(header::AUTHORIZATION) {
        return Ok(());
    }
    let expected = std::env::var("PUBLIC_WEB_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000".to_owned());
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiErr::forbidden("origin_required", "missing request origin"))?;
    if origin == expected.trim_end_matches('/') {
        Ok(())
    } else {
        Err(ApiErr::forbidden(
            "origin_mismatch",
            "request origin is not allowed",
        ))
    }
}

fn map_db_error(error: DbErr) -> ApiErr {
    let message = error.to_string();
    if message.contains("not found") {
        ApiErr::not_found("resource")
    } else if message.contains("membership required")
        || message.contains("administrator role required")
    {
        ApiErr::forbidden("insufficient_role", message)
    } else if message.contains("invalid") || message.contains("must belong") {
        ApiErr::bad_request("invalid_request", message)
    } else if message.contains("duplicate key") || message.contains("unique constraint") {
        ApiErr::conflict("already_exists", "resource already exists")
    } else {
        error.into()
    }
}

fn validate_required_text(value: &str, max: usize, field: &'static str) -> ApiResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max {
        return Err(ApiErr::bad_request(
            "invalid_text",
            format!("{field} must contain between 1 and {max} bytes"),
        ));
    }
    Ok(())
}

fn validate_optional_text(
    value: Option<&str>,
    max: usize,
    field: &'static str,
) -> ApiResult<()> {
    if value.is_some_and(|value| value.len() > max) {
        return Err(ApiErr::bad_request(
            "invalid_text",
            format!("{field} must not exceed {max} bytes"),
        ));
    }
    Ok(())
}

fn validate_optional_url(value: Option<&str>, field: &'static str) -> ApiResult<()> {
    if let Some(value) = value {
        if value.len() > 2_048
            || !(value.starts_with("https://") || value.starts_with("http://"))
        {
            return Err(ApiErr::bad_request(
                "invalid_url",
                format!("{field} must be an http(s) URL"),
            ));
        }
    }
    Ok(())
}

fn user_response(user: UserSummary, aal: u8) -> UserResponse {
    UserResponse {
        id: user.id,
        subject: user.subject,
        email: user.email,
        display_name: user.display_name,
        avatar_url: user.avatar_url,
        settings: user.settings,
        aal,
    }
}

fn org_response(org: OrgSummary) -> OrgResponse {
    OrgResponse {
        id: org.id,
        slug: org.slug,
        name: org.name,
        description: org.description,
        role: org.role,
    }
}

fn project_response(project: ProjectSummary) -> ProjectResponse {
    ProjectResponse {
        id: project.id,
        org_id: project.org_id,
        org_slug: project.org_slug,
        slug: project.slug,
        name: project.name,
        description: project.description,
        role: project.role,
    }
}

fn package_response(package: PackageSummary) -> PackageResponse {
    PackageResponse {
        id: package.id,
        org_id: package.org_id,
        org_slug: package.org_slug,
        project_id: package.project_id,
        project_slug: package.project_slug,
        name: package.name,
        description: package.description,
        visibility: package.visibility,
        repo_url: package.repo_url,
        config: package.config,
    }
}

fn home_response(home: HomePageData, aal: u8) -> HomeResponse {
    HomeResponse {
        user: home.user.map(|user| user_response(user, aal)),
        orgs: home.orgs.into_iter().map(org_response).collect(),
        projects: home.projects.into_iter().map(project_response).collect(),
        packages: home.packages.into_iter().map(package_response).collect(),
        query: home.query,
    }
}

fn dashboard_response(dashboard: OrgDashboardData) -> DashboardResponse {
    DashboardResponse {
        org: org_response(dashboard.org),
        projects: dashboard
            .projects
            .into_iter()
            .map(project_response)
            .collect(),
        packages: dashboard
            .packages
            .into_iter()
            .map(package_response)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn cookie_mutations_require_the_product_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://localhost:3000"),
        );
        assert!(require_mutation_origin(&headers).is_ok());

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://attacker.example"),
        );
        assert!(require_mutation_origin(&headers).is_err());
    }

    #[test]
    fn bearer_mutations_do_not_require_a_browser_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer cli-token"),
        );
        assert!(require_mutation_origin(&headers).is_ok());
    }
}
