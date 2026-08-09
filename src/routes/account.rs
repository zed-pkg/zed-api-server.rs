//! Browser/account API backed by Shared Auth and the shared zed-orm data plane.
//!
//! This module never receives passwords. Supabase access tokens are exchanged
//! by Shared Auth, and every product operation is authorized again against
//! registry-owned organization/project memberships.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use sea_orm::DbErr;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use uuid::Uuid;
use zed_orm::models::{PackageSettingsInput, UserSettingsInput};
use zed_orm::registry::{CreatePackageInput, PackageLicenseInput, PackageUploadInput};

use crate::auth::{AccountIdentity, bearer_token, map_shared_auth_error, require_account};
use crate::error::{ApiErr, ApiResult};
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
pub struct CreatePackageRequest {
    project_id: Option<Uuid>,
    name: String,
    description: Option<String>,
    #[serde(default = "default_vcs")]
    vcs: String,
    repo_url: String,
    #[serde(default = "empty_object")]
    config: JsonValue,
    #[serde(default = "default_archive_format")]
    default_archive_format: String,
}

#[derive(Debug, Deserialize)]
pub struct PackageSettingsRequest {
    description: Option<String>,
    project_id: Option<Uuid>,
    #[serde(default = "empty_object")]
    config: JsonValue,
}

#[derive(Debug, Deserialize)]
pub struct UserSettingsRequest {
    display_name: Option<String>,
    avatar_url: Option<String>,
    #[serde(default = "empty_object")]
    settings: JsonValue,
}

#[derive(Debug, Deserialize)]
pub struct PackageLicenseRequest {
    spdx_expression: Option<String>,
    license_name: Option<String>,
    license_url: Option<String>,
    license_text: Option<String>,
    checksum_sha256: Option<String>,
    #[serde(default)]
    is_primary: bool,
}

#[derive(Debug, Deserialize)]
pub struct PackageUploadRequest {
    source_upload_id: Option<Uuid>,
    version: String,
    archive_format: String,
    #[serde(default = "default_upload_state")]
    state: String,
    #[serde(default = "default_storage_backend")]
    storage_backend: String,
    storage_bucket: String,
    storage_key: String,
    original_filename: Option<String>,
    size_bytes: i64,
    sha256: String,
    vcs_tag: Option<String>,
    vcs_commit: Option<String>,
    #[serde(default = "empty_object")]
    metadata: JsonValue,
}

pub async fn auth_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<JsonValue>> {
    let public_url = state.shared_auth_public_url.as_ref().ok_or_else(|| {
        ApiErr::service_unavailable(
            "auth_unavailable",
            "shared authentication is not configured",
        )
    })?;
    Ok(Json(json!({
        "shared_auth_url": public_url,
        "application_id": state.shared_auth_application_id,
        "audience": state.shared_auth_audience,
        "supabase_exchange": "/v1/auth/exchange"
    })))
}

/// Exchange a Supabase access token for the shared-auth token used by all
/// account endpoints. The Supabase token is forwarded only to Shared Auth and
/// is never stored in the registry database.
pub async fn exchange_supabase(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<JsonValue>> {
    let token = bearer_token(&headers).ok_or_else(ApiErr::unauthorized)?;
    let client = state.shared_auth.as_ref().ok_or_else(|| {
        ApiErr::service_unavailable(
            "auth_unavailable",
            "shared authentication is not configured",
        )
    })?;
    let exchange = client
        .exchange(&token)
        .await
        .map_err(map_shared_auth_error)?;
    Ok(Json(json!({
        "access_token": exchange.access_token,
        "token_type": exchange.token_type,
        "expires_at": exchange.expires_at,
        "shared_user_id": exchange.shared_user_id,
        "project": exchange.project,
        "provider": exchange.provider,
        "provider_tenant": exchange.provider_tenant
    })))
}

pub async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated(&state, &headers).await?;
    let user = zed_orm::registry::ensure_federated_user(&state.db, &account.federated)
        .await
        .map_err(map_db_error)?;
    Ok(Json(json!({
        "id": user.id,
        "subject": user.shared_auth_subject,
        "email": user.email,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
        "settings": user.settings
    })))
}

pub async fn home(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HomeQuery>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let data = zed_orm::queries::read::home_for_user(&state.db, account.subject(), &query.q)
        .await
        .map_err(map_db_error)?;
    Ok(Json(home_value(data)))
}

pub async fn search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HomeQuery>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let hits =
        zed_orm::registry::search_registry(&state.db, Some(&account.federated), &query.q, 50)
            .await
            .map_err(map_db_error)?;
    Ok(Json(json!({
        "query": query.q,
        "hits": hits.into_iter().map(|hit| json!({
            "entity_type": hit.entity_type,
            "entity_id": hit.entity_id,
            "label": hit.label,
            "description": hit.description,
            "score": hit.score
        })).collect::<Vec<_>>()
    })))
}

pub async fn create_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateOrgRequest>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let org = zed_orm::queries::write::create_org(
        &state.db,
        account.subject(),
        &request.slug,
        &request.name,
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(json!({
        "id": org.id,
        "slug": org.slug,
        "name": org.name,
        "description": org.description,
        "settings": org.settings
    })))
}

pub async fn org_dashboard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let dashboard =
        zed_orm::queries::read::org_dashboard_for_user(&state.db, account.subject(), &org_slug)
            .await
            .map_err(map_db_error)?
            .ok_or_else(|| ApiErr::not_found("organization"))?;
    Ok(Json(org_dashboard_value(dashboard)))
}

pub async fn invite_org_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Json(request): Json<InvitationRequest>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let invitation = zed_orm::queries::write::invite_org_member(
        &state.db,
        account.subject(),
        &org_slug,
        &request.email,
        &request.role,
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(invitation_value(invitation)))
}

pub async fn create_project(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Json(request): Json<CreateProjectRequest>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let project = zed_orm::queries::write::create_project(
        &state.db,
        account.subject(),
        &org_slug,
        &request.slug,
        &request.name,
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(json!({
        "id": project.id,
        "org_id": project.org_id,
        "slug": project.slug,
        "name": project.name,
        "description": project.description,
        "settings": project.settings
    })))
}

pub async fn invite_project_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, project_slug)): Path<(String, String)>,
    Json(request): Json<InvitationRequest>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let invitation = zed_orm::queries::write::invite_project_member(
        &state.db,
        account.subject(),
        &org_slug,
        &project_slug,
        &request.email,
        &request.role,
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(invitation_value(invitation)))
}

pub async fn create_package(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Json(request): Json<CreatePackageRequest>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let package = zed_orm::registry::create_package(
        &state.db,
        &account.federated,
        &org_slug,
        CreatePackageInput {
            project_id: request.project_id,
            name: request.name,
            description: request.description,
            vcs: request.vcs,
            repo_url: request.repo_url,
            config: request.config,
            default_archive_format: request.default_archive_format,
        },
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(package_value(package)))
}

pub async fn update_package_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, package_name)): Path<(String, String)>,
    Json(request): Json<PackageSettingsRequest>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let current = zed_orm::queries::read::package_for_user(
        &state.db,
        account.subject(),
        &org_slug,
        &package_name,
    )
    .await
    .map_err(map_db_error)?
    .ok_or_else(|| ApiErr::not_found("package"))?;
    let package = zed_orm::queries::write::update_package_settings(
        &state.db,
        account.subject(),
        &org_slug,
        &package_name,
        PackageSettingsInput {
            description: request.description,
            project_id: request.project_id,
            // Visibility changes use a dedicated guarded endpoint.
            visibility: current.visibility,
            config: request.config,
        },
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(package_value(package)))
}

pub async fn make_package_public(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, package_name)): Path<(String, String)>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let package = zed_orm::registry::make_package_public(
        &state.db,
        &account.federated,
        &org_slug,
        &package_name,
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(package_value(package)))
}

pub async fn add_package_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, package_name)): Path<(String, String)>,
    Json(request): Json<PackageLicenseRequest>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let license = zed_orm::registry::add_package_license(
        &state.db,
        &account.federated,
        &org_slug,
        &package_name,
        PackageLicenseInput {
            spdx_expression: request.spdx_expression,
            license_name: request.license_name,
            license_url: request.license_url,
            license_text: request.license_text,
            checksum_sha256: request.checksum_sha256,
            is_primary: request.is_primary,
        },
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(json!({
        "id": license.id,
        "package_id": license.package_id,
        "spdx_expression": license.spdx_expression,
        "license_name": license.license_name,
        "license_url": license.license_url,
        "checksum_sha256": license.checksum_sha256,
        "is_primary": license.is_primary
    })))
}

pub async fn register_package_upload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, package_name)): Path<(String, String)>,
    Json(request): Json<PackageUploadRequest>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let upload = zed_orm::registry::register_package_upload(
        &state.db,
        &account.federated,
        &org_slug,
        &package_name,
        PackageUploadInput {
            source_upload_id: request.source_upload_id,
            version: request.version,
            archive_format: request.archive_format,
            state: request.state,
            storage_backend: request.storage_backend,
            storage_bucket: request.storage_bucket,
            storage_key: request.storage_key,
            original_filename: request.original_filename,
            size_bytes: request.size_bytes,
            sha256: request.sha256,
            vcs_tag: request.vcs_tag,
            vcs_commit: request.vcs_commit,
            metadata: request.metadata,
        },
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(json!({
        "id": upload.id,
        "package_id": upload.package_id,
        "source_upload_id": upload.source_upload_id,
        "version": upload.version,
        "archive_format": upload.archive_format,
        "state": upload.state,
        "storage_backend": upload.storage_backend,
        "storage_bucket": upload.storage_bucket,
        "storage_key": upload.storage_key,
        "size_bytes": upload.size_bytes,
        "sha256": upload.sha256,
        "published_at": upload.published_at
    })))
}

pub async fn update_user_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<UserSettingsRequest>,
) -> ApiResult<Json<JsonValue>> {
    let account = authenticated_and_projected(&state, &headers).await?;
    let user = zed_orm::queries::write::update_user_settings(
        &state.db,
        account.subject(),
        UserSettingsInput {
            display_name: request.display_name,
            avatar_url: request.avatar_url,
            settings: request.settings,
        },
    )
    .await
    .map_err(map_db_error)?;
    Ok(Json(json!({
        "id": user.id,
        "subject": user.subject,
        "email": user.email,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
        "settings": user.settings
    })))
}

async fn authenticated(state: &AppState, headers: &HeaderMap) -> ApiResult<AccountIdentity> {
    require_account(state, headers).await
}

async fn authenticated_and_projected(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<AccountIdentity> {
    let account = authenticated(state, headers).await?;
    zed_orm::registry::ensure_federated_user(&state.db, &account.federated)
        .await
        .map_err(map_db_error)?;
    Ok(account)
}

fn map_db_error(error: DbErr) -> ApiErr {
    let message = error.to_string();
    let normalized = message.to_lowercase();
    if normalized.contains("not found") {
        return ApiErr::not_found("resource");
    }
    if normalized.contains("membership required")
        || normalized.contains("administrator role required")
        || normalized.contains("write-capable membership required")
    {
        return ApiErr::forbidden("forbidden", "insufficient registry permission");
    }
    if normalized.contains("cannot become public")
        || normalized.contains("older than")
        || normalized.contains("more than fifty")
        || normalized.contains("more than 50")
    {
        return ApiErr::conflict("visibility_window_closed", message);
    }
    if normalized.contains("duplicate") || normalized.contains("unique constraint") {
        return ApiErr::conflict("already_exists", "the registry entity already exists");
    }
    if normalized.contains("invalid")
        || normalized.contains("must belong")
        || normalized.contains("is required")
        || normalized.contains("cannot be")
    {
        return ApiErr::bad_request("invalid_request", message);
    }
    error.into()
}

fn invitation_value(invitation: zed_orm::models::InvitationReceipt) -> JsonValue {
    json!({
        "invitation_id": invitation.invitation_id,
        // One-time secret: the database stores only its digest.
        "token": invitation.token,
        "email": invitation.email,
        "role": invitation.role
    })
}

fn home_value(data: zed_orm::models::HomePageData) -> JsonValue {
    json!({
        "user": data.user.map(|user| json!({
            "id": user.id,
            "subject": user.subject,
            "email": user.email,
            "display_name": user.display_name,
            "avatar_url": user.avatar_url,
            "settings": user.settings
        })),
        "orgs": data.orgs.into_iter().map(|org| json!({
            "id": org.id,
            "slug": org.slug,
            "name": org.name,
            "description": org.description,
            "role": org.role
        })).collect::<Vec<_>>(),
        "projects": data.projects.into_iter().map(project_summary_value).collect::<Vec<_>>(),
        "packages": data.packages.into_iter().map(package_summary_value).collect::<Vec<_>>(),
        "query": data.query
    })
}

fn org_dashboard_value(data: zed_orm::models::OrgDashboardData) -> JsonValue {
    json!({
        "org": {
            "id": data.org.id,
            "slug": data.org.slug,
            "name": data.org.name,
            "description": data.org.description,
            "role": data.org.role
        },
        "projects": data.projects.into_iter().map(project_summary_value).collect::<Vec<_>>(),
        "packages": data.packages.into_iter().map(package_summary_value).collect::<Vec<_>>()
    })
}

fn project_summary_value(project: zed_orm::models::ProjectSummary) -> JsonValue {
    json!({
        "id": project.id,
        "org_id": project.org_id,
        "org_slug": project.org_slug,
        "slug": project.slug,
        "name": project.name,
        "description": project.description,
        "role": project.role
    })
}

fn package_summary_value(package: zed_orm::models::PackageSummary) -> JsonValue {
    json!({
        "id": package.id,
        "org_id": package.org_id,
        "org_slug": package.org_slug,
        "project_id": package.project_id,
        "project_slug": package.project_slug,
        "name": package.name,
        "description": package.description,
        "visibility": package.visibility,
        "repo_url": package.repo_url,
        "config": package.config
    })
}

fn package_value(package: zed_orm::entities::package::Model) -> JsonValue {
    json!({
        "id": package.id,
        "org_id": package.org_id,
        "project_id": package.project_id,
        "name": package.name,
        "description": package.description,
        "vcs": package.vcs,
        "repo_url": package.repo_url,
        "visibility": package.visibility,
        "config": package.config,
        "default_archive_format": package.default_archive_format,
        "download_count": package.download_count,
        "upload_count": package.upload_count,
        "first_public_at": package.first_public_at,
        "created_at": package.created_at,
        "updated_at": package.updated_at
    })
}

fn empty_object() -> JsonValue {
    json!({})
}

fn default_vcs() -> String {
    "git".into()
}

fn default_archive_format() -> String {
    "tar_gz".into()
}

fn default_upload_state() -> String {
    "pending".into()
}

fn default_storage_backend() -> String {
    "s3".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_is_not_part_of_the_general_settings_request() {
        let request: PackageSettingsRequest = serde_json::from_value(json!({
            "description": "updated",
            "project_id": null,
            "config": {"install": "zed install"},
            "visibility": "public"
        }))
        .unwrap();
        assert_eq!(request.description.as_deref(), Some("updated"));
    }

    #[test]
    fn database_policy_errors_keep_their_public_semantics() {
        let error = map_db_error(DbErr::Custom(
            "package cannot become public after more than 50 downloads".into(),
        ));
        assert_eq!(error.status, axum::http::StatusCode::CONFLICT);
        assert_eq!(error.code, "visibility_window_closed");
    }
}
