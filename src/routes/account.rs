//! Browser/account API backed by Shared Auth and the canonical zed-orm-core
//! data plane.
//!
//! This module never receives passwords. Supabase access tokens are exchanged
//! by Shared Auth, and every product mutation rechecks registry-owned
//! organization/project membership inside the same PostgreSQL transaction as
//! the write.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use uuid::Uuid;
use zed_orm_core::account::{
    CreatePackageInput, CreateProjectInput, InvitationInput, PackageLicenseInput,
    PackageSettingsPatch, PackageUploadInput,
};
use zed_orm_core::models::{
    InvitationReceipt, OrgSummary, PackageSummary, ProjectSummary, UserSettingsInput, UserSummary,
};
use zed_orm_core::{OrmError, ReadContext, WriteContext};

use crate::auth::{
    AccountIdentity, bearer_token, hash_token, map_shared_auth_error, require_account,
};
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
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProjectRequest {
    slug: String,
    name: String,
    description: Option<String>,
    #[serde(default = "default_private")]
    visibility: String,
    #[serde(default = "empty_object")]
    settings: JsonValue,
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
    #[serde(default)]
    repo_url: String,
    homepage_url: Option<String>,
    #[serde(default = "empty_array")]
    keywords: JsonValue,
    #[serde(default = "empty_object")]
    config: JsonValue,
    #[serde(default = "default_archive_format")]
    default_archive_format: String,
}

#[derive(Debug, Deserialize)]
pub struct PackageSettingsRequest {
    description: Option<String>,
    project_id: Option<Uuid>,
    repo_url: Option<String>,
    homepage_url: Option<String>,
    keywords: Option<JsonValue>,
    config: Option<JsonValue>,
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
    #[serde(default)]
    is_primary: bool,
    package_version_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct PackageUploadRequest {
    package_version_id: Option<Uuid>,
    #[serde(alias = "version")]
    requested_version: String,
    #[serde(default = "default_upload_status", alias = "state")]
    status: String,
    #[serde(default = "default_storage_backend")]
    storage_backend: String,
    storage_key: Option<String>,
    #[serde(alias = "archive_format")]
    format: Option<String>,
    size_bytes: Option<i64>,
    sha256: Option<String>,
    client_ip_hash: Option<String>,
    user_agent: Option<String>,
    error: Option<String>,
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
        "supabase_exchange": "/api/v1/auth/exchange"
    })))
}

/// Exchange a Supabase access token for the Shared Auth token used by account
/// endpoints. The Supabase token is forwarded only to Shared Auth and is never
/// stored in the registry database.
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
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    Ok(Json(user_value(user)))
}

pub async fn home(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HomeQuery>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let read = registry_read(&state)?;
    let mut orgs = zed_orm_core::read::orgs_for_user(read, user.id)
        .await
        .map_err(map_orm_error)?;
    let visible_org_ids = orgs.iter().map(|org| org.id).collect::<Vec<_>>();

    let mut projects = Vec::new();
    for org in &orgs {
        let mut rows = zed_orm_core::read::projects_for_org(read, org.id, &org.slug, true)
            .await
            .map_err(map_orm_error)?;
        for project in &mut rows {
            let direct = zed_orm_core::account::project_role_for_user(read, project.id, user.id)
                .await
                .map_err(map_orm_error)?;
            project.role = strongest_role(Some(&org.role), direct.as_deref())
                .unwrap_or("reader")
                .to_owned();
        }
        projects.extend(rows);
    }

    let trimmed = query.q.trim();
    let packages = if trimmed.is_empty() {
        let mut rows = Vec::new();
        for org in &orgs {
            rows.extend(
                zed_orm_core::read::packages_for_org(read, org.id, &org.slug, true)
                    .await
                    .map_err(map_orm_error)?,
            );
        }
        rows
    } else {
        zed_orm_core::read::search_packages(read, trimmed, &visible_org_ids, 100)
            .await
            .map_err(map_orm_error)?
    };

    if !trimmed.is_empty() {
        orgs.retain(|org| {
            contains_ci(&org.slug, trimmed)
                || contains_ci(&org.name, trimmed)
                || org
                    .description
                    .as_deref()
                    .is_some_and(|value| contains_ci(value, trimmed))
        });
        projects.retain(|project| {
            contains_ci(&project.slug, trimmed)
                || contains_ci(&project.name, trimmed)
                || project
                    .description
                    .as_deref()
                    .is_some_and(|value| contains_ci(value, trimmed))
        });
    }

    Ok(Json(json!({
        "user": user_value(user),
        "orgs": orgs.into_iter().map(org_summary_value).collect::<Vec<_>>(),
        "projects": projects.into_iter().map(project_summary_value).collect::<Vec<_>>(),
        "packages": packages.into_iter().map(package_summary_value).collect::<Vec<_>>(),
        "query": query.q
    })))
}

pub async fn search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HomeQuery>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let read = registry_read(&state)?;
    let visible_org_ids = zed_orm_core::read::orgs_for_user(read, user.id)
        .await
        .map_err(map_orm_error)?
        .into_iter()
        .map(|org| org.id)
        .collect::<Vec<_>>();
    let hits = zed_orm_core::registry::search_registry(read, &query.q, &visible_org_ids, 50)
        .await
        .map_err(map_orm_error)?;
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
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let org = zed_orm_core::write::create_org(
        registry_write(&state)?,
        user.id,
        &request.slug,
        &request.name,
        request.description.as_deref(),
    )
    .await
    .map_err(map_orm_error)?;
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
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let read = registry_read(&state)?;
    let org = zed_orm_core::read::org_by_slug(read, &org_slug)
        .await
        .map_err(map_orm_error)?
        .ok_or_else(|| ApiErr::not_found("organization"))?;
    let role = zed_orm_core::read::org_role_for_user(read, org.id, user.id)
        .await
        .map_err(map_orm_error)?
        .ok_or_else(|| ApiErr::not_found("organization"))?;
    let org_summary = OrgSummary {
        id: org.id,
        slug: org.slug,
        name: org.name,
        description: org.description,
        role,
    };
    let mut projects =
        zed_orm_core::read::projects_for_org(read, org_summary.id, &org_summary.slug, true)
            .await
            .map_err(map_orm_error)?;
    for project in &mut projects {
        let direct = zed_orm_core::account::project_role_for_user(read, project.id, user.id)
            .await
            .map_err(map_orm_error)?;
        project.role = strongest_role(Some(&org_summary.role), direct.as_deref())
            .unwrap_or("reader")
            .to_owned();
    }
    let packages =
        zed_orm_core::read::packages_for_org(read, org_summary.id, &org_summary.slug, true)
            .await
            .map_err(map_orm_error)?;
    Ok(Json(json!({
        "org": org_summary_value(org_summary),
        "projects": projects.into_iter().map(project_summary_value).collect::<Vec<_>>(),
        "packages": packages.into_iter().map(package_summary_value).collect::<Vec<_>>()
    })))
}

pub async fn invite_org_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Json(request): Json<InvitationRequest>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let invitation = zed_orm_core::account::invite_org_member_for_user(
        registry_write(&state)?,
        user.id,
        &org_slug,
        invitation_input(request),
    )
    .await
    .map_err(map_orm_error)?;
    Ok(Json(invitation_value(invitation)))
}

pub async fn create_project(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Json(request): Json<CreateProjectRequest>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let project = zed_orm_core::account::create_project_for_user(
        registry_write(&state)?,
        user.id,
        &org_slug,
        CreateProjectInput {
            slug: request.slug,
            name: request.name,
            description: request.description,
            visibility: request.visibility,
            settings: request.settings,
        },
    )
    .await
    .map_err(map_orm_error)?;
    Ok(Json(json!({
        "id": project.id,
        "org_id": project.org_id,
        "slug": project.slug,
        "name": project.name,
        "description": project.description,
        "visibility": project.visibility,
        "settings": project.settings
    })))
}

/// Return the project settings view retained from PR #27, authorized through
/// the canonical data plane. Organization membership and direct project
/// membership are combined exactly as they are for the account home view.
pub async fn project_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, project_slug)): Path<(String, String)>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let read = registry_read(&state)?;
    let org = zed_orm_core::read::org_by_slug(read, &org_slug)
        .await
        .map_err(map_orm_error)?
        .ok_or_else(|| ApiErr::not_found("project"))?;
    let project = zed_orm_core::account::project_by_org_and_slug(read, org.id, &project_slug)
        .await
        .map_err(map_orm_error)?
        .ok_or_else(|| ApiErr::not_found("project"))?;
    let org_role = zed_orm_core::read::org_role_for_user(read, org.id, user.id)
        .await
        .map_err(map_orm_error)?;
    let project_role = zed_orm_core::account::project_role_for_user(read, project.id, user.id)
        .await
        .map_err(map_orm_error)?;
    let role = strongest_role(org_role.as_deref(), project_role.as_deref())
        .ok_or_else(|| ApiErr::not_found("project"))?;
    Ok(Json(json!({
        "id": project.id,
        "org_id": project.org_id,
        "org_slug": org.slug,
        "slug": project.slug,
        "name": project.name,
        "description": project.description,
        "visibility": project.visibility,
        "settings": project.settings,
        "role": role
    })))
}

pub async fn invite_project_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, project_slug)): Path<(String, String)>,
    Json(request): Json<InvitationRequest>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let invitation = zed_orm_core::account::invite_project_member_for_user(
        registry_write(&state)?,
        user.id,
        &org_slug,
        &project_slug,
        invitation_input(request),
    )
    .await
    .map_err(map_orm_error)?;
    Ok(Json(invitation_value(invitation)))
}

pub async fn create_package(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_slug): Path<String>,
    Json(request): Json<CreatePackageRequest>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let mut config = request.config;
    let object = config.as_object_mut().ok_or_else(|| {
        ApiErr::bad_request("invalid_request", "package config must be a JSON object")
    })?;
    object.insert(
        "default_archive_format".to_owned(),
        JsonValue::String(normalize_archive_format(&request.default_archive_format)?.to_owned()),
    );
    let package = zed_orm_core::account::create_package_for_user(
        registry_write(&state)?,
        user.id,
        &org_slug,
        CreatePackageInput {
            project_id: request.project_id,
            name: request.name,
            description: request.description,
            vcs: request.vcs,
            repo_url: request.repo_url,
            homepage_url: request.homepage_url,
            keywords: request.keywords,
            config,
        },
    )
    .await
    .map_err(map_orm_error)?;
    Ok(Json(package_value(package)))
}

/// Return package settings only to an organization or owning-project member.
/// Public package visibility is deliberately insufficient for this management
/// endpoint because the response includes registry configuration.
pub async fn package_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, package_name)): Path<(String, String)>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let read = registry_read(&state)?;
    let (package, org) =
        zed_orm_core::read::package_by_org_and_name(read, &org_slug, &package_name)
            .await
            .map_err(map_orm_error)?
            .ok_or_else(|| ApiErr::not_found("package"))?;
    let org_role = zed_orm_core::read::org_role_for_user(read, org.id, user.id)
        .await
        .map_err(map_orm_error)?;
    let project_role = match package.project_id {
        Some(project_id) => zed_orm_core::account::project_role_for_user(read, project_id, user.id)
            .await
            .map_err(map_orm_error)?,
        None => None,
    };
    strongest_role(org_role.as_deref(), project_role.as_deref())
        .ok_or_else(|| ApiErr::not_found("package"))?;
    Ok(Json(package_value(package)))
}

pub async fn update_package_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, package_name)): Path<(String, String)>,
    Json(request): Json<PackageSettingsRequest>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let current = zed_orm_core::read::package_by_org_and_name(
        registry_read(&state)?,
        &org_slug,
        &package_name,
    )
    .await
    .map_err(map_orm_error)?
    .map(|(package, _)| package)
    .ok_or_else(|| ApiErr::not_found("package"))?;
    let package = zed_orm_core::account::update_package_settings_for_user(
        registry_write(&state)?,
        user.id,
        &org_slug,
        &package_name,
        PackageSettingsPatch {
            description: request.description,
            project_id: request.project_id,
            repo_url: request.repo_url.unwrap_or(current.repo_url),
            homepage_url: request.homepage_url.or(current.homepage_url),
            keywords: request.keywords.unwrap_or(current.keywords),
            config: request
                .config
                .filter(|value| !is_empty_object(value))
                .unwrap_or(current.config),
        },
    )
    .await
    .map_err(map_orm_error)?;
    Ok(Json(package_value(package)))
}

pub async fn make_package_public(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, package_name)): Path<(String, String)>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let package = zed_orm_core::account::make_package_public_for_user(
        registry_write(&state)?,
        user.id,
        &org_slug,
        &package_name,
    )
    .await
    .map_err(map_orm_error)?;
    Ok(Json(package_value(package)))
}

pub async fn add_package_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, package_name)): Path<(String, String)>,
    Json(request): Json<PackageLicenseRequest>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let kind = if request.spdx_expression.is_some() {
        "spdx"
    } else if request.license_text.is_some() || request.license_url.is_some() {
        "custom"
    } else {
        "proprietary"
    };
    let license = zed_orm_core::account::add_package_license_for_user(
        registry_write(&state)?,
        user.id,
        &org_slug,
        &package_name,
        PackageLicenseInput {
            package_version_id: request.package_version_id,
            kind: kind.to_owned(),
            spdx_id: request.spdx_expression,
            name: request.license_name,
            url: request.license_url,
            text_body: request.license_text,
            is_primary: request.is_primary,
        },
    )
    .await
    .map_err(map_orm_error)?;
    Ok(Json(json!({
        "id": license.id,
        "package_id": license.package_id,
        "package_version_id": license.package_version_id,
        "kind": license.kind,
        "spdx_id": license.spdx_id,
        "name": license.name,
        "url": license.url,
        "is_primary": license.is_primary
    })))
}

pub async fn register_package_upload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org_slug, package_name)): Path<(String, String)>,
    Json(request): Json<PackageUploadRequest>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let status = normalize_upload_status(&request.status);
    let completed_at = matches!(status.as_str(), "verified" | "failed" | "aborted")
        .then(|| Utc::now().fixed_offset());
    let read = registry_read(&state)?;
    let package = zed_orm_core::read::package_by_org_and_name(read, &org_slug, &package_name)
        .await
        .map_err(map_orm_error)?
        .map(|(package, _)| package)
        .ok_or_else(|| ApiErr::not_found("package"))?;
    let package_version_id = match request.package_version_id {
        Some(version_id) => Some(version_id),
        None => zed_orm_core::read::versions_for_package(read, package.id)
            .await
            .map_err(map_orm_error)?
            .into_iter()
            .find(|version| version.version == request.requested_version)
            .map(|version| version.id),
    };
    let upload = zed_orm_core::account::register_package_upload_for_user(
        registry_write(&state)?,
        user.id,
        &org_slug,
        &package_name,
        PackageUploadInput {
            package_version_id,
            requested_version: request.requested_version,
            status,
            storage_backend: request.storage_backend,
            storage_key: request.storage_key,
            format: request
                .format
                .as_deref()
                .map(normalize_archive_format)
                .transpose()?
                .map(str::to_owned),
            size_bytes: request.size_bytes,
            sha256: request.sha256,
            api_token_id: None,
            client_ip_hash: request.client_ip_hash,
            user_agent: request.user_agent,
            error: request.error,
            completed_at,
        },
    )
    .await
    .map_err(map_orm_error)?;
    Ok(Json(json!({
        "id": upload.id,
        "package_id": upload.package_id,
        "package_version_id": upload.package_version_id,
        "requested_version": upload.requested_version,
        "status": upload.status,
        "storage_backend": upload.storage_backend,
        "storage_key": upload.storage_key,
        "format": upload.format,
        "size_bytes": upload.size_bytes,
        "sha256": upload.sha256,
        "completed_at": upload.completed_at
    })))
}

pub async fn update_user_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<UserSettingsRequest>,
) -> ApiResult<Json<JsonValue>> {
    let (_, user) = authenticated_and_projected(&state, &headers).await?;
    let updated = zed_orm_core::write::update_user_settings(
        registry_write(&state)?,
        user.id,
        &UserSettingsInput {
            display_name: request.display_name,
            avatar_url: request.avatar_url,
            settings: request.settings,
        },
    )
    .await
    .map_err(map_orm_error)?;
    Ok(Json(user_value(updated)))
}

async fn authenticated(state: &AppState, headers: &HeaderMap) -> ApiResult<AccountIdentity> {
    require_account(state, headers).await
}

async fn authenticated_and_projected(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(AccountIdentity, UserSummary)> {
    let account = authenticated(state, headers).await?;
    let user =
        zed_orm_core::write::upsert_user_from_session(registry_write(state)?, &account.session)
            .await
            .map_err(map_orm_error)?;
    Ok((account, user))
}

fn registry_read(state: &AppState) -> ApiResult<&ReadContext> {
    state.registry_read.as_ref().ok_or_else(|| {
        ApiErr::service_unavailable(
            "registry_data_plane_unavailable",
            "canonical registry read context is not configured",
        )
    })
}

fn registry_write(state: &AppState) -> ApiResult<&WriteContext> {
    state.registry_write.as_ref().ok_or_else(|| {
        ApiErr::service_unavailable(
            "registry_data_plane_unavailable",
            "canonical registry write context is not configured",
        )
    })
}

pub(crate) fn map_orm_error(error: OrmError) -> ApiErr {
    match error {
        OrmError::VisibilityWindowExpired(message)
        | OrmError::VisibilityDownloadLimitExceeded(message) => {
            ApiErr::conflict("visibility_window_closed", message)
        }
        OrmError::NotFound(message) => ApiErr::not_found(&message),
        OrmError::PolicyViolation(message) => {
            let normalized = message.to_ascii_lowercase();
            if normalized.contains("membership")
                || normalized.contains("role")
                || normalized.contains("permission")
            {
                ApiErr::forbidden("forbidden", "insufficient registry permission")
            } else {
                ApiErr::bad_request("invalid_request", message)
            }
        }
        OrmError::Database(message) => {
            let normalized = message.to_ascii_lowercase();
            if normalized.contains("duplicate") || normalized.contains("unique") {
                ApiErr::conflict("already_exists", "the registry entity already exists")
            } else {
                tracing::error!(error = %message, "canonical registry database error");
                ApiErr {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    code: "internal",
                    message: "internal database error".to_owned(),
                }
            }
        }
        _ => ApiErr {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: "internal registry error".to_owned(),
        },
    }
}

fn invitation_input(request: InvitationRequest) -> InvitationInput {
    let token = format!(
        "zpkg_inv_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    InvitationInput {
        email: request.email,
        role: request.role,
        token_hash: hash_token(&token),
        token,
        expires_at: (Utc::now() + Duration::days(7)).fixed_offset(),
    }
}

fn invitation_value(invitation: InvitationReceipt) -> JsonValue {
    json!({
        "invitation_id": invitation.invitation_id,
        // One-time secret: the database stores only its digest.
        "token": invitation.token,
        "email": invitation.email,
        "role": invitation.role
    })
}

fn user_value(user: UserSummary) -> JsonValue {
    json!({
        "id": user.id,
        "subject": user.subject,
        "realm": user.realm,
        "email": user.email,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
        "settings": user.settings
    })
}

fn org_summary_value(org: OrgSummary) -> JsonValue {
    json!({
        "id": org.id,
        "slug": org.slug,
        "name": org.name,
        "description": org.description,
        "role": org.role
    })
}

fn project_summary_value(project: ProjectSummary) -> JsonValue {
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

fn package_summary_value(package: PackageSummary) -> JsonValue {
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
        "config": package.config,
        "latest_version": package.latest_version,
        "download_count": package.download_count,
        "version_count": package.version_count
    })
}

fn package_value(package: zed_orm_core::entities::package::Model) -> JsonValue {
    json!({
        "id": package.id,
        "org_id": package.org_id,
        "project_id": package.project_id,
        "name": package.name,
        "description": package.description,
        "vcs": package.vcs,
        "repo_url": package.repo_url,
        "homepage_url": package.homepage_url,
        "keywords": package.keywords,
        "visibility": package.visibility,
        "config": package.config,
        "download_count": package.download_count,
        "version_count": package.version_count,
        "latest_version": package.latest_version,
        "first_published_at": package.first_published_at,
        "created_at": package.created_at,
        "updated_at": package.updated_at
    })
}

fn strongest_role<'a>(org_role: Option<&'a str>, project_role: Option<&'a str>) -> Option<&'a str> {
    [org_role, project_role]
        .into_iter()
        .flatten()
        .max_by_key(|role| match *role {
            "owner" => 4,
            "admin" => 3,
            "member" => 2,
            "reader" => 1,
            _ => 0,
        })
}

fn contains_ci(value: &str, query: &str) -> bool {
    value
        .to_ascii_lowercase()
        .contains(&query.to_ascii_lowercase())
}

fn normalize_archive_format(value: &str) -> ApiResult<&'static str> {
    match value {
        "tar.gz" | "tar_gz" | "tgz" => Ok("tar.gz"),
        "tar.zst" | "tar_zst" | "tzst" => Ok("tar.zst"),
        "zip" => Ok("zip"),
        _ => Err(ApiErr::bad_request(
            "invalid_archive_format",
            "archive format must be tar.gz, tar.zst, or zip",
        )),
    }
}

fn normalize_upload_status(value: &str) -> String {
    match value {
        "complete" | "completed" | "published" => "verified".to_owned(),
        known @ ("pending" | "uploading" | "stored" | "verified" | "failed" | "aborted") => {
            known.to_owned()
        }
        unknown => unknown.to_owned(),
    }
}

fn is_empty_object(value: &JsonValue) -> bool {
    value.as_object().is_some_and(serde_json::Map::is_empty)
}

fn empty_object() -> JsonValue {
    json!({})
}

fn empty_array() -> JsonValue {
    json!([])
}

fn default_vcs() -> String {
    "git".to_owned()
}

fn default_private() -> String {
    "private".to_owned()
}

fn default_archive_format() -> String {
    "tar.gz".to_owned()
}

fn default_upload_status() -> String {
    "pending".to_owned()
}

fn default_storage_backend() -> String {
    "r2".to_owned()
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
    fn invitation_tokens_are_high_entropy_and_only_the_digest_is_persistable() {
        let input = invitation_input(InvitationRequest {
            email: "member@example.test".to_owned(),
            role: "member".to_owned(),
        });
        assert!(input.token.starts_with("zpkg_inv_"));
        assert!(input.token.len() >= 64);
        assert_eq!(input.token_hash.len(), 64);
        assert!(!input.token_hash.contains(&input.token));
    }

    #[test]
    fn archive_aliases_canonicalize_to_stored_formats() {
        assert_eq!(normalize_archive_format("tar_gz").unwrap(), "tar.gz");
        assert_eq!(normalize_archive_format("tar.zst").unwrap(), "tar.zst");
        assert!(normalize_archive_format("rar").is_err());
    }

    #[test]
    fn database_policy_errors_keep_their_public_semantics() {
        let error = map_orm_error(OrmError::VisibilityDownloadLimitExceeded(
            "package has 51 downloads".to_owned(),
        ));
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "visibility_window_closed");
    }

    #[test]
    fn strongest_membership_scope_wins() {
        assert_eq!(strongest_role(Some("reader"), Some("admin")), Some("admin"));
        assert_eq!(strongest_role(Some("owner"), Some("member")), Some("owner"));
    }
}
