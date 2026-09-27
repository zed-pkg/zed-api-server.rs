//! Artifact download (by sha256) and unpkg-style single-file serving.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use tokio_util::io::ReaderStream;

use crate::auth::require_package_reader;
use crate::entities::version;
use crate::error::{ApiErr, ApiResult};
use crate::files;
use crate::state::AppState;
use crate::storage::Download;

use super::{artifact_format, find_org, find_package};

const IMMUTABLE: &str = "public, max-age=31536000, immutable";

fn artifact_requires_private_authorization(
    packages: &[zed_orm_core::models::PackageSummary],
) -> bool {
    !packages.is_empty()
        && packages
            .iter()
            .all(|package| package.visibility != "public")
}

async fn authorize_artifact_read(
    state: &AppState,
    headers: &HeaderMap,
    sha256: &str,
) -> ApiResult<()> {
    let read = state.registry_read.as_ref().ok_or_else(|| {
        ApiErr::service_unavailable(
            "registry_data_plane_unavailable",
            "canonical registry read context is not configured",
        )
    })?;
    let packages = zed_orm_core::read::packages_for_artifact_sha256(read, sha256)
        .await
        .map_err(crate::account::map_orm_error)?;

    // Legacy-only artifacts predate canonical visibility and remain in the
    // existing anonymous compatibility plane. A shared digest with any public
    // canonical reference is public bytes by definition; private references
    // cannot make those same bytes secret again.
    if !artifact_requires_private_authorization(&packages) {
        return Ok(());
    }

    let reader = require_package_reader(state, headers).await?;
    let Some(user) =
        zed_orm_core::read::user_by_subject(read, &reader.session.realm, reader.session.subject)
            .await
            .map_err(crate::account::map_orm_error)?
    else {
        return Err(ApiErr::not_found("artifact"));
    };

    for package in &packages {
        let org_role = zed_orm_core::read::org_role_for_user(read, package.org_id, user.id)
            .await
            .map_err(crate::account::map_orm_error)?;
        if org_role.is_some() {
            return Ok(());
        }
        if let Some(project_id) = package.project_id {
            let project_role = zed_orm_core::read::project_role_for_user(read, project_id, user.id)
                .await
                .map_err(crate::account::map_orm_error)?;
            if project_role.is_some() {
                return Ok(());
            }
        }
    }

    // Do not confirm a private artifact's existence to an authenticated user
    // who lacks membership in every referencing package.
    Err(ApiErr::not_found("artifact"))
}

pub async fn get_artifact(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(sha256): Path<String>,
) -> ApiResult<Response> {
    authorize_artifact_read(&state, &headers, &sha256).await?;
    let row = version::Entity::find()
        .filter(version::Column::Sha256.eq(&sha256))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiErr::not_found("artifact"))?;
    match state.store.download(&row.artifact_key).await? {
        Download::Redirect(url) => {
            Ok((StatusCode::FOUND, [(header::LOCATION, url)]).into_response())
        }
        // Process-memory downloads reuse the store's immutable ref-counted
        // buffer. Body::from(Bytes) does not copy the artifact.
        Download::Bytes { bytes } => Ok((
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    artifact_format(&row.format).content_type().to_string(),
                ),
                (header::CACHE_CONTROL, IMMUTABLE.to_string()),
                (header::CONTENT_LENGTH, bytes.len().to_string()),
            ],
            Body::from(bytes),
        )
            .into_response()),
        // Streamed, never buffered: serving a 100 MB artifact costs a read
        // buffer, not 100 MB of resident memory per concurrent request.
        Download::File { file, len } => Ok((
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    artifact_format(&row.format).content_type().to_string(),
                ),
                (header::CACHE_CONTROL, IMMUTABLE.to_string()),
                (header::CONTENT_LENGTH, len.to_string()),
            ],
            Body::from_stream(ReaderStream::new(file)),
        )
            .into_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;
    use zed_orm_core::models::PackageSummary;

    fn package(visibility: &str) -> PackageSummary {
        PackageSummary {
            id: Uuid::nil(),
            org_id: Uuid::nil(),
            org_slug: "example".into(),
            project_id: None,
            project_slug: None,
            name: "pkg".into(),
            description: None,
            visibility: visibility.into(),
            repo_url: "https://github.com/example/pkg".into(),
            config: json!({}),
            latest_version: None,
            download_count: 0,
            version_count: 1,
            updated_at: chrono::Utc::now().fixed_offset(),
        }
    }

    #[test]
    fn shared_digest_is_anonymous_when_any_reference_is_public() {
        assert!(!artifact_requires_private_authorization(&[]));
        assert!(!artifact_requires_private_authorization(&[package(
            "public"
        )]));
        assert!(!artifact_requires_private_authorization(&[
            package("private"),
            package("public"),
        ]));
    }

    #[test]
    fn all_private_digest_requires_resource_authorization() {
        assert!(artifact_requires_private_authorization(&[
            package("private"),
            package("private"),
        ]));
    }
}

pub async fn get_file(
    State(state): State<Arc<AppState>>,
    Path((org_slug, name, ver, path)): Path<(String, String, String, String)>,
) -> ApiResult<Response> {
    let org_row = find_org(&state, &org_slug).await?;
    let pkg = find_package(&state, &org_row, &name).await?;
    let row = version::Entity::find()
        .filter(version::Column::PackageId.eq(pkg.id))
        .filter(version::Column::Version.eq(&ver))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiErr::not_found("version"))?;
    let archive = state.store.get_bytes(&row.artifact_key).await?;
    // Decompression is CPU-bound and can run long on a large artifact. Left
    // inline it blocks a tokio worker, and a future that never yields cannot be
    // interrupted by the router's TimeoutLayer — so the request keeps burning
    // CPU past the timeout. Hand it to the blocking pool.
    let format = artifact_format(&row.format);
    let want = path.clone();
    let file = tokio::task::spawn_blocking(move || files::extract_file(&archive, format, &want))
        .await
        .map_err(|err| ApiErr::from(anyhow::anyhow!("extract task failed: {err}")))?
        .map_err(ApiErr::from)?
        .ok_or_else(|| ApiErr::not_found("file"))?;
    // Active-content types are neutralized and the response is sandboxed so
    // author-published files cannot run as active content from this origin (H2).
    Ok((StatusCode::OK, files::served_file_headers(&path), file).into_response())
}
