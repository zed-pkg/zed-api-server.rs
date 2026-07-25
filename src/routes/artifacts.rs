//! Artifact download (by sha256) and unpkg-style single-file serving.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use tokio_util::io::ReaderStream;

use crate::entities::version;
use crate::error::{ApiErr, ApiResult};
use crate::files;
use crate::state::AppState;
use crate::storage::Download;

use super::{artifact_format, find_org, find_package};

const IMMUTABLE: &str = "public, max-age=31536000, immutable";

pub async fn get_artifact(
    State(state): State<Arc<AppState>>,
    Path(sha256): Path<String>,
) -> ApiResult<Response> {
    let row = version::Entity::find()
        .filter(version::Column::Sha256.eq(&sha256))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiErr::not_found("artifact"))?;
    match state.store.download(&row.artifact_key).await? {
        Download::Redirect(url) => {
            Ok((StatusCode::FOUND, [(header::LOCATION, url)]).into_response())
        }
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
