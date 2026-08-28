//! Package and version metadata reads.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use zed_interfaces::registry::{PackageMetadata, VersionMetadata};

use crate::entities::version;
use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;

use super::{find_org, find_package, version_metadata, visible_versions_desc};

pub async fn get_package(
    State(state): State<Arc<AppState>>,
    Path((org_slug, name)): Path<(String, String)>,
) -> ApiResult<Json<PackageMetadata>> {
    let org_row = find_org(&state, &org_slug).await?;
    let pkg = find_package(&state, &org_row, &name).await?;
    let rows = version::Entity::find()
        .filter(version::Column::PackageId.eq(pkg.id))
        .all(&state.db)
        .await?;
    let versions = visible_versions_desc(&rows);
    // Compute before moving fields out of `pkg`.
    let tags = super::tags_of(&pkg);
    Ok(Json(PackageMetadata {
        org: org_slug,
        name,
        description: pkg.description,
        vcs: pkg.vcs.parse().unwrap_or_default(),
        repo_url: pkg.repo_url,
        version_scheme: zed_interfaces::version::VersionScheme::from_str_lenient(
            &pkg.version_scheme,
        ),
        latest: versions.first().cloned(),
        tags,
        versions,
        // From the newest publish: the mirror set a package advertises is the
        // one its most recent release declared, not one an abandoned version
        // named years ago.
        mirrors: rows
            .iter()
            .max_by_key(|row| row.published_at)
            .and_then(|row| serde_json::from_value(row.mirrors.clone()).ok())
            .unwrap_or_default(),
        // Inlined so a client that resolves a package also learns how to
        // verify a mirror's answer next time — without a second round trip it
        // may not get to make.
        signing_keys: super::keys::load_keys(&state, org_row.id)
            .await
            .unwrap_or_default(),
    }))
}

pub async fn get_version(
    State(state): State<Arc<AppState>>,
    Path((org_slug, name, ver)): Path<(String, String, String)>,
) -> ApiResult<Json<VersionMetadata>> {
    let org_row = find_org(&state, &org_slug).await?;
    let pkg = find_package(&state, &org_row, &name).await?;
    let row = version::Entity::find()
        .filter(version::Column::PackageId.eq(pkg.id))
        .filter(version::Column::Version.eq(&ver))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiErr::not_found("version"))?;
    Ok(Json(version_metadata(&state, &org_slug, &name, &row)))
}
