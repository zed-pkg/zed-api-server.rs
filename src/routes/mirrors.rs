//! What this deployment advertises about itself: where else its contents can
//! be fetched, and the signed index for one package.
//!
//! The bootstrap document exists to break a circularity. A client that cannot
//! reach the registry cannot ask the registry where its mirrors are — so every
//! mirror serves the same document, and reaching any one of them recovers the
//! whole set, including hosts in DNS zones this one does not depend on.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use zed_interfaces::mirror::{MIRROR_BOOTSTRAP_SCHEMA_V1, MirrorBootstrapV1};
use zed_interfaces::registry::{MirrorsResponse, SignedIndexResponse};
use zed_interfaces::signing::{IndexAttestationV1, IndexEntryV1, SIGNED_INDEX_SCHEMA_V1};

use crate::entities::version;
use crate::error::ApiResult;
use crate::state::AppState;

use super::{artifact_format, find_org, find_package};

pub async fn get_mirrors(State(state): State<Arc<AppState>>) -> Json<MirrorsResponse> {
    Json(MirrorsResponse {
        registry_url: state.public_base_url.clone(),
        mirrors: state.mirrors.clone(),
    })
}

/// The same content at the well-known path, so a client looking for a
/// bootstrap finds one at the same URL on every mirror kind.
pub async fn get_bootstrap(State(state): State<Arc<AppState>>) -> Json<MirrorBootstrapV1> {
    Json(MirrorBootstrapV1 {
        schema: MIRROR_BOOTSTRAP_SCHEMA_V1.to_owned(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        registry_url: state.public_base_url.clone(),
        mirrors: state.mirrors.clone(),
    })
}

/// A package's version index in the shape a mirror serves it.
///
/// A stored publisher-signed document wins: it is the only form a client under
/// `--trust-mirror-metadata` will accept, because an index this server
/// assembled carries this server's authority, and a client asking a mirror has
/// already decided it cannot rely on that.
///
/// Without one, the assembled unsigned index is still served — it is useful to
/// a browser, to `zed find`, and to any client that reached the canonical host
/// over TLS. It simply will not satisfy a mirror-fallback resolution, which is
/// the correct outcome rather than a gap: an unsigned index accepted from a
/// mirror is exactly what an attacker would supply.
pub async fn get_signed_index(
    State(state): State<Arc<AppState>>,
    Path((org_slug, name)): Path<(String, String)>,
) -> ApiResult<Json<SignedIndexResponse>> {
    let org_row = find_org(&state, &org_slug).await?;
    let pkg = find_package(&state, &org_row, &name).await?;

    if let Some(stored) = pkg.signed_index.clone()
        && let Ok(document) = serde_json::from_value::<SignedIndexResponse>(stored)
    {
        return Ok(Json(document));
    }

    let rows = version::Entity::find()
        .filter(version::Column::PackageId.eq(pkg.id))
        .all(&state.db)
        .await?;

    let mut ordered: Vec<String> = rows.iter().map(|row| row.version.clone()).collect();
    zed_interfaces::version::sort_desc(&mut ordered);
    let mut versions: Vec<IndexEntryV1> = rows
        .iter()
        .map(|row| IndexEntryV1 {
            version: row.version.clone(),
            sha256: row.sha256.clone(),
            size: row.size.max(0) as u64,
            format: artifact_format(&row.format),
            vcs_tag: row.vcs_tag.clone(),
            vcs_commit: row.vcs_commit.clone().unwrap_or_default(),
            published_at: row.published_at.to_rfc3339(),
            yanked: row.yanked,
        })
        .collect();
    versions.sort_by_key(|entry| {
        ordered
            .iter()
            .position(|candidate| candidate == &entry.version)
            .unwrap_or(usize::MAX)
    });

    // From the newest publish, so the advertised mirror set is the one the most
    // recent release declared rather than one a long-abandoned version did.
    let mirrors = rows
        .iter()
        .max_by_key(|row| row.published_at)
        .and_then(|row| serde_json::from_value(row.mirrors.clone()).ok())
        .unwrap_or_default();

    Ok(Json(SignedIndexResponse {
        schema: SIGNED_INDEX_SCHEMA_V1.to_owned(),
        payload: IndexAttestationV1 {
            org: org_slug,
            name,
            generated_at: chrono::Utc::now().to_rfc3339(),
            sequence: pkg.index_sequence.max(1) as u64,
            versions,
            mirrors,
        },
        signatures: Vec::new(),
    }))
}

/// Accept a publisher-signed index for a package.
///
/// Written by `zed mirror publish-index` rather than by `zed publish`:
/// building it needs the full version list, which is a registry read, and a
/// publish that has already been accepted must not be able to fail on one.
pub async fn put_signed_index(
    State(state): State<Arc<AppState>>,
    Path((org_slug, name)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
    Json(document): Json<SignedIndexResponse>,
) -> ApiResult<Json<SignedIndexResponse>> {
    let token = crate::auth::require_token(&state.db, &headers).await?;
    let org_row = find_org(&state, &org_slug).await?;
    crate::rbac::authorize_publish(
        token.org_id,
        crate::rbac::Role::parse(&token.role),
        org_row.id,
    )?;
    let pkg = find_package(&state, &org_row, &name).await?;

    if document.payload.org != org_slug || document.payload.name != name {
        return Err(crate::error::ApiErr::bad_request(
            "index_identity_mismatch",
            "the signed index names a different package than the route does",
        ));
    }

    let candidate = zed_interfaces::signing::SignedIndexV1 {
        schema: document.schema.clone(),
        payload: document.payload.clone(),
        signatures: document.signatures.clone(),
    };
    candidate.validate().map_err(|error| {
        crate::error::ApiErr::bad_request("invalid_index", format!("invalid signed index: {error}"))
    })?;
    let keys = super::keys::load_keys(&state, org_row.id).await?;
    let preimage = zed_interfaces::signing::index_attestation_preimage(&document.payload).map_err(
        |error| {
            crate::error::ApiErr::bad_request(
                "invalid_index",
                format!("cannot reconstruct the signed payload: {error}"),
            )
        },
    )?;
    crate::signing::verify_any(&preimage, &document.signatures, &keys).map_err(|error| {
        crate::error::ApiErr::bad_request(
            "signature_invalid",
            format!("no enrolled key verifies this index: {error}"),
        )
    })?;

    // Monotonic or nothing. Accepting a lower sequence would let a replayed
    // upload roll consumers back to an index that predates a security release,
    // which is precisely what the counter exists to prevent.
    if document.payload.sequence < pkg.index_sequence.max(0) as u64 {
        return Err(crate::error::ApiErr::conflict(
            "index_rollback",
            format!(
                "index sequence {} is older than the stored {}",
                document.payload.sequence, pkg.index_sequence
            ),
        ));
    }

    let mut active: crate::entities::package::ActiveModel = pkg.into();
    active.signed_index = sea_orm::ActiveValue::Set(Some(serde_json::to_value(&document)?));
    active.index_sequence = sea_orm::ActiveValue::Set(document.payload.sequence as i64);
    sea_orm::ActiveModelTrait::update(active, &state.db).await?;

    Ok(Json(document))
}
