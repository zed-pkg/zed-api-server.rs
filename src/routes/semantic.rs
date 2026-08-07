//! RAG / embedding endpoints (Postgres-only; pgvector has no SQLite analogue).
//!
//! - `PUT /v1/packages/{org}/{name}/embedding` upserts a package's embedding
//!   for one model (publish authority).
//! - `POST /v1/search/semantic` ranks stored embeddings by cosine distance
//!   within one model's space.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use sea_orm::{ConnectionTrait, DatabaseBackend, EntityTrait};
use zed_interfaces::registry::{
    EmbeddingUpsertRequest, SemanticHit, SemanticSearchRequest, SemanticSearchResponse,
};

use crate::auth::require_token;
use crate::embeddings;
use crate::entities::{org, package};
use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;

use super::search::{has_all_tags, parse_tag_filter};
use super::{find_org, find_package};

/// Vector features require Postgres (pgvector). Fail clearly elsewhere rather
/// than emit SQL SQLite can't run.
fn require_pg(state: &AppState) -> ApiResult<()> {
    if state.db.get_database_backend() == DatabaseBackend::Postgres {
        Ok(())
    } else {
        Err(ApiErr::bad_request(
            "vector_unsupported",
            "embedding search requires a Postgres (pgvector) backend",
        ))
    }
}

pub async fn upsert_embedding(
    State(state): State<Arc<AppState>>,
    Path((org_slug, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<EmbeddingUpsertRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_pg(&state)?;
    let token = require_token(&state.db, &headers).await?;
    let org_row = find_org(&state, &org_slug).await?;
    // Writing a package's embedding is a mutation of its published metadata:
    // same authority as publish/yank.
    crate::rbac::authorize_publish(
        token.org_id,
        crate::rbac::Role::parse(&token.role),
        org_row.id,
    )?;
    let pkg = find_package(&state, &org_row, &name).await?;

    embeddings::upsert(
        &state.db,
        pkg.id,
        &request.model,
        &request.embedding,
        &request.content,
    )
    .await
    .map_err(|e| ApiErr::bad_request("invalid_embedding", e.to_string()))?;

    Ok(Json(serde_json::json!({
        "org": org_slug, "name": name, "model": request.model,
    })))
}

pub async fn semantic_search(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SemanticSearchRequest>,
) -> ApiResult<Json<SemanticSearchResponse>> {
    require_pg(&state)?;
    let want_tags = parse_tag_filter(&Some(request.tags.join(",")));
    // Over-fetch a little so tag post-filtering still returns a full page.
    let raw_limit = (request.limit as u64).clamp(1, 100);
    let fetch = if want_tags.is_empty() {
        raw_limit
    } else {
        (raw_limit * 4).min(100)
    };

    let neighbors = embeddings::search(&state.db, &request.model, &request.embedding, fetch)
        .await
        .map_err(|e| ApiErr::bad_request("invalid_embedding", e.to_string()))?;

    let mut items = Vec::with_capacity(neighbors.len());
    for neighbor in neighbors {
        let Some((pkg, Some(org_row))) = package::Entity::find_by_id(neighbor.package_id)
            .find_also_related(org::Entity)
            .one(&state.db)
            .await?
        else {
            continue;
        };
        let tags = super::tags_of(&pkg);
        if !has_all_tags(&tags, &want_tags) {
            continue;
        }
        items.push(SemanticHit {
            org: org_row.slug,
            name: pkg.name,
            description: pkg.description,
            distance: neighbor.distance,
            tags,
        });
        if items.len() as u64 >= raw_limit {
            break;
        }
    }
    Ok(Json(SemanticSearchResponse { items }))
}
