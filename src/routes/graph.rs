//! Dependency-graph reads.
//!
//! Two distinct facts, deliberately not conflated (see the `zpkg/dependency-graph/v1`
//! RFC in `zed-interfaces`): the immutable *declared* requirements of one exact
//! package version, and an immutable *resolution artifact* addressed by its
//! resolution digest.
//!
//! Declared requirements are read from the canonical immutable package-version
//! row in Postgres. That row is transactionally adopted from the verified,
//! content-addressed publish and retains the normalized manifest plus the exact
//! artifact identity. The server never resolves anything —
//! producing a resolved graph requires resolver state the registry does not
//! have, and re-resolving old metadata against today's index and labelling the
//! result "the graph for this lock" is precisely what the contract forbids.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
#[cfg(test)]
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zed_interfaces::{
    DEPENDENCY_GRAPH_AUTHORITATIVE_HEADER, DEPENDENCY_GRAPH_DEFAULT_MAX_EDGES,
    DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES, DEPENDENCY_GRAPH_DEFAULT_MAX_NODES,
    DEPENDENCY_GRAPH_DIGEST_HEADER, DEPENDENCY_GRAPH_SCHEMA_V1, DeclaredDependency,
    DependencyGraphData, DependencyGraphDocument, DependencyGraphFormat, DependencyKind,
    PackageVersionIdentity,
};

use crate::auth::{bearer_token, require_account, require_token};
#[cfg(test)]
use crate::entities::version;
use crate::error::{ApiErr, ApiResult};
#[cfg(test)]
use crate::files;
use crate::state::AppState;

use super::find_org;
#[cfg(test)]
use super::{artifact_format, find_package};

/// Declared metadata is immutable for an exact package version, so it caches
/// like the artifact itself.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const PRIVATE_NO_STORE: &str = "private, no-store";

/// Visibility-sensitive cache policy for one canonical package graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DeclaredGraphAccess {
    Public,
    Private,
}

impl DeclaredGraphAccess {
    pub(super) const fn cache_control(self) -> &'static str {
        match self {
            Self::Public => IMMUTABLE,
            Self::Private => PRIVATE_NO_STORE,
        }
    }

    pub(super) const fn vary(self) -> &'static str {
        match self {
            Self::Public => "Accept",
            Self::Private => "Accept, Authorization",
        }
    }
}

/// Every failure to produce a graph — unknown org, unknown package, unknown
/// version, unknown or malformed resolution digest, and (once private graphs
/// exist) an unauthorized private read — answers with this one response.
/// Distinguishing them would let an anonymous caller enumerate private
/// topology by probing status codes.
fn graph_not_found() -> ApiErr {
    ApiErr {
        status: StatusCode::NOT_FOUND,
        code: "not_found",
        message: "dependency graph not found".to_string(),
    }
}

/// An empty body whose length is deliberately unknown to Hyper.
///
/// Hyper 1.11 removes an explicit selected-representation `Content-Length`
/// from a 304 when the body advertises an exact zero size. An unknown size hint
/// lets Hyper retain that RFC-valid metadata header, while the 304 status still
/// forces the wire body to zero bytes. `is_end_stream` must remain false until
/// Hyper has classified the response body.
struct MetadataOnlyBody;

impl HttpBody for MetadataOnlyBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}

pub(super) fn not_modified_response(headers: HeaderMap) -> Response {
    let mut response = Response::new(axum::body::Body::new(MetadataOnlyBody));
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    *response.headers_mut() = headers;
    response
}

fn requires_graph_authorization(visibility: &str) -> ApiResult<bool> {
    match visibility {
        "public" => Ok(false),
        "internal" | "private" => Ok(true),
        // A newly introduced visibility state is protected until this service
        // explicitly understands its authority model.
        _ => Err(graph_not_found()),
    }
}

#[derive(Debug, Deserialize)]
pub struct DeclaredQuery {
    #[serde(default)]
    view: Option<String>,
    #[serde(default)]
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResolutionQuery {
    #[serde(default)]
    format: Option<String>,
}

/// `GET|HEAD /v1/packages/{org}/{name}/versions/{version}/dependency-graph?view=declared`
pub async fn get_declared_graph(
    State(state): State<Arc<AppState>>,
    Path((org_slug, name, ver)): Path<(String, String, String)>,
    Query(query): Query<DeclaredQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    // This route serves declarations only. An exact package version has no one
    // universal resolved graph — that depends on target, features, registry
    // checkpoints and lock decisions — so asking for one here is an error
    // rather than a silently different answer.
    match query.view.as_deref() {
        Some("declared") => {}
        _ => {
            return Err(ApiErr::bad_request(
                "unsupported_view",
                "package-version dependency graphs are declared-view only; \
                 exact resolved graphs are addressed by resolution digest",
            ));
        }
    }
    let format = resolve_format(&headers, query.format.as_deref())?;
    let (document, access) =
        load_authorized_declared_document(&state, &headers, &org_slug, &name, &ver).await?;
    respond(
        &headers,
        format,
        &document,
        &filename_stem(&org_slug, &name, &ver),
        access,
    )
}

/// Shared authorized loader for the canonical and extended representation
/// routes. Keeping access, artifact extraction, and typed graph construction in
/// one path prevents the two format families from drifting on bounds or policy.
pub(super) async fn load_authorized_declared_document(
    state: &AppState,
    headers: &HeaderMap,
    org_slug: &str,
    name: &str,
    ver: &str,
) -> ApiResult<(DependencyGraphDocument, DeclaredGraphAccess)> {
    let Some(read) = state.registry_read.as_ref() else {
        // Legacy-only unit fixtures predate the canonical Postgres plane. Keep
        // their artifact-integrity coverage without permitting this fallback in
        // a production build.
        #[cfg(test)]
        return load_legacy_declared_document(
            state,
            org_slug,
            name,
            ver,
            DeclaredGraphAccess::Public,
        )
        .await;

        #[cfg(not(test))]
        return Err(ApiErr::service_unavailable(
            "registry_data_plane_unavailable",
            "canonical registry read context is not configured",
        ));
    };
    // Look the package up once and carry that exact row through authorization
    // and version loading. Repeating the lookup on either side of the access
    // check would leave a fail-open race if visibility, project ownership, or
    // the package row changed between queries.
    let (package, canonical_org) =
        zed_orm_core::read::package_by_org_and_name(read, org_slug, name)
            .await
            .map_err(|error| {
                ApiErr::from(anyhow::anyhow!(
                    "canonical package visibility lookup failed: {error}"
                ))
            })?
            .ok_or_else(graph_not_found)?;
    let access =
        authorize_declared_graph(state, headers, org_slug, &package, &canonical_org).await?;
    // Use the final core checkpoint's exact lookup rather than scanning the
    // 100-row page-oriented version listing. The package row carried through
    // authorization supplies the immutable package id for this query.
    let row = zed_orm_core::read::package_version_by_package_and_version(read, package.id, ver)
        .await
        .map_err(|error| {
            ApiErr::from(anyhow::anyhow!(
                "canonical package-version lookup failed: {error}"
            ))
        })?
        .ok_or_else(graph_not_found)?;
    let manifest: zed_interfaces::Manifest =
        serde_json::from_value(row.manifest).map_err(|error| {
            ApiErr::from(anyhow::anyhow!(
                "canonical package-version manifest is invalid: {error}"
            ))
        })?;
    if manifest.package.org != org_slug
        || manifest.package.name != name
        || manifest.package.version != ver
    {
        return Err(ApiErr::from(anyhow::anyhow!(
            "canonical package-version manifest coordinate does not match its package row: \
             expected {org_slug}/{name}@{ver}, stored {}/{}@{}",
            manifest.package.org,
            manifest.package.name,
            manifest.package.version
        )));
    }

    let document = declared_document(&state.registry_id, ver, &manifest)?;
    Ok((document, access))
}

#[cfg(test)]
async fn load_legacy_declared_document(
    state: &AppState,
    org_slug: &str,
    name: &str,
    ver: &str,
    access: DeclaredGraphAccess,
) -> ApiResult<(DependencyGraphDocument, DeclaredGraphAccess)> {
    let org_row = find_org(state, org_slug)
        .await
        .map_err(|_| graph_not_found())?;
    let pkg = find_package(state, &org_row, name)
        .await
        .map_err(|_| graph_not_found())?;
    let row = version::Entity::find()
        .filter(version::Column::PackageId.eq(pkg.id))
        .filter(version::Column::Version.eq(ver))
        .one(&state.db)
        .await?
        .ok_or_else(graph_not_found)?;
    let archive = state.store.get_bytes(&row.artifact_key).await?;
    let archive_format = artifact_format(&row.format);
    let manifest_bytes = tokio::task::spawn_blocking(move || {
        files::extract_file(
            &archive,
            archive_format,
            zed_interfaces::paths::MANIFEST_FILE,
        )
    })
    .await
    .map_err(|error| ApiErr::from(anyhow::anyhow!("extract task failed: {error}")))?
    .map_err(ApiErr::from)?
    .ok_or_else(graph_not_found)?;
    let manifest_text = String::from_utf8(manifest_bytes)
        .map_err(|_| ApiErr::from(anyhow::anyhow!("stored manifest is not valid UTF-8")))?;
    let manifest = zed_interfaces::Manifest::parse(&manifest_text).map_err(|error| {
        ApiErr::from(anyhow::anyhow!("stored manifest does not parse: {error}"))
    })?;
    if manifest.package.org != org_slug
        || manifest.package.name != name
        || manifest.package.version != ver
    {
        return Err(ApiErr::from(anyhow::anyhow!(
            "stored package-version manifest coordinate does not match its package row: \
             expected {org_slug}/{name}@{ver}, stored {}/{}@{}",
            manifest.package.org,
            manifest.package.name,
            manifest.package.version
        )));
    }
    let document = declared_document(&state.registry_id, ver, &manifest)?;
    Ok((document, access))
}

/// Authorize a declared-graph read against the canonical package visibility.
///
/// Public packages remain anonymous. Internal and private packages require either a live
/// legacy token scoped to the matching legacy organization or a delegated
/// browser account that belongs to the canonical organization/owning project.
/// Every missing, invalid, cross-tenant, or insufficient credential collapses
/// to the same graph 404 so private package coordinates cannot be enumerated.
pub(super) async fn authorize_declared_graph(
    state: &AppState,
    headers: &HeaderMap,
    org_slug: &str,
    package: &zed_orm_core::entities::package::Model,
    canonical_org: &zed_orm_core::entities::org::Model,
) -> ApiResult<DeclaredGraphAccess> {
    let read = state.registry_read.as_ref().ok_or_else(|| {
        ApiErr::service_unavailable(
            "registry_data_plane_unavailable",
            "canonical registry read context is not configured",
        )
    })?;

    if !requires_graph_authorization(&package.visibility)? {
        return Ok(DeclaredGraphAccess::Public);
    }
    if bearer_token(headers).is_none() {
        return Err(graph_not_found());
    }

    // CLI/package tokens are scoped in the transitional plane. Only a scoped
    // token for this exact legacy organization is accepted; an unscoped admin
    // token is intentionally not universal private-read authority.
    if let Ok(token) = require_token(&state.db, headers).await {
        let legacy_org = find_org(state, org_slug)
            .await
            .map_err(|_| graph_not_found())?;
        return if token.org_id == Some(legacy_org.id) {
            Ok(DeclaredGraphAccess::Private)
        } else {
            Err(graph_not_found())
        };
    }

    // A browser bearer must be a session-backed, audience-bound delegated
    // product token. Authentication failures (including a dependency outage)
    // are concealed here rather than exposing that the private package exists.
    let account = require_account(state, headers)
        .await
        .map_err(|_| graph_not_found())?;
    let user =
        zed_orm_core::read::user_by_subject(read, &account.session.realm, account.session.subject)
            .await
            .map_err(|_| graph_not_found())?
            .ok_or_else(graph_not_found)?;
    let org_role = zed_orm_core::read::org_role_for_user(read, canonical_org.id, user.id)
        .await
        .map_err(|_| graph_not_found())?;
    if org_role.is_some() {
        return Ok(DeclaredGraphAccess::Private);
    }
    if let Some(project_id) = package.project_id {
        let project_role = zed_orm_core::read::project_role_for_user(read, project_id, user.id)
            .await
            .map_err(|_| graph_not_found())?;
        if project_role.is_some() {
            return Ok(DeclaredGraphAccess::Private);
        }
    }
    Err(graph_not_found())
}

/// `GET|HEAD /v1/resolutions/{resolution_digest}/dependency-graph`
///
/// Resolution artifacts are content-addressed records published by a resolver,
/// stored by DEN-2868. Until that storage exists there is nothing to serve, and
/// the honest answer is the same indistinguishable 404 an unauthorized or
/// unknown digest gets. The alternative — resolving server-side — is forbidden:
/// the result would carry no lock identity and would not be the graph for the
/// resolution the caller asked about.
pub async fn get_resolution_graph(
    State(_state): State<Arc<AppState>>,
    Path(_digest): Path<String>,
    Query(query): Query<ResolutionQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    // Negotiation still runs first: a caller asking for an unsupported
    // representation learns that from a 406 without learning whether any
    // resolution exists, and the check stays identical once storage lands.
    let _format = resolve_format(&headers, query.format.as_deref())?;
    Err(graph_not_found())
}

/// Map an exact manifest onto the declared view: unresolved requirements, never
/// invented exact versions.
pub(super) fn declared_document(
    registry: &str,
    version: &str,
    manifest: &zed_interfaces::Manifest,
) -> ApiResult<DependencyGraphDocument> {
    if manifest.package.version != version {
        return Err(ApiErr::from(anyhow::anyhow!(
            "stored manifest version {} does not match requested exact version {version}",
            manifest.package.version
        )));
    }
    manifest
        .package
        .version_scheme
        .validate_version(version)
        .map_err(|error| {
            ApiErr::from(anyhow::anyhow!(
                "stored manifest version is invalid for {}: {error}",
                manifest.package.version_scheme.as_str()
            ))
        })?;
    let dependency_count = checked_declared_dependency_count(
        manifest.dependencies.len(),
        manifest.build_dependencies.len(),
    )?;
    let mut dependencies = Vec::with_capacity(dependency_count);
    let runtime = manifest
        .dependencies
        .iter()
        .map(|kv| (kv, DependencyKind::Runtime));
    let build = manifest
        .build_dependencies
        .iter()
        .map(|kv| (kv, DependencyKind::Build));
    for ((key, requirement), kind) in runtime.chain(build) {
        // Publish validates dependency keys, so a key without an `org/name`
        // split means the stored artifact is corrupt. Fail the request rather
        // than emit a graph that quietly omits an edge.
        let (dep_org, dep_name) = key.split_once('/').ok_or_else(|| {
            ApiErr::from(anyhow::anyhow!(
                "stored manifest declares dependency key `{key}` without an org segment"
            ))
        })?;
        dependencies.push(DeclaredDependency {
            registry_id: registry.to_string(),
            org: dep_org.to_string(),
            name: dep_name.to_string(),
            requirement: requirement.clone(),
            kind,
            optional: false,
            default_features: true,
            features: Vec::new(),
            target: None,
        });
    }

    DependencyGraphDocument {
        schema: DEPENDENCY_GRAPH_SCHEMA_V1.to_string(),
        graph: DependencyGraphData::Declared {
            package: PackageVersionIdentity {
                registry_id: registry.to_string(),
                org: manifest.package.org.clone(),
                name: manifest.package.name.clone(),
                version: version.to_string(),
            },
            dependencies,
        },
        graph_digest: None,
    }
    .finalize()
    .map_err(|err| ApiErr::from(anyhow::anyhow!("dependency graph is invalid: {err}")))
}

fn checked_declared_dependency_count(runtime: usize, build: usize) -> ApiResult<usize> {
    let count = runtime
        .checked_add(build)
        .ok_or_else(graph_limit_exceeded)?;
    let nodes = count.checked_add(1).ok_or_else(graph_limit_exceeded)?;
    ensure_graph_counts(nodes, count)?;
    Ok(count)
}

pub(super) fn ensure_graph_bounds(document: &DependencyGraphDocument) -> ApiResult<()> {
    let (nodes, edges) = match &document.graph {
        DependencyGraphData::Declared { dependencies, .. } => (
            dependencies
                .len()
                .checked_add(1)
                .ok_or_else(graph_limit_exceeded)?,
            dependencies.len(),
        ),
        DependencyGraphData::Resolved { nodes, edges, .. } => (nodes.len(), edges.len()),
    };
    ensure_graph_counts(nodes, edges)
}

fn ensure_graph_counts(nodes: usize, edges: usize) -> ApiResult<()> {
    if nodes > DEPENDENCY_GRAPH_DEFAULT_MAX_NODES as usize
        || edges > DEPENDENCY_GRAPH_DEFAULT_MAX_EDGES as usize
    {
        return Err(graph_limit_exceeded());
    }
    Ok(())
}

pub(super) fn ensure_encoded_size(length: usize) -> ApiResult<()> {
    if length as u64 > DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES {
        return Err(representation_too_large());
    }
    Ok(())
}

fn graph_limit_exceeded() -> ApiErr {
    ApiErr {
        status: StatusCode::UNPROCESSABLE_ENTITY,
        code: "graph_limit_exceeded",
        message: "dependency graph exceeds the server node or edge limit".to_string(),
    }
}

fn representation_too_large() -> ApiErr {
    ApiErr {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        code: "graph_representation_too_large",
        message: "dependency graph representation exceeds the server limit".to_string(),
    }
}

/// Resolve the representation from `Accept` and `format=`.
///
/// A conflict is a 406 rather than a silent pick: a caller that sends
/// `Accept: …+json` and `format=toml` has two incompatible expectations, and
/// choosing either one would hand it bytes it cannot parse.
fn resolve_format(
    headers: &HeaderMap,
    format_query: Option<&str>,
) -> ApiResult<DependencyGraphFormat> {
    let from_query = match format_query {
        None => None,
        Some(value) => Some(parse_format_name(value).ok_or_else(|| ApiErr {
            status: StatusCode::NOT_ACCEPTABLE,
            code: "unsupported_format",
            message: format!("unsupported dependency graph format `{value}`"),
        })?),
    };

    let accepted = parse_accept(headers)?;
    match (from_query, accepted) {
        (Some(format), None) => Ok(format),
        (Some(format), Some(accepted)) if accepted.iter().any(|entry| entry.0 == format) => {
            Ok(format)
        }
        (Some(_), Some(_)) => Err(ApiErr {
            status: StatusCode::NOT_ACCEPTABLE,
            code: "format_conflict",
            message: "requested graph representations conflict".to_string(),
        }),
        (None, None) => Ok(DependencyGraphFormat::Json),
        (None, Some(accepted)) => accepted
            .into_iter()
            .fold(
                None::<(DependencyGraphFormat, u16)>,
                |selected, candidate| match selected {
                    Some(current) if current.1 >= candidate.1 => Some(current),
                    _ => Some(candidate),
                },
            )
            .map(|(format, _quality)| format)
            .ok_or_else(|| ApiErr {
                status: StatusCode::NOT_ACCEPTABLE,
                code: "unsupported_format",
                message: "no acceptable dependency graph representation".to_string(),
            }),
    }
}

fn parse_format_name(value: &str) -> Option<DependencyGraphFormat> {
    Some(match value.to_ascii_lowercase().as_str() {
        "json" => DependencyGraphFormat::Json,
        "yaml" | "yml" => DependencyGraphFormat::Yaml,
        "toml" => DependencyGraphFormat::Toml,
        "dot" | "graphviz" => DependencyGraphFormat::Dot,
        "mermaid" | "mmd" => DependencyGraphFormat::Mermaid,
        _ => return None,
    })
}

/// Effective positive qualities for all representations named by every Accept
/// field-line. An exact q=0 exclusion overrides a positive wildcard for that
/// representation. `None` means Accept was absent or contained no media range.
fn parse_accept(headers: &HeaderMap) -> ApiResult<Option<Vec<(DependencyGraphFormat, u16)>>> {
    let formats = [
        DependencyGraphFormat::Json,
        DependencyGraphFormat::Yaml,
        DependencyGraphFormat::Toml,
        DependencyGraphFormat::Dot,
        DependencyGraphFormat::Mermaid,
    ];
    let mut saw_entry = false;
    let mut selected = [None; 5];

    for value in headers.get_all(header::ACCEPT).iter() {
        let value = value.to_str().map_err(|_| ApiErr {
            status: StatusCode::NOT_ACCEPTABLE,
            code: "unsupported_format",
            message: "no acceptable dependency graph representation".to_string(),
        })?;
        for entry in value.split(',').filter(|entry| !entry.trim().is_empty()) {
            saw_entry = true;
            for (index, format) in formats.iter().copied().enumerate() {
                let Some(candidate) = canonical_accept_match(entry, format.media_type()) else {
                    continue;
                };
                if selected[index].is_none_or(|current: (u16, u16)| {
                    candidate.0 > current.0 || (candidate.0 == current.0 && candidate.1 > current.1)
                }) {
                    selected[index] = Some(candidate);
                }
            }
        }
    }

    if !saw_entry {
        return Ok(None);
    }
    Ok(Some(
        formats
            .into_iter()
            .zip(selected)
            .filter_map(|(format, selected)| {
                selected
                    .filter(|(_specificity, quality)| *quality > 0)
                    .map(|(_specificity, quality)| (format, quality))
            })
            .collect(),
    ))
}

fn canonical_accept_match(entry: &str, registered: &str) -> Option<(u16, u16)> {
    let mut parts = entry.split(';');
    let media = parts.next()?.trim().to_ascii_lowercase();
    let (requested_type, requested_subtype) = media.split_once('/')?;
    let mut registered_parts = registered.split(';');
    let (registered_type, registered_subtype) = registered_parts.next()?.trim().split_once('/')?;
    let registered_parameters: Vec<_> = registered_parts
        .filter_map(|parameter| parameter.trim().split_once('='))
        .collect();
    let media_specificity: u16 = match (requested_type, requested_subtype) {
        ("*", "*") => 0,
        (requested_type, "*") if requested_type == registered_type => 1,
        (requested_type, requested_subtype)
            if requested_type == registered_type && requested_subtype == registered_subtype =>
        {
            2
        }
        _ => return None,
    };

    let mut quality = 1_000;
    let mut parameter_specificity = 0_u16;
    for parameter in parts {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("q") {
            quality = parse_accept_quality(value.trim()).unwrap_or(0);
            break;
        }
        let requested_value = value.trim().trim_matches('"');
        if !registered_parameters
            .iter()
            .any(|(registered_name, registered_value)| {
                name.trim().eq_ignore_ascii_case(registered_name.trim())
                    && requested_value
                        .eq_ignore_ascii_case(registered_value.trim().trim_matches('"'))
            })
        {
            return None;
        }
        parameter_specificity = parameter_specificity.saturating_add(1);
    }
    Some((
        media_specificity * 256 + parameter_specificity.min(255),
        quality,
    ))
}

fn parse_accept_quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let fraction = format!("{fraction:0<3}").parse::<u16>().ok()?;
    match whole {
        "0" => Some(fraction),
        "1" if fraction == 0 => Some(1_000),
        _ => None,
    }
}

/// Encode, bound, validate against the caller's `If-None-Match`, and answer.
fn respond(
    headers: &HeaderMap,
    format: DependencyGraphFormat,
    document: &DependencyGraphDocument,
    filename_stem: &str,
    access: DeclaredGraphAccess,
) -> ApiResult<Response> {
    let body = encode(document, format)?;
    // Never return a truncated document: a caller cannot tell a clipped graph
    // from a complete one, and the digest would not match either way.
    ensure_encoded_size(body.len())?;

    // Strong validator over the encoded bytes of *this* representation. The
    // semantic graph digest is deliberately not reused: YAML and TOML of one
    // graph share that digest while their bytes differ, so using it as an ETag
    // would let a cache serve YAML bytes for a JSON request.
    let etag = format!("\"{}\"", hex::encode(Sha256::digest(&body)));
    let graph_digest = document
        .graph_digest
        .clone()
        .ok_or_else(|| ApiErr::from(anyhow::anyhow!("finalized graph carries no digest")))?;
    let disposition = format!(
        "attachment; filename=\"{filename_stem}.dependency-graph.{}\"",
        format.extension()
    );

    let header_value = |value: &str| {
        header::HeaderValue::from_str(value)
            .map_err(|_| ApiErr::from(anyhow::anyhow!("graph response header is not valid ASCII")))
    };
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, header_value(&etag)?);
    response_headers.insert(header::CACHE_CONTROL, header_value(access.cache_control())?);
    response_headers.insert(header::VARY, header_value(access.vary())?);
    response_headers.insert(header::CONTENT_DISPOSITION, header_value(&disposition)?);
    response_headers.insert(
        header::CONTENT_LENGTH,
        header_value(&body.len().to_string())?,
    );
    // Header name is a contract constant, so clients and server cannot drift.
    response_headers.insert(
        header::HeaderName::from_static(DEPENDENCY_GRAPH_DIGEST_HEADER),
        header_value(&graph_digest)?,
    );
    response_headers.insert(
        header::HeaderName::from_static(DEPENDENCY_GRAPH_AUTHORITATIVE_HEADER),
        header::HeaderValue::from_static(if format.is_authoritative() {
            "true"
        } else {
            "false"
        }),
    );

    if if_none_match_matches(headers, &etag) {
        // 304 carries selected-representation metadata, never body bytes.
        return Ok(not_modified_response(response_headers));
    }

    response_headers.insert(header::CONTENT_TYPE, header_value(format.media_type())?);
    Ok((StatusCode::OK, response_headers, body).into_response())
}

/// Weak comparison per RFC 9110 for `If-None-Match` on GET and HEAD: a weak
/// validator can match the same opaque tag emitted as a strong ETag, and `*`
/// matches any existing representation.
fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|candidate| {
            candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
        })
}

/// Download filename built only from validated coordinates, never from
/// caller-supplied bytes: path separators, quotes, control characters, and
/// non-ASCII are replaced rather than reflected into the header.
fn filename_stem(org: &str, name: &str, version: &str) -> String {
    let mut stem = String::with_capacity(org.len() + name.len() + version.len() + 2);
    for (index, part) in [org, name, version].iter().enumerate() {
        if index > 0 {
            stem.push('_');
        }
        for ch in part.chars() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+') {
                stem.push(ch);
            } else {
                stem.push('_');
            }
        }
    }
    stem
}

fn encode(document: &DependencyGraphDocument, format: DependencyGraphFormat) -> ApiResult<Vec<u8>> {
    ensure_graph_bounds(document)?;
    let canonical = document
        .canonical_document_bytes()
        .map_err(|err| ApiErr::from(anyhow::anyhow!("graph canonicalization failed: {err}")))?;
    ensure_encoded_size(canonical.len())?;
    let encoded = match format {
        DependencyGraphFormat::Json => canonical,
        DependencyGraphFormat::Yaml => {
            let value: Value = serde_json::from_slice(&canonical)
                .map_err(|err| ApiErr::from(anyhow::anyhow!("canonical JSON reparse: {err}")))?;
            let mut out = String::new();
            write_yaml(&value, 0, &mut out);
            out.into_bytes()
        }
        DependencyGraphFormat::Toml => {
            let value: Value = serde_json::from_slice(&canonical)
                .map_err(|err| ApiErr::from(anyhow::anyhow!("canonical JSON reparse: {err}")))?;
            write_toml(&value)?.into_bytes()
        }
        DependencyGraphFormat::Dot => render_dot(document)?.into_bytes(),
        DependencyGraphFormat::Mermaid => render_mermaid(document)?.into_bytes(),
    };
    ensure_encoded_size(encoded.len())?;
    Ok(encoded)
}

// ---------------------------------------------------------------------------
// Authoritative text projections.
//
// Both are emitted from the *canonical JSON* rather than from the typed model a
// second time, so all three representations are the same document by
// construction and share one semantic digest. They are written here instead of
// delegated to a general-purpose serializer because the contract constrains the
// output beyond what those guarantee: the YAML must stay inside a
// JSON-compatible safe subset (no tags, anchors, aliases, or merge keys) and the
// TOML must be normalized with absent optionals omitted rather than spelled as
// sentinels.
// ---------------------------------------------------------------------------

/// Emit the safe YAML subset: every scalar is a JSON-escaped double-quoted
/// string or a bare number/bool, and no anchor, alias, tag, or merge key can be
/// produced by construction.
fn write_yaml(value: &Value, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    match value {
        Value::Object(map) if map.is_empty() => out.push_str("{}\n"),
        Value::Object(map) => {
            for (index, (key, child)) in map.iter().enumerate() {
                if index > 0 || indent > 0 {
                    out.push_str(&pad);
                }
                out.push_str(&yaml_scalar_key(key));
                out.push(':');
                match child {
                    Value::Object(inner) if !inner.is_empty() => {
                        out.push('\n');
                        write_yaml(child, indent + 1, out);
                    }
                    Value::Array(items) if !items.is_empty() => {
                        out.push('\n');
                        write_yaml(child, indent + 1, out);
                    }
                    _ => {
                        out.push(' ');
                        write_yaml(child, indent + 1, out);
                    }
                }
            }
        }
        Value::Array(items) if items.is_empty() => out.push_str("[]\n"),
        Value::Array(items) => {
            for item in items {
                out.push_str(&pad);
                out.push_str("- ");
                match item {
                    Value::Object(inner) if !inner.is_empty() => {
                        // First key rides the dash; the rest align under it.
                        let mut nested = String::new();
                        write_yaml(item, indent + 1, &mut nested);
                        out.push_str(nested.trim_start_matches(' '));
                    }
                    _ => write_yaml(item, indent + 1, out),
                }
            }
        }
        Value::String(text) => {
            out.push_str(&json_string(text));
            out.push('\n');
        }
        Value::Number(number) => {
            out.push_str(&number.to_string());
            out.push('\n');
        }
        Value::Bool(flag) => {
            out.push_str(if *flag { "true" } else { "false" });
            out.push('\n');
        }
        // The v1 model omits absent members rather than spelling them `null`,
        // so this arm is unreachable for a valid document; emitting the quoted
        // empty string keeps the subset closed even if that ever changes.
        Value::Null => out.push_str("\"\"\n"),
    }
}

fn yaml_scalar_key(key: &str) -> String {
    json_string(key)
}

/// Emit normalized TOML: scalars first, then one table per object member, then
/// one array-of-tables per array-of-object member. Nested objects inside those
/// use inline tables, so no header can ever appear after a value in the table it
/// belongs to.
fn write_toml(value: &Value) -> ApiResult<String> {
    let Value::Object(root) = value else {
        return Err(ApiErr::from(anyhow::anyhow!(
            "dependency graph document is not an object"
        )));
    };
    let mut out = String::new();
    for (key, child) in root {
        if is_toml_table(child) || is_toml_array_of_tables(child) {
            continue;
        }
        out.push_str(&format!("{} = {}\n", json_string(key), toml_inline(child)));
    }
    for (key, child) in root {
        if !is_toml_table(child) {
            continue;
        }
        out.push_str(&format!("\n[{}]\n", json_string(key)));
        let Value::Object(table) = child else {
            continue;
        };
        for (inner_key, inner) in table {
            out.push_str(&format!(
                "{} = {}\n",
                json_string(inner_key),
                toml_inline(inner)
            ));
        }
    }
    for (key, child) in root {
        if !is_toml_array_of_tables(child) {
            continue;
        }
        let Value::Array(items) = child else { continue };
        for item in items {
            out.push_str(&format!("\n[[{}]]\n", json_string(key)));
            let Value::Object(table) = item else { continue };
            for (inner_key, inner) in table {
                out.push_str(&format!(
                    "{} = {}\n",
                    json_string(inner_key),
                    toml_inline(inner)
                ));
            }
        }
    }
    Ok(out)
}

fn is_toml_table(value: &Value) -> bool {
    matches!(value, Value::Object(map) if !map.is_empty())
}

fn is_toml_array_of_tables(value: &Value) -> bool {
    matches!(value, Value::Array(items) if !items.is_empty() && items.iter().all(|item| matches!(item, Value::Object(_))))
}

fn toml_inline(value: &Value) -> String {
    match value {
        Value::String(text) => json_string(text),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => "\"\"".to_string(),
        Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(toml_inline).collect();
            format!("[{}]", rendered.join(", "))
        }
        Value::Object(map) => {
            let rendered: Vec<String> = map
                .iter()
                .map(|(key, child)| format!("{} = {}", json_string(key), toml_inline(child)))
                .collect();
            format!("{{ {} }}", rendered.join(", "))
        }
    }
}

/// JSON string literal — valid as-is in the YAML double-quoted style and as a
/// TOML basic string.
fn json_string(text: &str) -> String {
    Value::String(text.to_string()).to_string()
}

// ---------------------------------------------------------------------------
// Convenience renderings. Not authoritative, not digest inputs, and explicitly
// excluded from the round-trip guarantee — they are for humans and graphviz.
// ---------------------------------------------------------------------------

fn render_dot(document: &DependencyGraphDocument) -> ApiResult<String> {
    let mut out = String::from(
        "// Non-authoritative rendering of a zpkg/dependency-graph/v1 document.\n\
         // Use the JSON, YAML, or TOML representation for interchange.\n\
         digraph zpkg {\n  rankdir=LR;\n",
    );
    match &document.graph {
        DependencyGraphData::Declared {
            package,
            dependencies,
        } => {
            let root = package.to_string();
            let root_id = graph_node_id(&root);
            push_graph_text(
                &mut out,
                &format!("  {root_id} [label={}, shape=box];\n", json_string(&root)),
            )?;
            for dependency in dependencies {
                let target = format!(
                    "{}::{}/{} {}",
                    dependency.registry_id, dependency.org, dependency.name, dependency.requirement
                );
                let target_id = graph_node_id(&target);
                push_graph_text(
                    &mut out,
                    &format!("  {target_id} [label={}];\n", json_string(&target)),
                )?;
                push_graph_text(&mut out, &format!("  {root_id} -> {target_id};\n"))?;
            }
        }
        DependencyGraphData::Resolved { nodes, edges, .. } => {
            for node in nodes {
                let identity = node.id.to_string();
                push_graph_text(
                    &mut out,
                    &format!(
                        "  {} [label={}, shape=box];\n",
                        graph_node_id(&identity),
                        json_string(&identity)
                    ),
                )?;
            }
            for edge in edges {
                push_graph_text(
                    &mut out,
                    &format!(
                        "  {} -> {};\n",
                        graph_node_id(&edge.from.to_string()),
                        graph_node_id(&edge.to.to_string())
                    ),
                )?;
            }
        }
    }
    push_graph_text(&mut out, "}\n")?;
    Ok(out)
}

fn render_mermaid(document: &DependencyGraphDocument) -> ApiResult<String> {
    let mut out = String::from(
        "%% Non-authoritative rendering of a zpkg/dependency-graph/v1 document.\n\
         %% Use the JSON, YAML, or TOML representation for interchange.\n\
         graph LR\n",
    );
    let label = |text: &str| {
        format!(
            "  {}[\"{}\"]\n",
            graph_node_id(text),
            mermaid_safe_label(text)
        )
    };
    match &document.graph {
        DependencyGraphData::Declared {
            package,
            dependencies,
        } => {
            let root = package.to_string();
            push_graph_text(&mut out, &label(&root))?;
            for dependency in dependencies {
                let target = format!(
                    "{}::{}/{} {}",
                    dependency.registry_id, dependency.org, dependency.name, dependency.requirement
                );
                push_graph_text(&mut out, &label(&target))?;
                push_graph_text(
                    &mut out,
                    &format!(
                        "  {} --> {}\n",
                        graph_node_id(&root),
                        graph_node_id(&target)
                    ),
                )?;
            }
        }
        DependencyGraphData::Resolved { nodes, edges, .. } => {
            for node in nodes {
                push_graph_text(&mut out, &label(&node.id.to_string()))?;
            }
            for edge in edges {
                push_graph_text(
                    &mut out,
                    &format!(
                        "  {} --> {}\n",
                        graph_node_id(&edge.from.to_string()),
                        graph_node_id(&edge.to.to_string())
                    ),
                )?;
            }
        }
    }
    Ok(out)
}

/// Stable, collision-resistant identifier accepted by DOT and Mermaid. Using
/// an identifier rather than the full coordinate on every edge also prevents a
/// long root coordinate from being repeated hundreds of thousands of times.
fn graph_node_id(text: &str) -> String {
    format!("n{}", hex::encode(&Sha256::digest(text.as_bytes())[..8]))
}

fn push_graph_text(output: &mut String, value: &str) -> ApiResult<()> {
    let length = output
        .len()
        .checked_add(value.len())
        .ok_or_else(representation_too_large)?;
    ensure_encoded_size(length)?;
    output.push_str(value);
    Ok(())
}

/// Keep untrusted package metadata inside one Mermaid label. Mermaid's quoted
/// label grammar does not use JSON string escaping consistently across
/// renderers, so a `\"` or escaped newline is not a sufficient boundary. Keep
/// common coordinate characters readable and spell every other scalar as a
/// safe ASCII token that cannot close the label or introduce a directive.
fn mermaid_safe_label(text: &str) -> String {
    let mut label = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_ascii_alphanumeric()
            || matches!(
                character,
                ' ' | '.' | '_' | ':' | '/' | '@' | '+' | '-' | '^' | '=' | ','
            )
        {
            label.push(character);
        } else {
            label.push_str(&format!("_u{:X}_", character as u32));
        }
    }
    label
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn accept(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_str(value).unwrap());
        headers
    }

    fn sample_manifest() -> zed_interfaces::Manifest {
        zed_interfaces::Manifest::parse(
            r#"
[package]
org = "acme"
name = "app"
version = "1.0.0"

[package.repository]
url = "https://github.com/acme/app"

[dependencies]
"acme/corelib" = "^2"

[build-dependencies]
"acme/codegen" = "^0.3"
"#,
        )
        .expect("fixture manifest parses")
    }

    fn sample_document() -> DependencyGraphDocument {
        declared_document("registry:zpkg-primary", "1.0.0", &sample_manifest())
            .expect("fixture document builds")
    }

    #[test]
    fn declared_view_keeps_requirements_unresolved_and_kinds_distinct() {
        let document = sample_document();
        document.verify_digest().expect("finalized graph verifies");
        let DependencyGraphData::Declared {
            package,
            dependencies,
        } = &document.graph
        else {
            panic!("declared view");
        };
        assert_eq!(package.org, "acme");
        assert_eq!(package.version, "1.0.0");
        assert_eq!(dependencies.len(), 2);
        let codegen = dependencies
            .iter()
            .find(|dependency| dependency.name == "codegen")
            .expect("build dependency present");
        assert_eq!(codegen.kind, DependencyKind::Build);
        assert_eq!(codegen.requirement, "^0.3");
        let corelib = dependencies
            .iter()
            .find(|dependency| dependency.name == "corelib")
            .expect("runtime dependency present");
        assert_eq!(corelib.kind, DependencyKind::Runtime);
        // A requirement, not an invented exact version.
        assert_eq!(corelib.requirement, "^2");
    }

    #[test]
    fn declared_graph_refuses_version_relabeling_and_invalid_semver() {
        let manifest = sample_manifest();
        let relabeled = declared_document("registry:registry.zpkg.net", "2.0.0", &manifest)
            .expect_err("a URL version cannot relabel another stored manifest");
        assert_eq!(relabeled.code, "internal");

        let mut invalid = sample_manifest();
        invalid.package.version = "latest".to_string();
        let invalid = declared_document("registry:registry.zpkg.net", "latest", &invalid)
            .expect_err("semver packages require an exact semantic version");
        assert_eq!(invalid.code, "internal");
    }

    #[test]
    fn internal_private_and_unknown_visibility_fail_closed() {
        assert!(!requires_graph_authorization("public").unwrap());
        assert!(requires_graph_authorization("internal").unwrap());
        assert!(requires_graph_authorization("private").unwrap());
        assert_eq!(
            requires_graph_authorization("future-policy")
                .unwrap_err()
                .code,
            "not_found"
        );
    }

    #[test]
    fn declared_dependency_count_is_checked_before_allocation() {
        // A declared graph has one package node in addition to its dependency
        // nodes, so the node limit is reached before the larger edge limit.
        let limit = DEPENDENCY_GRAPH_DEFAULT_MAX_NODES as usize - 1;
        assert_eq!(
            checked_declared_dependency_count(limit.saturating_sub(1), 1).unwrap(),
            limit
        );
        assert_eq!(
            checked_declared_dependency_count(limit, 1)
                .unwrap_err()
                .code,
            "graph_limit_exceeded"
        );
        assert!(
            ensure_graph_counts(1, DEPENDENCY_GRAPH_DEFAULT_MAX_EDGES as usize).is_ok(),
            "the independent edge limit is inclusive"
        );
        assert_eq!(
            ensure_graph_counts(1, DEPENDENCY_GRAPH_DEFAULT_MAX_EDGES as usize + 1)
                .unwrap_err()
                .code,
            "graph_limit_exceeded"
        );
        assert_eq!(
            checked_declared_dependency_count(usize::MAX, 1)
                .unwrap_err()
                .code,
            "graph_limit_exceeded"
        );
    }

    #[test]
    fn encoded_size_limit_is_inclusive_and_fails_closed() {
        assert!(ensure_encoded_size(DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES as usize).is_ok());
        assert_eq!(
            ensure_encoded_size(DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES as usize + 1)
                .unwrap_err()
                .code,
            "graph_representation_too_large"
        );
    }

    /// The three authoritative representations must decode to one typed
    /// document with one semantic digest. Parsed here with independent
    /// third-party parsers, so this proves interoperability rather than that
    /// the emitters agree with themselves.
    #[test]
    fn authoritative_representations_round_trip_to_one_document() {
        let document = sample_document();
        let json = encode(&document, DependencyGraphFormat::Json).unwrap();
        let yaml = encode(&document, DependencyGraphFormat::Yaml).unwrap();
        let toml_bytes = encode(&document, DependencyGraphFormat::Toml).unwrap();

        let from_json = DependencyGraphDocument::parse_verified_canonical(&json)
            .expect("served JSON is canonical and verifies byte-exactly");
        let from_yaml: DependencyGraphDocument =
            serde_yaml::from_slice(&yaml).expect("served YAML parses");
        let from_toml: DependencyGraphDocument =
            toml::from_str(std::str::from_utf8(&toml_bytes).unwrap()).expect("served TOML parses");

        assert_eq!(from_json, document);
        assert_eq!(from_yaml, document);
        assert_eq!(from_toml, document);
        from_yaml.verify_digest().unwrap();
        from_toml.verify_digest().unwrap();
        assert_eq!(from_yaml.graph_digest, from_json.graph_digest);
        assert_eq!(from_toml.graph_digest, from_json.graph_digest);

        // Same semantic identity, different bytes: reusing one ETag across
        // representations would be a cache-poisoning bug.
        assert_ne!(json, yaml);
        assert_ne!(json, toml_bytes);
    }

    #[test]
    fn every_golden_graph_round_trips_through_authoritative_text_formats() {
        for (name, document) in zed_interfaces::golden_fixture_documents() {
            let json = encode(&document, DependencyGraphFormat::Json).unwrap();
            let yaml = encode(&document, DependencyGraphFormat::Yaml).unwrap();
            let toml = encode(&document, DependencyGraphFormat::Toml).unwrap();

            let from_json = DependencyGraphDocument::parse_verified_canonical(&json)
                .unwrap_or_else(|error| panic!("canonical JSON failed for {name}: {error}"));
            let from_yaml: DependencyGraphDocument = serde_yaml::from_slice(&yaml)
                .unwrap_or_else(|error| panic!("YAML failed for {name}: {error}"));
            let from_toml: DependencyGraphDocument =
                toml::from_str(std::str::from_utf8(&toml).unwrap())
                    .unwrap_or_else(|error| panic!("TOML failed for {name}: {error}"));

            assert_eq!(from_json, document, "JSON mismatch for {name}");
            assert_eq!(from_yaml, document, "YAML mismatch for {name}");
            assert_eq!(from_toml, document, "TOML mismatch for {name}");
            from_yaml.verify_digest().unwrap();
            from_toml.verify_digest().unwrap();
        }
    }

    /// The safe subset admits no YAML feature that can alias, tag, or merge.
    #[test]
    fn yaml_stays_inside_the_safe_subset() {
        let yaml =
            String::from_utf8(encode(&sample_document(), DependencyGraphFormat::Yaml).unwrap())
                .unwrap();
        for forbidden in ['&', '*', '!'] {
            assert!(
                !yaml.contains(forbidden),
                "safe-subset YAML must not contain {forbidden}: {yaml}"
            );
        }
        assert!(!yaml.contains("<<"), "no merge keys: {yaml}");
    }

    #[test]
    fn accept_and_format_conflict_is_not_silently_resolved() {
        let json_accept = accept(DependencyGraphFormat::Json.media_type());
        assert_eq!(
            resolve_format(&json_accept, Some("toml")).unwrap_err().code,
            "format_conflict"
        );
        // Agreement is fine, as is either one alone.
        assert_eq!(
            resolve_format(&json_accept, Some("json")).unwrap(),
            DependencyGraphFormat::Json
        );
        assert_eq!(
            resolve_format(
                &accept("application/vnd.zpkg.dependency-graph.v1+toml"),
                None
            )
            .unwrap(),
            DependencyGraphFormat::Toml
        );
        assert_eq!(
            resolve_format(&HeaderMap::new(), Some("yaml")).unwrap(),
            DependencyGraphFormat::Yaml
        );
        // No preference at all defaults to canonical JSON.
        assert_eq!(
            resolve_format(&HeaderMap::new(), None).unwrap(),
            DependencyGraphFormat::Json
        );
        assert_eq!(
            resolve_format(&accept("*/*"), None).unwrap(),
            DependencyGraphFormat::Json
        );
        assert_eq!(
            resolve_format(&HeaderMap::new(), Some("YML")).unwrap(),
            DependencyGraphFormat::Yaml
        );
        // Text renderings are still negotiable despite their charset parameter.
        assert_eq!(
            resolve_format(&accept("text/vnd.graphviz"), None).unwrap(),
            DependencyGraphFormat::Dot
        );
        // An Accept naming only representations we cannot produce is a 406,
        // not a surprise JSON body.
        let err = resolve_format(&accept("application/xml"), None).unwrap_err();
        assert_eq!(err.status, StatusCode::NOT_ACCEPTABLE);
        let err = resolve_format(&HeaderMap::new(), Some("xml")).unwrap_err();
        assert_eq!(err.status, StatusCode::NOT_ACCEPTABLE);
    }

    #[test]
    fn accept_honors_quality_specificity_and_all_field_lines() {
        let json = DependencyGraphFormat::Json.media_type();
        let yaml = DependencyGraphFormat::Yaml.media_type();
        let mut headers = HeaderMap::new();
        headers.append(
            header::ACCEPT,
            HeaderValue::from_str(&format!("{json};q=0")).unwrap(),
        );
        headers.append(
            header::ACCEPT,
            HeaderValue::from_str(&format!("{yaml};q=0.7, */*;q=0.5")).unwrap(),
        );
        assert_eq!(
            resolve_format(&headers, None).unwrap(),
            DependencyGraphFormat::Yaml
        );
        assert_eq!(
            resolve_format(&headers, Some("json")).unwrap_err().code,
            "format_conflict"
        );
        // A specifically excluded text representation remains excluded even
        // when a generic text wildcard is positive.
        let mut text = HeaderMap::new();
        text.insert(
            header::ACCEPT,
            "text/*;q=1, text/vnd.graphviz;charset=utf-8;q=0"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            resolve_format(&text, None).unwrap(),
            DependencyGraphFormat::Mermaid
        );
        assert!(resolve_format(&text, Some("dot")).is_err());
    }

    /// Hostile identifiers cannot escape the filename or inject a header.
    #[test]
    fn download_filenames_are_built_only_from_safe_characters() {
        let stem = filename_stem("../../etc", "a\"; drop\r\n", "1.0.0\u{0000}");
        assert_eq!(stem, ".._.._etc_a___drop___1.0.0_");
        assert!(!stem.contains('/'));
        assert!(!stem.contains('"'));
        assert!(!stem.contains('\r'));
        assert!(!stem.contains('\n'));
        // Matches the grammar the OpenAPI contract advertises.
        assert!(
            stem.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+' | '_'))
        );
    }

    #[test]
    fn strong_validators_match_only_the_same_representation() {
        let document = sample_document();
        let json = respond(
            &HeaderMap::new(),
            DependencyGraphFormat::Json,
            &document,
            "acme_app_1.0.0",
            DeclaredGraphAccess::Public,
        )
        .unwrap();
        let json_etag = json.headers().get(header::ETAG).unwrap().clone();
        let digest = json
            .headers()
            .get(DEPENDENCY_GRAPH_DIGEST_HEADER)
            .unwrap()
            .clone();
        assert_eq!(
            json.headers()
                .get(DEPENDENCY_GRAPH_AUTHORITATIVE_HEADER)
                .unwrap(),
            "true"
        );
        assert_eq!(
            json.headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            encode(&document, DependencyGraphFormat::Json)
                .unwrap()
                .len()
        );

        let yaml = respond(
            &HeaderMap::new(),
            DependencyGraphFormat::Yaml,
            &document,
            "acme_app_1.0.0",
            DeclaredGraphAccess::Public,
        )
        .unwrap();
        // Semantic identity is shared; byte identity is not.
        assert_eq!(
            yaml.headers().get(DEPENDENCY_GRAPH_DIGEST_HEADER),
            Some(&digest)
        );
        assert_ne!(yaml.headers().get(header::ETAG), Some(&json_etag));
        assert_ne!(digest.to_str().unwrap(), json_etag.to_str().unwrap());

        // The JSON validator produces 304 for JSON …
        let mut conditional = HeaderMap::new();
        conditional.insert(header::IF_NONE_MATCH, json_etag.clone());
        let not_modified = respond(
            &conditional,
            DependencyGraphFormat::Json,
            &document,
            "acme_app_1.0.0",
            DeclaredGraphAccess::Public,
        )
        .unwrap();
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(not_modified.headers().get(header::ETAG), Some(&json_etag));
        assert!(not_modified.headers().contains_key(header::CONTENT_LENGTH));
        assert_eq!(
            not_modified
                .headers()
                .get(DEPENDENCY_GRAPH_AUTHORITATIVE_HEADER)
                .unwrap(),
            "true"
        );

        // … and never for YAML.
        let yaml_conditional = respond(
            &conditional,
            DependencyGraphFormat::Yaml,
            &document,
            "acme_app_1.0.0",
            DeclaredGraphAccess::Public,
        )
        .unwrap();
        assert_eq!(yaml_conditional.status(), StatusCode::OK);

        // RFC 9110 requires weak comparison for If-None-Match on GET/HEAD,
        // even though the response's representation validator is strong.
        let mut weak = HeaderMap::new();
        weak.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_str(&format!("W/{}", json_etag.to_str().unwrap())).unwrap(),
        );
        let weak_response = respond(
            &weak,
            DependencyGraphFormat::Json,
            &document,
            "acme_app_1.0.0",
            DeclaredGraphAccess::Public,
        )
        .unwrap();
        assert_eq!(weak_response.status(), StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn private_graph_responses_are_never_cacheable() {
        let response = respond(
            &HeaderMap::new(),
            DependencyGraphFormat::Json,
            &sample_document(),
            "acme_app_1.0.0",
            DeclaredGraphAccess::Private,
        )
        .unwrap();
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            PRIVATE_NO_STORE
        );
        assert_eq!(
            response.headers().get(header::VARY).unwrap(),
            "Accept, Authorization"
        );
    }

    #[test]
    fn registry_identity_is_the_stable_configured_coordinate() {
        let document = declared_document("registry:zpkg-primary", "1.0.0", &sample_manifest())
            .expect("fixture document builds");
        let DependencyGraphData::Declared {
            package,
            dependencies,
        } = document.graph
        else {
            panic!("declared view");
        };
        assert_eq!(package.registry_id, "registry:zpkg-primary");
        assert!(
            dependencies
                .iter()
                .all(|dependency| dependency.registry_id == "registry:zpkg-primary")
        );
    }

    // -----------------------------------------------------------------------
    // End-to-end through the real router, against a real stored artifact.
    // -----------------------------------------------------------------------

    /// A published artifact carrying the fixture manifest, so the endpoint
    /// reads its declaration from package bytes exactly as in production.
    fn artifact_with_manifest() -> Vec<u8> {
        use std::io::Write;
        let manifest = r#"
[package]
org = "acme"
name = "http-kit"
version = "1.0.0"

[package.repository]
url = "https://github.com/acme/http-kit"

[dependencies]
"acme/corelib" = "^2"
"#;
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(manifest.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    format!(
                        "{}/{}",
                        zed_interfaces::paths::ARCHIVE_ROOT,
                        zed_interfaces::paths::MANIFEST_FILE
                    ),
                    manifest.as_bytes(),
                )
                .unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    async fn seeded_app() -> axum::Router {
        use chrono::Utc;
        use sea_orm::{ActiveModelTrait, ActiveValue, ConnectionTrait, Database, Schema};
        use uuid::Uuid;

        use crate::config::{StorageConfig, TagPolicy};
        use crate::entities::{org, package, token, version};
        use crate::storage::ArtifactStore;
        use crate::verify::TagVerifier;

        let db = Database::connect("sqlite::memory:").await.unwrap();
        let backend = db.get_database_backend();
        let schema = Schema::new(backend);
        for stmt in [
            schema.create_table_from_entity(org::Entity),
            schema.create_table_from_entity(token::Entity),
            schema.create_table_from_entity(package::Entity),
            schema.create_table_from_entity(version::Entity),
        ] {
            db.execute(backend.build(&stmt)).await.unwrap();
        }

        let org_id = Uuid::new_v4();
        let pkg_id = Uuid::new_v4();
        org::ActiveModel {
            id: ActiveValue::Set(org_id),
            slug: ActiveValue::Set("acme".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            created_by_token: ActiveValue::Set(None),
        }
        .insert(&db)
        .await
        .unwrap();
        package::ActiveModel {
            id: ActiveValue::Set(pkg_id),
            org_id: ActiveValue::Set(org_id),
            name: ActiveValue::Set("http-kit".to_string()),
            description: ActiveValue::Set(None),
            vcs: ActiveValue::Set("git".to_string()),
            repo_url: ActiveValue::Set("https://github.com/acme/http-kit".to_string()),
            version_scheme: ActiveValue::Set("semver".to_string()),
            tags: ActiveValue::Set(serde_json::json!([])),
            created_at: ActiveValue::Set(Utc::now()),
        }
        .insert(&db)
        .await
        .unwrap();
        version::ActiveModel {
            id: ActiveValue::Set(Uuid::new_v4()),
            package_id: ActiveValue::Set(pkg_id),
            version: ActiveValue::Set("1.0.0".to_string()),
            sha256: ActiveValue::Set("a".repeat(64)),
            size: ActiveValue::Set(1),
            format: ActiveValue::Set("tar.gz".to_string()),
            vcs_tag: ActiveValue::Set("v1.0.0".to_string()),
            vcs_commit: ActiveValue::Set(None),
            artifact_key: ActiveValue::Set("artifacts/graph.tar.gz".to_string()),
            yanked: ActiveValue::Set(false),
            published_at: ActiveValue::Set(Utc::now()),
        }
        .insert(&db)
        .await
        .unwrap();

        let dir = std::env::temp_dir().join(format!("zed-api-graph-test-{}", Uuid::new_v4()));
        let store = ArtifactStore::from_config(&StorageConfig::Local {
            dir: dir.to_string_lossy().to_string(),
        })
        .await
        .unwrap();
        store
            .put(
                "artifacts/graph.tar.gz",
                artifact_with_manifest().into(),
                "application/gzip",
            )
            .await
            .unwrap();

        super::super::router(
            Arc::new(AppState {
                db,
                registry_read: None,
                registry_write: None,
                store,
                verifier: TagVerifier::new(TagPolicy::Off),
                public_base_url: "https://registry.zpkg.net".to_string(),
                registry_id: "registry:zpkg-primary".to_string(),
                max_orgs_per_token: 5,
                fiducia: None,
                rate_limiter: None,
                shared_auth: None,
                shared_auth_audience: "zpkg-api".to_owned(),
                shared_auth_application_id: "zpkg-web".to_owned(),
                shared_auth_public_url: None,
            }),
            8 * 1024 * 1024,
        )
    }

    async fn request(
        app: &axum::Router,
        method: &str,
        uri: &str,
        request_headers: &[(header::HeaderName, &str)],
    ) -> Response {
        use tower::util::ServiceExt;
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        for (name, value) in request_headers {
            builder = builder.header(name, *value);
        }
        app.clone()
            .oneshot(builder.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap()
    }

    const DECLARED_URI: &str =
        "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph?view=declared";

    /// The served declaration comes from the published artifact and verifies
    /// byte-exactly as canonical JSON.
    #[tokio::test]
    async fn declared_graph_is_served_from_the_published_artifact() {
        let app = seeded_app().await;
        let response = request(&app, "GET", DECLARED_URI, &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            DependencyGraphFormat::Json.media_type()
        );
        assert_eq!(
            response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"acme_http-kit_1.0.0.dependency-graph.json\""
        );
        assert_eq!(response.headers().get(header::VARY).unwrap(), "Accept");
        let digest = response
            .headers()
            .get(DEPENDENCY_GRAPH_DIGEST_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let document = DependencyGraphDocument::parse_verified_canonical(&body)
            .expect("served bytes are canonical and verify");
        assert_eq!(document.graph_digest.as_deref(), Some(digest.as_str()));
        let DependencyGraphData::Declared {
            package,
            dependencies,
        } = &document.graph
        else {
            panic!("declared view");
        };
        assert_eq!(package.registry_id, "registry:zpkg-primary");
        assert_eq!(package.name, "http-kit");
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].requirement, "^2");
    }

    /// Every registered representation exposes byte-exact length and
    /// authority metadata consistently across GET, HEAD, and conditional GET.
    #[tokio::test]
    async fn every_format_has_exact_get_head_and_not_modified_metadata() {
        let app = seeded_app().await;
        let cases = [
            (
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph?view=declared&format=json",
                true,
            ),
            (
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph?view=declared&format=yaml",
                true,
            ),
            (
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph?view=declared&format=toml",
                true,
            ),
            (
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph?view=declared&format=dot",
                false,
            ),
            (
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph?view=declared&format=mermaid",
                false,
            ),
            (
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph/export/json5",
                true,
            ),
            (
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph/export/xml",
                true,
            ),
            (
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph/export/csv",
                false,
            ),
            (
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph/export/msgpack",
                true,
            ),
            (
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph/export/protobuf",
                true,
            ),
        ];
        let metadata = [
            "etag",
            "cache-control",
            "vary",
            "content-disposition",
            "content-length",
            DEPENDENCY_GRAPH_DIGEST_HEADER,
            DEPENDENCY_GRAPH_AUTHORITATIVE_HEADER,
        ];

        for (uri, authoritative) in cases {
            let get = request(&app, "GET", uri, &[]).await;
            assert_eq!(get.status(), StatusCode::OK, "GET {uri}");
            let get_headers = get.headers().clone();
            assert_eq!(
                get_headers
                    .get(DEPENDENCY_GRAPH_AUTHORITATIVE_HEADER)
                    .unwrap(),
                if authoritative { "true" } else { "false" },
                "authority for {uri}"
            );
            let body = axum::body::to_bytes(get.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(
                get_headers
                    .get(header::CONTENT_LENGTH)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap(),
                body.len(),
                "GET length for {uri}"
            );

            let head = request(&app, "HEAD", uri, &[]).await;
            assert_eq!(head.status(), StatusCode::OK, "HEAD {uri}");
            let head_headers = head.headers().clone();
            assert!(
                axum::body::to_bytes(head.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .is_empty(),
                "HEAD body for {uri}"
            );
            for name in metadata {
                assert_eq!(
                    head_headers.get(name),
                    get_headers.get(name),
                    "HEAD {name} for {uri}"
                );
            }

            let etag = get_headers.get(header::ETAG).unwrap().to_str().unwrap();
            let not_modified = request(&app, "GET", uri, &[(header::IF_NONE_MATCH, etag)]).await;
            assert_eq!(
                not_modified.status(),
                StatusCode::NOT_MODIFIED,
                "conditional GET {uri}"
            );
            let not_modified_headers = not_modified.headers().clone();
            assert!(
                axum::body::to_bytes(not_modified.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .is_empty(),
                "304 body for {uri}"
            );
            for name in metadata {
                assert_eq!(
                    not_modified_headers.get(name),
                    get_headers.get(name),
                    "304 {name} for {uri}"
                );
            }
        }
    }

    /// `HEAD` answers with the same metadata and no body; a matching
    /// `If-None-Match` yields 304 for that representation only.
    #[tokio::test]
    async fn head_and_conditional_requests_behave_per_representation() {
        let app = seeded_app().await;
        let head = request(&app, "HEAD", DECLARED_URI, &[]).await;
        assert_eq!(head.status(), StatusCode::OK);
        let etag = head
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(head.headers().contains_key(DEPENDENCY_GRAPH_DIGEST_HEADER));
        let head_body = axum::body::to_bytes(head.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(head_body.is_empty(), "HEAD carries no body");

        let conditional = request(
            &app,
            "GET",
            DECLARED_URI,
            &[(header::IF_NONE_MATCH, etag.as_str())],
        )
        .await;
        assert_eq!(conditional.status(), StatusCode::NOT_MODIFIED);

        // The same validator against the YAML representation must NOT match.
        let other = request(
            &app,
            "GET",
            &format!("{DECLARED_URI}&format=yaml"),
            &[(header::IF_NONE_MATCH, etag.as_str())],
        )
        .await;
        assert_eq!(other.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn extended_exports_preserve_head_negotiation_and_private_miss_semantics() {
        const EXPORT_URI: &str =
            "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph/export/xml";
        let app = seeded_app().await;
        let head = request(
            &app,
            "HEAD",
            EXPORT_URI,
            &[(
                header::ACCEPT,
                "application/vnd.zpkg.dependency-graph.v1+xml",
            )],
        )
        .await;
        assert_eq!(head.status(), StatusCode::OK);
        assert!(head.headers().contains_key(header::CONTENT_LENGTH));
        let etag = head
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            axum::body::to_bytes(head.into_body(), usize::MAX)
                .await
                .unwrap()
                .is_empty(),
            "HEAD carries no export body"
        );

        let weak_etag = format!("W/{etag}");
        let conditional = request(
            &app,
            "GET",
            EXPORT_URI,
            &[(header::IF_NONE_MATCH, weak_etag.as_str())],
        )
        .await;
        assert_eq!(conditional.status(), StatusCode::NOT_MODIFIED);

        let unacceptable = request(&app, "GET", EXPORT_URI, &[(header::ACCEPT, "text/csv")]).await;
        assert_eq!(unacceptable.status(), StatusCode::NOT_ACCEPTABLE);
        let unknown_unacceptable = request(
            &app,
            "GET",
            "/v1/packages/nope/http-kit/versions/1.0.0/dependency-graph/export/xml",
            &[(header::ACCEPT, "text/csv")],
        )
        .await;
        assert_eq!(unknown_unacceptable.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            axum::body::to_bytes(unacceptable.into_body(), usize::MAX)
                .await
                .unwrap(),
            axum::body::to_bytes(unknown_unacceptable.into_body(), usize::MAX)
                .await
                .unwrap(),
            "negotiation failures must not reveal package existence"
        );

        let mut bodies = Vec::new();
        for uri in [
            "/v1/packages/nope/http-kit/versions/1.0.0/dependency-graph/export/xml",
            "/v1/packages/acme/nope/versions/1.0.0/dependency-graph/export/xml",
            "/v1/packages/acme/http-kit/versions/9.9.9/dependency-graph/export/xml",
        ] {
            let response = request(&app, "GET", uri, &[]).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "private, no-store"
            );
            bodies.push(
                axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            );
        }
        assert!(bodies.windows(2).all(|pair| pair[0] == pair[1]));
    }

    /// Every miss — unknown org, package, version, or resolution digest —
    /// answers identically, so probing cannot enumerate what exists.
    #[tokio::test]
    async fn misses_are_indistinguishable() {
        let app = seeded_app().await;
        let mut bodies = Vec::new();
        for uri in [
            "/v1/packages/nope/http-kit/versions/1.0.0/dependency-graph?view=declared",
            "/v1/packages/acme/nope/versions/1.0.0/dependency-graph?view=declared",
            "/v1/packages/acme/http-kit/versions/9.9.9/dependency-graph?view=declared",
            "/v1/resolutions/sha256:0000000000000000000000000000000000000000000000000000000000000000/dependency-graph",
            "/v1/resolutions/not-a-digest/dependency-graph",
        ] {
            let response = request(&app, "GET", uri, &[]).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            bodies.push(
                axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            );
        }
        assert!(
            bodies.windows(2).all(|pair| pair[0] == pair[1]),
            "denial bodies must be byte-identical: {bodies:?}"
        );
    }

    /// The package-version route serves declarations only: asking it for a
    /// resolved graph is an explicit error, never a different answer.
    #[tokio::test]
    async fn package_route_refuses_to_invent_a_universal_resolved_graph() {
        let app = seeded_app().await;
        for uri in [
            "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph",
            "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph?view=resolved",
        ] {
            let response = request(&app, "GET", uri, &[]).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["code"], "unsupported_view");
        }
    }

    /// Negotiation over the wire: each representation is served under its own
    /// media type, and a conflict is refused rather than silently resolved.
    #[tokio::test]
    async fn representations_and_conflicts_over_http() {
        let app = seeded_app().await;
        for (format, expected) in [
            ("yaml", DependencyGraphFormat::Yaml),
            ("toml", DependencyGraphFormat::Toml),
            ("dot", DependencyGraphFormat::Dot),
            ("mermaid", DependencyGraphFormat::Mermaid),
        ] {
            let response =
                request(&app, "GET", &format!("{DECLARED_URI}&format={format}"), &[]).await;
            assert_eq!(response.status(), StatusCode::OK, "{format}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                expected.media_type(),
                "{format}"
            );
        }

        let conflict = request(
            &app,
            "GET",
            &format!("{DECLARED_URI}&format=toml"),
            &[(header::ACCEPT, DependencyGraphFormat::Json.media_type())],
        )
        .await;
        assert_eq!(conflict.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[test]
    fn convenience_renderings_declare_they_are_not_authoritative() {
        let document = sample_document();
        for format in [DependencyGraphFormat::Dot, DependencyGraphFormat::Mermaid] {
            let rendered = String::from_utf8(encode(&document, format).unwrap()).unwrap();
            assert!(rendered.contains("Non-authoritative"));
            assert!(!format.is_authoritative());
            let response = respond(
                &HeaderMap::new(),
                format,
                &document,
                "acme_app_1.0.0",
                DeclaredGraphAccess::Public,
            )
            .unwrap();
            assert_eq!(
                response
                    .headers()
                    .get(DEPENDENCY_GRAPH_AUTHORITATIVE_HEADER)
                    .unwrap(),
                "false"
            );
        }
    }

    #[test]
    fn mermaid_labels_cannot_break_out_into_directives() {
        let hostile = "pkg\"]\nclick root callback\r\n<script>";
        let label = mermaid_safe_label(hostile);
        assert!(
            !label
                .chars()
                .any(|character| matches!(character, '"' | ']' | '\n' | '\r' | '<' | '>'))
        );
        assert!(label.contains("_u22_"));
        assert!(label.contains("_uA_"));

        let mut document = sample_document();
        let DependencyGraphData::Declared { dependencies, .. } = &mut document.graph else {
            unreachable!();
        };
        dependencies[0].requirement = hostile.to_string();
        let document = document.finalize().unwrap();
        let mermaid = render_mermaid(&document).unwrap();
        assert!(!mermaid.contains("\nclick "));
        assert!(!mermaid.contains("<script>"));
    }
}
