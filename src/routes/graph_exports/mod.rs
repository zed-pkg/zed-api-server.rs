//! Extended dependency-graph export representations.
//!
//! The canonical graph contract remains `zpkg/dependency-graph/v1`. This
//! module projects that one finalized document into additional interchange
//! formats without re-resolving dependencies or changing semantic identity.
//! JSON5, XML, MessagePack, and Protocol Buffers are lossless projections.
//! CSV is intentionally an analytics-oriented node/edge table and advertises
//! itself as non-authoritative.

mod csv;
mod messagepack;
mod protobuf;
mod xml;

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};
use zed_interfaces::{
    DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES, DEPENDENCY_GRAPH_DIGEST_HEADER,
    DEPENDENCY_GRAPH_SCHEMA_V1, DeclaredDependency, DependencyGraphCompleteness,
    DependencyGraphData, DependencyGraphDocument, DependencyKind, PackageVersionIdentity,
};

use crate::entities::version;
use crate::error::{ApiErr, ApiResult};
use crate::files;
use crate::state::AppState;

use super::{artifact_format, find_org, find_package};

const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const AUTHORITATIVE_HEADER: &str = "x-zpkg-graph-authoritative";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GraphExportFormat {
    Json5,
    Xml,
    Csv,
    MessagePack,
    Protobuf,
}

impl GraphExportFormat {
    fn parse(value: &str) -> Option<Self> {
        Some(match value.to_ascii_lowercase().as_str() {
            "json5" => Self::Json5,
            "xml" => Self::Xml,
            "csv" => Self::Csv,
            "msgpack" | "messagepack" | "mpk" => Self::MessagePack,
            "protobuf" | "proto" | "pb" => Self::Protobuf,
            _ => return None,
        })
    }

    const fn extension(self) -> &'static str {
        match self {
            Self::Json5 => "json5",
            Self::Xml => "xml",
            Self::Csv => "csv",
            Self::MessagePack => "msgpack",
            Self::Protobuf => "pb",
        }
    }

    const fn media_type(self) -> &'static str {
        match self {
            Self::Json5 => "application/vnd.zpkg.dependency-graph.v1+json5",
            Self::Xml => "application/vnd.zpkg.dependency-graph.v1+xml",
            Self::Csv => "text/csv; charset=utf-8",
            Self::MessagePack => "application/vnd.zpkg.dependency-graph.v1+msgpack",
            Self::Protobuf => "application/vnd.zpkg.dependency-graph.v1+protobuf",
        }
    }

    const fn is_authoritative(self) -> bool {
        !matches!(self, Self::Csv)
    }
}

/// `GET|HEAD /v1/packages/{org}/{name}/versions/{version}/dependency-graph/export/{format}`
pub async fn get_declared_graph_export(
    State(state): State<Arc<AppState>>,
    Path((org_slug, name, ver, format_name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let format = GraphExportFormat::parse(&format_name).ok_or_else(|| ApiErr {
        status: StatusCode::NOT_ACCEPTABLE,
        code: "unsupported_format",
        message: format!("unsupported dependency graph export format `{format_name}`"),
    })?;
    let document = load_declared_document(&state, &org_slug, &name, &ver).await?;
    respond(
        &headers,
        format,
        &document,
        &filename_stem(&org_slug, &name, &ver),
    )
}

fn graph_not_found() -> ApiErr {
    ApiErr {
        status: StatusCode::NOT_FOUND,
        code: "not_found",
        message: "dependency graph not found".to_string(),
    }
}

async fn load_declared_document(
    state: &AppState,
    org_slug: &str,
    name: &str,
    ver: &str,
) -> ApiResult<DependencyGraphDocument> {
    let org_row = find_org(state, org_slug)
        .await
        .map_err(|_| graph_not_found())?;
    let package = find_package(state, &org_row, name)
        .await
        .map_err(|_| graph_not_found())?;
    let row = version::Entity::find()
        .filter(version::Column::PackageId.eq(package.id))
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

    declared_document(&registry_id(&state.public_base_url), ver, &manifest)
}

fn registry_id(public_base_url: &str) -> String {
    let host = public_base_url
        .split_once("://")
        .map_or(public_base_url, |(_scheme, rest)| rest)
        .split('/')
        .next()
        .unwrap_or(public_base_url)
        .trim_end_matches('.');
    if host.is_empty() {
        format!("registry:{public_base_url}")
    } else {
        format!("registry:{host}")
    }
}

fn declared_document(
    registry: &str,
    version: &str,
    manifest: &zed_interfaces::Manifest,
) -> ApiResult<DependencyGraphDocument> {
    let mut dependencies = Vec::new();
    let runtime = manifest
        .dependencies
        .iter()
        .map(|entry| (entry, DependencyKind::Runtime));
    let build = manifest
        .build_dependencies
        .iter()
        .map(|entry| (entry, DependencyKind::Build));

    for ((key, requirement), kind) in runtime.chain(build) {
        let (org, name) = key.split_once('/').ok_or_else(|| {
            ApiErr::from(anyhow::anyhow!(
                "stored manifest declares dependency key `{key}` without an org segment"
            ))
        })?;
        dependencies.push(DeclaredDependency {
            registry_id: registry.to_string(),
            org: org.to_string(),
            name: name.to_string(),
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
    .map_err(|error| ApiErr::from(anyhow::anyhow!("dependency graph is invalid: {error}")))
}

fn respond(
    request_headers: &HeaderMap,
    format: GraphExportFormat,
    document: &DependencyGraphDocument,
    filename_stem: &str,
) -> ApiResult<Response> {
    let body = encode(document, format)?;
    if body.len() as u64 > DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES {
        return Err(ApiErr {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "graph_representation_too_large",
            message: "dependency graph representation exceeds the server limit".to_string(),
        });
    }

    let etag = format!("\"{}\"", hex::encode(Sha256::digest(&body)));
    let graph_digest = document
        .graph_digest
        .as_deref()
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
    response_headers.insert(header::CACHE_CONTROL, header_value(IMMUTABLE)?);
    response_headers.insert(header::CONTENT_DISPOSITION, header_value(&disposition)?);
    response_headers.insert(
        header::HeaderName::from_static(DEPENDENCY_GRAPH_DIGEST_HEADER),
        header_value(graph_digest)?,
    );
    response_headers.insert(
        header::HeaderName::from_static(AUTHORITATIVE_HEADER),
        header::HeaderValue::from_static(if format.is_authoritative() {
            "true"
        } else {
            "false"
        }),
    );

    if if_none_match_matches(request_headers, &etag) {
        return Ok((StatusCode::NOT_MODIFIED, response_headers).into_response());
    }

    response_headers.insert(header::CONTENT_TYPE, header_value(format.media_type())?);
    Ok((StatusCode::OK, response_headers, body).into_response())
}

fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    let Some(value) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    value
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate == etag)
}

fn filename_stem(org: &str, name: &str, version: &str) -> String {
    let mut stem = String::with_capacity(org.len() + name.len() + version.len() + 2);
    for (index, part) in [org, name, version].iter().enumerate() {
        if index > 0 {
            stem.push('_');
        }
        for character in part.chars() {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+') {
                stem.push(character);
            } else {
                stem.push('_');
            }
        }
    }
    stem
}

fn encode(document: &DependencyGraphDocument, format: GraphExportFormat) -> ApiResult<Vec<u8>> {
    match format {
        GraphExportFormat::Json5 => encode_json5(document),
        GraphExportFormat::Xml => Ok(xml::encode(document).into_bytes()),
        GraphExportFormat::Csv => csv::encode(document),
        GraphExportFormat::MessagePack => messagepack::encode(document),
        GraphExportFormat::Protobuf => Ok(protobuf::encode(document)),
    }
}

fn encode_json5(document: &DependencyGraphDocument) -> ApiResult<Vec<u8>> {
    let canonical = document
        .canonical_document_bytes()
        .map_err(|error| ApiErr::from(anyhow::anyhow!("graph canonicalization failed: {error}")))?;
    let digest = document.graph_digest.as_deref().unwrap_or("missing");
    let mut output = format!(
        "// zpkg/dependency-graph/v1 — lossless JSON5 projection\n\
         // graph_digest: {digest}\n\
         // Comments may be removed; the remaining value is canonical JSON.\n"
    )
    .into_bytes();
    output.extend_from_slice(&canonical);
    output.push(b'\n');
    Ok(output)
}

const fn dependency_kind_code(kind: DependencyKind) -> u64 {
    match kind {
        DependencyKind::Runtime => 1,
        DependencyKind::Build => 2,
        DependencyKind::Development => 3,
        DependencyKind::Peer => 4,
        DependencyKind::Tooling => 5,
    }
}

const fn dependency_kind_name(kind: DependencyKind) -> &'static str {
    match kind {
        DependencyKind::Runtime => "runtime",
        DependencyKind::Build => "build",
        DependencyKind::Development => "development",
        DependencyKind::Peer => "peer",
        DependencyKind::Tooling => "tooling",
    }
}

const fn completeness_code(completeness: DependencyGraphCompleteness) -> u64 {
    match completeness {
        DependencyGraphCompleteness::Complete => 1,
        DependencyGraphCompleteness::Projected => 2,
    }
}

const fn completeness_name(completeness: DependencyGraphCompleteness) -> &'static str {
    match completeness {
        DependencyGraphCompleteness::Complete => "complete",
        DependencyGraphCompleteness::Projected => "projected",
    }
}

const fn bool_name(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
fn sample_document() -> DependencyGraphDocument {
    DependencyGraphDocument {
        schema: DEPENDENCY_GRAPH_SCHEMA_V1.to_string(),
        graph: DependencyGraphData::Declared {
            package: PackageVersionIdentity {
                registry_id: "registry:registry.zpkg.net".to_string(),
                org: "acme".to_string(),
                name: "app".to_string(),
                version: "1.0.0-beta.1".to_string(),
            },
            dependencies: vec![DeclaredDependency {
                registry_id: "registry:registry.zpkg.net".to_string(),
                org: "acme".to_string(),
                name: "core<&\"".to_string(),
                requirement: "^2, >=2.1\nnext".to_string(),
                kind: DependencyKind::Runtime,
                optional: true,
                default_features: false,
                features: vec!["tls".to_string(), "json".to_string()],
                target: Some("x86_64-unknown-linux-gnu".to_string()),
            }],
        },
        graph_digest: None,
    }
    .finalize()
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_map_to_stable_export_formats() {
        assert_eq!(
            GraphExportFormat::parse("messagepack"),
            Some(GraphExportFormat::MessagePack)
        );
        assert_eq!(
            GraphExportFormat::parse("proto"),
            Some(GraphExportFormat::Protobuf)
        );
        assert!(GraphExportFormat::parse("pickle").is_none());
        assert!(!GraphExportFormat::Csv.is_authoritative());
        assert!(GraphExportFormat::Xml.is_authoritative());
    }

    #[test]
    fn json5_is_comments_plus_the_canonical_document() {
        let document = sample_document();
        let bytes = encode_json5(&document).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("// zpkg/dependency-graph/v1"));
        let json = text
            .lines()
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let decoded: DependencyGraphDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, document);
        decoded.verify_digest().unwrap();
    }

    #[test]
    fn validators_are_per_representation_but_digest_is_shared() {
        let document = sample_document();
        let json5 = respond(
            &HeaderMap::new(),
            GraphExportFormat::Json5,
            &document,
            "acme_app_1.0.0",
        )
        .unwrap();
        let xml = respond(
            &HeaderMap::new(),
            GraphExportFormat::Xml,
            &document,
            "acme_app_1.0.0",
        )
        .unwrap();
        assert_ne!(
            json5.headers().get(header::ETAG),
            xml.headers().get(header::ETAG)
        );
        assert_eq!(
            json5.headers().get(DEPENDENCY_GRAPH_DIGEST_HEADER),
            xml.headers().get(DEPENDENCY_GRAPH_DIGEST_HEADER)
        );
        assert_eq!(json5.headers().get(AUTHORITATIVE_HEADER).unwrap(), "true");
    }
}
