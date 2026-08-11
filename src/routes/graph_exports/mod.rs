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
use sha2::{Digest, Sha256};
use zed_interfaces::{
    DEPENDENCY_GRAPH_AUTHORITATIVE_HEADER, DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES,
    DEPENDENCY_GRAPH_DIGEST_HEADER, DependencyGraphCompleteness, DependencyGraphDocument,
    DependencyGraphExportFormat, DependencyKind,
};
#[cfg(test)]
use zed_interfaces::{
    DEPENDENCY_GRAPH_SCHEMA_V1, DeclaredDependency, DependencyGraphData, PackageVersionIdentity,
};

use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;

#[cfg(test)]
use super::graph::declared_document;
use super::graph::{DeclaredGraphAccess, load_authorized_declared_document};

type GraphExportFormat = DependencyGraphExportFormat;

/// `GET|HEAD /v1/packages/{org}/{name}/versions/{version}/dependency-graph/export/{format}`
pub async fn get_declared_graph_export(
    State(state): State<Arc<AppState>>,
    Path((org_slug, name, ver, format_name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let format = GraphExportFormat::parse_name(&format_name).ok_or_else(|| ApiErr {
        status: StatusCode::NOT_ACCEPTABLE,
        code: "unsupported_format",
        message: format!("unsupported dependency graph export format `{format_name}`"),
    })?;
    ensure_acceptable(&headers, format)?;
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

fn ensure_acceptable(headers: &HeaderMap, format: GraphExportFormat) -> ApiResult<()> {
    let mut saw_nonempty_value = false;
    let mut selected: Option<(u16, u16)> = None;
    let registered = format.media_type();

    for value in headers.get_all(header::ACCEPT).iter() {
        let Ok(value) = value.to_str() else {
            return Err(ApiErr {
                status: StatusCode::NOT_ACCEPTABLE,
                code: "unsupported_format",
                message: "requested export format is not acceptable".to_string(),
            });
        };
        if value.trim().is_empty() {
            continue;
        }
        saw_nonempty_value = true;
        for entry in value.split(',') {
            let Some((specificity, quality)) = accept_match(entry, registered) else {
                continue;
            };
            if selected.is_none_or(|current| {
                specificity > current.0 || (specificity == current.0 && quality > current.1)
            }) {
                selected = Some((specificity, quality));
            }
        }
    }

    if !saw_nonempty_value || selected.is_some_and(|(_, quality)| quality > 0) {
        return Ok(());
    }
    Err(ApiErr {
        status: StatusCode::NOT_ACCEPTABLE,
        code: "unsupported_format",
        message: "requested export format is not acceptable".to_string(),
    })
}

fn accept_match(entry: &str, registered: &str) -> Option<(u16, u16)> {
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
            quality = parse_quality(value.trim()).unwrap_or(0);
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

fn parse_quality(value: &str) -> Option<u16> {
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

fn respond(
    request_headers: &HeaderMap,
    format: GraphExportFormat,
    document: &DependencyGraphDocument,
    filename_stem: &str,
    access: DeclaredGraphAccess,
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
    response_headers.insert(header::CACHE_CONTROL, header_value(access.cache_control())?);
    response_headers.insert(header::VARY, header_value(access.vary())?);
    response_headers.insert(header::CONTENT_DISPOSITION, header_value(&disposition)?);
    response_headers.insert(
        header::CONTENT_LENGTH,
        header_value(&body.len().to_string())?,
    );
    response_headers.insert(
        header::HeaderName::from_static(DEPENDENCY_GRAPH_DIGEST_HEADER),
        header_value(graph_digest)?,
    );
    response_headers.insert(
        header::HeaderName::from_static(DEPENDENCY_GRAPH_AUTHORITATIVE_HEADER),
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
    document
        .verify_digest()
        .map_err(|error| ApiErr::from(anyhow::anyhow!("graph verification failed: {error}")))?;
    let canonical = document
        .canonical_document_bytes()
        .map_err(|error| ApiErr::from(anyhow::anyhow!("graph canonicalization failed: {error}")))?;
    if canonical.len() as u64 > DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES {
        return Err(representation_too_large());
    }
    match format {
        GraphExportFormat::Json5 => encode_json5(document, &canonical),
        GraphExportFormat::Xml => xml::encode(document),
        GraphExportFormat::Csv => csv::encode(document),
        GraphExportFormat::MessagePack => messagepack::encode(&canonical),
        GraphExportFormat::Protobuf => Ok(protobuf::encode(document)),
    }
}

fn encode_json5(document: &DependencyGraphDocument, canonical: &[u8]) -> ApiResult<Vec<u8>> {
    let digest = document.graph_digest.as_deref().unwrap_or("missing");
    let prefix = format!(
        "// zpkg/dependency-graph/v1 — lossless JSON5 projection\n\
         // graph_digest: {digest}\n\
         // Comments may be removed; the remaining value is canonical JSON.\n"
    );
    let encoded_len = prefix
        .len()
        .checked_add(canonical.len())
        .and_then(|length| length.checked_add(1))
        .ok_or_else(representation_too_large)?;
    if encoded_len as u64 > DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES {
        return Err(representation_too_large());
    }
    let mut output = Vec::with_capacity(encoded_len);
    output.extend_from_slice(prefix.as_bytes());
    output.extend_from_slice(canonical);
    output.push(b'\n');
    Ok(output)
}

pub(super) fn representation_too_large() -> ApiErr {
    ApiErr {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        code: "graph_representation_too_large",
        message: "dependency graph representation exceeds the server limit".to_string(),
    }
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
            GraphExportFormat::parse_name("messagepack"),
            Some(GraphExportFormat::MessagePack)
        );
        assert_eq!(
            GraphExportFormat::parse_name("proto"),
            Some(GraphExportFormat::Protobuf)
        );
        assert!(GraphExportFormat::parse_name("pickle").is_none());
        assert!(!GraphExportFormat::Csv.is_authoritative());
        assert!(GraphExportFormat::Xml.is_authoritative());
    }

    #[test]
    fn json5_is_comments_plus_the_canonical_document() {
        let document = sample_document();
        let canonical = document.canonical_document_bytes().unwrap();
        let bytes = encode_json5(&document, &canonical).unwrap();
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
            DeclaredGraphAccess::Public,
        )
        .unwrap();
        let xml = respond(
            &HeaderMap::new(),
            GraphExportFormat::Xml,
            &document,
            "acme_app_1.0.0",
            DeclaredGraphAccess::Public,
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
        assert_eq!(
            json5
                .headers()
                .get(DEPENDENCY_GRAPH_AUTHORITATIVE_HEADER)
                .unwrap(),
            "true"
        );
        assert_eq!(json5.headers().get(header::VARY).unwrap(), "Accept");
        assert!(
            json5
                .headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap()
                > 0
        );
    }

    #[test]
    fn private_exports_are_no_store_and_vary_on_authorization() {
        let response = respond(
            &HeaderMap::new(),
            GraphExportFormat::Json5,
            &sample_document(),
            "acme_app_1.0.0",
            DeclaredGraphAccess::Private,
        )
        .unwrap();
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
        assert_eq!(
            response.headers().get(header::VARY).unwrap(),
            "Accept, Authorization"
        );
    }

    #[test]
    fn accept_is_checked_with_quality_and_specificity() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            "application/*;q=0.5, application/vnd.zpkg.dependency-graph.v1+xml;q=1"
                .parse()
                .unwrap(),
        );
        ensure_acceptable(&headers, GraphExportFormat::Xml).unwrap();

        headers.insert(
            header::ACCEPT,
            "application/vnd.zpkg.dependency-graph.v1+xml;q=0, */*;q=1"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            ensure_acceptable(&headers, GraphExportFormat::Xml)
                .unwrap_err()
                .status,
            StatusCode::NOT_ACCEPTABLE
        );

        headers.insert(header::ACCEPT, "text/csv".parse().unwrap());
        ensure_acceptable(&headers, GraphExportFormat::Csv).unwrap();
        assert!(ensure_acceptable(&headers, GraphExportFormat::Xml).is_err());

        headers.insert(
            header::ACCEPT,
            "text/csv; charset=iso-8859-1".parse().unwrap(),
        );
        assert!(ensure_acceptable(&headers, GraphExportFormat::Csv).is_err());

        headers.insert(
            header::ACCEPT,
            "text/csv;q=1, text/csv;charset=utf-8;q=0".parse().unwrap(),
        );
        assert!(
            ensure_acceptable(&headers, GraphExportFormat::Csv).is_err(),
            "the more specific media range controls quality"
        );
    }

    #[test]
    fn if_none_match_uses_weak_comparison_and_all_field_lines() {
        let document = sample_document();
        let response = respond(
            &HeaderMap::new(),
            GraphExportFormat::Json5,
            &document,
            "acme_app_1.0.0",
            DeclaredGraphAccess::Public,
        )
        .unwrap();
        let etag = response
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.append(header::IF_NONE_MATCH, "\"unrelated\"".parse().unwrap());
        headers.append(header::IF_NONE_MATCH, format!("W/{etag}").parse().unwrap());
        let not_modified = respond(
            &headers,
            GraphExportFormat::Json5,
            &document,
            "acme_app_1.0.0",
            DeclaredGraphAccess::Public,
        )
        .unwrap();
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(not_modified.headers().get(header::ETAG).unwrap(), etag);
    }

    #[test]
    fn declared_graph_includes_build_dependencies_with_their_kind() {
        let manifest = zed_interfaces::Manifest::parse(
            r#"
[package]
org = "acme"
name = "app"
version = "1.0.0"

[package.repository]
url = "https://github.com/acme/app"

[dependencies]
"acme/runtime" = "^1"

[build-dependencies]
"acme/compiler" = "^2"
"#,
        )
        .unwrap();
        let document = declared_document("registry:registry.zpkg.net", "1.0.0", &manifest).unwrap();
        let DependencyGraphData::Declared { dependencies, .. } = document.graph else {
            panic!("declared graph");
        };
        assert_eq!(dependencies.len(), 2);
        assert!(dependencies.iter().any(|dependency| {
            dependency.name == "runtime" && dependency.kind == DependencyKind::Runtime
        }));
        assert!(dependencies.iter().any(|dependency| {
            dependency.name == "compiler" && dependency.kind == DependencyKind::Build
        }));
    }

    #[test]
    fn export_filenames_cannot_inject_headers_or_paths() {
        let stem = filename_stem("../../etc", "a\"; drop\r\n", "1.0.0\0");
        assert_eq!(stem, ".._.._etc_a___drop___1.0.0_");
        assert!(stem.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+' | '_')
        }));
    }
}
