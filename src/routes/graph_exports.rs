//! Extended dependency-graph download representations.
//!
//! The canonical graph contract remains `zpkg/dependency-graph/v1`. This
//! handler loads the same immutable package manifest as the canonical graph
//! endpoint, finalizes one typed document, and projects it into additional
//! formats without resolving dependencies again.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zed_interfaces::{
    DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES, DEPENDENCY_GRAPH_DIGEST_HEADER,
    DEPENDENCY_GRAPH_SCHEMA_V1, DeclaredDependency, DependencyGraphData,
    DependencyGraphDocument, DependencyKind, PackageVersionIdentity,
};

use crate::entities::version;
use crate::error::{ApiErr, ApiResult};
use crate::files;
use crate::state::AppState;

use super::{artifact_format, find_org, find_package};

const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const AUTHORITATIVE_HEADER: &str = "x-zpkg-graph-authoritative";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportFormat {
    Json5,
    Xml,
    Csv,
    MessagePack,
    Protobuf,
}

impl ExportFormat {
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
    Path((org_slug, name, package_version, format_name)): Path<(
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let format = ExportFormat::parse(&format_name).ok_or_else(|| ApiErr {
        status: StatusCode::NOT_ACCEPTABLE,
        code: "unsupported_format",
        message: format!("unsupported dependency graph export format `{format_name}`"),
    })?;
    let document = load_declared_document(&state, &org_slug, &name, &package_version).await?;
    respond(
        &headers,
        format,
        &document,
        &filename_stem(&org_slug, &name, &package_version),
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
    package_version: &str,
) -> ApiResult<DependencyGraphDocument> {
    let org_row = find_org(state, org_slug)
        .await
        .map_err(|_| graph_not_found())?;
    let package = find_package(state, &org_row, name)
        .await
        .map_err(|_| graph_not_found())?;
    let row = version::Entity::find()
        .filter(version::Column::PackageId.eq(package.id))
        .filter(version::Column::Version.eq(package_version))
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
    let manifest = zed_interfaces::Manifest::parse(&manifest_text)
        .map_err(|error| ApiErr::from(anyhow::anyhow!("stored manifest does not parse: {error}")))?;

    declared_document(
        &registry_id(&state.public_base_url),
        package_version,
        &manifest,
    )
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
    package_version: &str,
    manifest: &zed_interfaces::Manifest,
) -> ApiResult<DependencyGraphDocument> {
    let runtime = manifest
        .dependencies
        .iter()
        .map(|entry| (entry, DependencyKind::Runtime));
    let build = manifest
        .build_dependencies
        .iter()
        .map(|entry| (entry, DependencyKind::Build));
    let mut dependencies = Vec::new();

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
                version: package_version.to_string(),
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
    format: ExportFormat,
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

fn filename_stem(org: &str, name: &str, package_version: &str) -> String {
    let mut stem = String::with_capacity(org.len() + name.len() + package_version.len() + 2);
    for (index, part) in [org, name, package_version].iter().enumerate() {
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

fn encode(document: &DependencyGraphDocument, format: ExportFormat) -> ApiResult<Vec<u8>> {
    match format {
        ExportFormat::Json5 => encode_json5(document),
        ExportFormat::Xml => Ok(encode_xml(document)?.into_bytes()),
        ExportFormat::Csv => encode_csv(document),
        ExportFormat::MessagePack => encode_messagepack(document),
        ExportFormat::Protobuf => encode_protobuf(document),
    }
}

fn canonical_json(document: &DependencyGraphDocument) -> ApiResult<Vec<u8>> {
    document
        .canonical_document_bytes()
        .map_err(|error| ApiErr::from(anyhow::anyhow!("graph canonicalization failed: {error}")))
}

fn declared_parts(
    document: &DependencyGraphDocument,
) -> ApiResult<(&PackageVersionIdentity, &[DeclaredDependency])> {
    match &document.graph {
        DependencyGraphData::Declared {
            package,
            dependencies,
        } => Ok((package, dependencies)),
        DependencyGraphData::Resolved { .. } => Err(ApiErr::from(anyhow::anyhow!(
            "declared graph export received a resolved document"
        ))),
    }
}

// ---------------------------------------------------------------------------
// JSON5: comments plus the canonical JSON document (JSON is valid JSON5).
// ---------------------------------------------------------------------------

fn encode_json5(document: &DependencyGraphDocument) -> ApiResult<Vec<u8>> {
    let canonical = canonical_json(document)?;
    let digest = document.graph_digest.as_deref().unwrap_or("missing");
    let mut output = format!(
        "// zpkg/dependency-graph/v1 — lossless JSON5 projection\n\
         // graph_digest: {digest}\n\
         // Remove these comments to recover the canonical JSON document.\n"
    )
    .into_bytes();
    output.extend_from_slice(&canonical);
    output.push(b'\n');
    Ok(output)
}

// ---------------------------------------------------------------------------
// XML: deterministic declared-graph projection.
// ---------------------------------------------------------------------------

fn encode_xml(document: &DependencyGraphDocument) -> ApiResult<String> {
    let (package, dependencies) = declared_parts(document)?;
    let mut output = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    output.push_str("<dependency-graph");
    xml_attribute(&mut output, "schema", &document.schema);
    if let Some(digest) = &document.graph_digest {
        xml_attribute(&mut output, "graph-digest", digest);
    }
    xml_attribute(&mut output, "view", "declared");
    output.push_str(">\n  <package");
    xml_identity_attributes(&mut output, package);
    output.push_str(" />\n");
    writeln!(
        output,
        "  <dependencies count=\"{}\">",
        dependencies.len()
    )
    .expect("writing to a String cannot fail");

    for dependency in dependencies {
        output.push_str("    <dependency");
        xml_attribute(&mut output, "registry-id", &dependency.registry_id);
        xml_attribute(&mut output, "org", &dependency.org);
        xml_attribute(&mut output, "name", &dependency.name);
        xml_attribute(&mut output, "requirement", &dependency.requirement);
        xml_attribute(&mut output, "kind", dependency_kind_name(dependency.kind));
        xml_attribute(&mut output, "optional", bool_name(dependency.optional));
        xml_attribute(
            &mut output,
            "default-features",
            bool_name(dependency.default_features),
        );
        if let Some(target) = &dependency.target {
            xml_attribute(&mut output, "target", target);
        }
        if dependency.features.is_empty() {
            output.push_str(" />\n");
        } else {
            output.push_str(">\n      <features>\n");
            for feature in &dependency.features {
                writeln!(
                    output,
                    "        <feature>{}</feature>",
                    escape_xml_text(feature)
                )
                .expect("writing to a String cannot fail");
            }
            output.push_str("      </features>\n    </dependency>\n");
        }
    }

    output.push_str("  </dependencies>\n</dependency-graph>\n");
    Ok(output)
}

fn xml_identity_attributes(output: &mut String, identity: &PackageVersionIdentity) {
    xml_attribute(output, "registry-id", &identity.registry_id);
    xml_attribute(output, "org", &identity.org);
    xml_attribute(output, "name", &identity.name);
    xml_attribute(output, "version", &identity.version);
}

fn xml_attribute(output: &mut String, name: &str, value: &str) {
    write!(output, " {name}=\"{}\"", escape_xml_attribute(value))
        .expect("writing to a String cannot fail");
}

fn escape_xml_attribute(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t' => escaped.push_str("&#9;"),
            '\n' => escaped.push_str("&#10;"),
            '\r' => escaped.push_str("&#13;"),
            control if control.is_control() => escaped.push('\u{fffd}'),
            other => escaped.push(other),
        }
    }
    escaped
}

fn escape_xml_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            control if control.is_control() && !matches!(control, '\t' | '\n' | '\r') => {
                escaped.push('\u{fffd}');
            }
            other => escaped.push(other),
        }
    }
    escaped
}

// ---------------------------------------------------------------------------
// CSV: RFC 4180 declared-node/edge analytics projection.
// ---------------------------------------------------------------------------

const CSV_HEADER: [&str; 20] = [
    "record_type",
    "view",
    "graph_digest",
    "from_registry",
    "from_org",
    "from_name",
    "from_version",
    "to_registry",
    "to_org",
    "to_name",
    "to_version",
    "requirement",
    "kind",
    "optional",
    "default_features",
    "target",
    "features_json",
    "artifact_digest",
    "completeness",
    "schema",
];

fn encode_csv(document: &DependencyGraphDocument) -> ApiResult<Vec<u8>> {
    let (package, dependencies) = declared_parts(document)?;
    let digest = document.graph_digest.as_deref().unwrap_or_default();
    let mut output = String::new();
    csv_record(&mut output, &CSV_HEADER);
    csv_record(
        &mut output,
        &csv_row(
            "node",
            digest,
            package,
            None,
            "",
            "",
            false,
            true,
            "",
            "[]",
            &document.schema,
        ),
    );

    for dependency in dependencies {
        let target = PackageVersionIdentity {
            registry_id: dependency.registry_id.clone(),
            org: dependency.org.clone(),
            name: dependency.name.clone(),
            version: String::new(),
        };
        let features = serde_json::to_string(&dependency.features).map_err(|error| {
            ApiErr::from(anyhow::anyhow!("serialize declared CSV features: {error}"))
        })?;
        csv_record(
            &mut output,
            &csv_row(
                "edge",
                digest,
                package,
                Some(&target),
                &dependency.requirement,
                dependency_kind_name(dependency.kind),
                dependency.optional,
                dependency.default_features,
                dependency.target.as_deref().unwrap_or_default(),
                &features,
                &document.schema,
            ),
        );
    }
    Ok(output.into_bytes())
}

#[allow(clippy::too_many_arguments)]
fn csv_row(
    record_type: &str,
    graph_digest: &str,
    from: &PackageVersionIdentity,
    to: Option<&PackageVersionIdentity>,
    requirement: &str,
    kind: &str,
    optional: bool,
    default_features: bool,
    target: &str,
    features_json: &str,
    schema: &str,
) -> [String; 20] {
    let to = to.cloned().unwrap_or_else(empty_identity);
    [
        record_type.to_string(),
        "declared".to_string(),
        graph_digest.to_string(),
        from.registry_id.clone(),
        from.org.clone(),
        from.name.clone(),
        from.version.clone(),
        to.registry_id,
        to.org,
        to.name,
        to.version,
        requirement.to_string(),
        kind.to_string(),
        bool_name(optional).to_string(),
        bool_name(default_features).to_string(),
        target.to_string(),
        features_json.to_string(),
        String::new(),
        String::new(),
        schema.to_string(),
    ]
}

fn empty_identity() -> PackageVersionIdentity {
    PackageVersionIdentity {
        registry_id: String::new(),
        org: String::new(),
        name: String::new(),
        version: String::new(),
    }
}

fn csv_record<T: AsRef<str>, const N: usize>(output: &mut String, fields: &[T; N]) {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        csv_field(output, field.as_ref());
    }
    output.push_str("\r\n");
}

fn csv_field(output: &mut String, value: &str) {
    let needs_quotes = value
        .bytes()
        .any(|byte| matches!(byte, b',' | b'"' | b'\r' | b'\n'));
    if !needs_quotes {
        output.push_str(value);
        return;
    }
    output.push('"');
    for character in value.chars() {
        if character == '"' {
            output.push_str("\"\"");
        } else {
            output.push(character);
        }
    }
    output.push('"');
}

// ---------------------------------------------------------------------------
// MessagePack: direct binary encoding of the canonical JSON value.
// ---------------------------------------------------------------------------

fn encode_messagepack(document: &DependencyGraphDocument) -> ApiResult<Vec<u8>> {
    let canonical = canonical_json(document)?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|error| {
        ApiErr::from(anyhow::anyhow!("reparse canonical graph JSON: {error}"))
    })?;
    let mut output = Vec::with_capacity(canonical.len());
    messagepack_value(&value, &mut output)?;
    Ok(output)
}

fn messagepack_value(value: &Value, output: &mut Vec<u8>) -> ApiResult<()> {
    match value {
        Value::Null => output.push(0xc0),
        Value::Bool(false) => output.push(0xc2),
        Value::Bool(true) => output.push(0xc3),
        Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                messagepack_u64(value, output);
            } else if let Some(value) = number.as_i64() {
                messagepack_i64(value, output);
            } else {
                return Err(ApiErr::from(anyhow::anyhow!(
                    "dependency graph contains a non-integer number"
                )));
            }
        }
        Value::String(value) => messagepack_string(value, output)?,
        Value::Array(items) => {
            messagepack_array_len(items.len(), output)?;
            for item in items {
                messagepack_value(item, output)?;
            }
        }
        Value::Object(map) => {
            messagepack_map_len(map.len(), output)?;
            for (key, value) in map {
                messagepack_string(key, output)?;
                messagepack_value(value, output)?;
            }
        }
    }
    Ok(())
}

fn messagepack_u64(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=0x7f => output.push(value as u8),
        0x80..=0xff => output.extend_from_slice(&[0xcc, value as u8]),
        0x100..=0xffff => {
            output.push(0xcd);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0xce);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(0xcf);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn messagepack_i64(value: i64, output: &mut Vec<u8>) {
    if value >= 0 {
        messagepack_u64(value as u64, output);
    } else if value >= -32 {
        output.push(value as i8 as u8);
    } else if value >= i8::MIN as i64 {
        output.extend_from_slice(&[0xd0, value as i8 as u8]);
    } else if value >= i16::MIN as i64 {
        output.push(0xd1);
        output.extend_from_slice(&(value as i16).to_be_bytes());
    } else if value >= i32::MIN as i64 {
        output.push(0xd2);
        output.extend_from_slice(&(value as i32).to_be_bytes());
    } else {
        output.push(0xd3);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn messagepack_string(value: &str, output: &mut Vec<u8>) -> ApiResult<()> {
    let bytes = value.as_bytes();
    match bytes.len() {
        0..=31 => output.push(0xa0 | bytes.len() as u8),
        32..=0xff => output.extend_from_slice(&[0xd9, bytes.len() as u8]),
        0x100..=0xffff => {
            output.push(0xda);
            output.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
        _ => {
            let length = u32::try_from(bytes.len()).map_err(|_| {
                ApiErr::from(anyhow::anyhow!("MessagePack string exceeds u32 length"))
            })?;
            output.push(0xdb);
            output.extend_from_slice(&length.to_be_bytes());
        }
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn messagepack_array_len(length: usize, output: &mut Vec<u8>) -> ApiResult<()> {
    match length {
        0..=15 => output.push(0x90 | length as u8),
        16..=0xffff => {
            output.push(0xdc);
            output.extend_from_slice(&(length as u16).to_be_bytes());
        }
        _ => {
            let length = u32::try_from(length).map_err(|_| {
                ApiErr::from(anyhow::anyhow!("MessagePack array exceeds u32 length"))
            })?;
            output.push(0xdd);
            output.extend_from_slice(&length.to_be_bytes());
        }
    }
    Ok(())
}

fn messagepack_map_len(length: usize, output: &mut Vec<u8>) -> ApiResult<()> {
    match length {
        0..=15 => output.push(0x80 | length as u8),
        16..=0xffff => {
            output.push(0xde);
            output.extend_from_slice(&(length as u16).to_be_bytes());
        }
        _ => {
            let length = u32::try_from(length).map_err(|_| {
                ApiErr::from(anyhow::anyhow!("MessagePack map exceeds u32 length"))
            })?;
            output.push(0xdf);
            output.extend_from_slice(&length.to_be_bytes());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Protocol Buffers: typed declared-graph field numbers from the shared schema.
// ---------------------------------------------------------------------------

fn encode_protobuf(document: &DependencyGraphDocument) -> ApiResult<Vec<u8>> {
    let (package, dependencies) = declared_parts(document)?;
    let mut declared = Vec::new();
    proto_message(1, &proto_identity(package), &mut declared);
    for dependency in dependencies {
        proto_message(2, &proto_declared_dependency(dependency), &mut declared);
    }

    let mut output = Vec::new();
    proto_string(1, &document.schema, &mut output);
    if let Some(digest) = &document.graph_digest {
        proto_string(2, digest, &mut output);
    }
    proto_message(10, &declared, &mut output);
    Ok(output)
}

fn proto_identity(identity: &PackageVersionIdentity) -> Vec<u8> {
    let mut output = Vec::new();
    proto_string(1, &identity.registry_id, &mut output);
    proto_string(2, &identity.org, &mut output);
    proto_string(3, &identity.name, &mut output);
    proto_string(4, &identity.version, &mut output);
    output
}

fn proto_declared_dependency(dependency: &DeclaredDependency) -> Vec<u8> {
    let mut output = Vec::new();
    proto_string(1, &dependency.registry_id, &mut output);
    proto_string(2, &dependency.org, &mut output);
    proto_string(3, &dependency.name, &mut output);
    proto_string(4, &dependency.requirement, &mut output);
    proto_u64(5, dependency_kind_code(dependency.kind), &mut output);
    proto_bool(6, dependency.optional, &mut output);
    proto_bool(7, dependency.default_features, &mut output);
    for feature in &dependency.features {
        proto_string(8, feature, &mut output);
    }
    if let Some(target) = &dependency.target {
        proto_string(9, target, &mut output);
    }
    output
}

fn proto_string(field: u32, value: &str, output: &mut Vec<u8>) {
    proto_message(field, value.as_bytes(), output);
}

fn proto_message(field: u32, value: &[u8], output: &mut Vec<u8>) {
    proto_varint((u64::from(field) << 3) | 2, output);
    proto_varint(value.len() as u64, output);
    output.extend_from_slice(value);
}

fn proto_bool(field: u32, value: bool, output: &mut Vec<u8>) {
    if value {
        proto_u64(field, 1, output);
    }
}

fn proto_u64(field: u32, value: u64, output: &mut Vec<u8>) {
    proto_varint(u64::from(field) << 3, output);
    proto_varint(value, output);
}

fn proto_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
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

const fn bool_name(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn aliases_map_to_stable_export_formats() {
        assert_eq!(
            ExportFormat::parse("messagepack"),
            Some(ExportFormat::MessagePack)
        );
        assert_eq!(ExportFormat::parse("proto"), Some(ExportFormat::Protobuf));
        assert!(ExportFormat::parse("pickle").is_none());
        assert!(!ExportFormat::Csv.is_authoritative());
        assert!(ExportFormat::Xml.is_authoritative());
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
    fn xml_escapes_attributes_and_preserves_declared_fields() {
        let xml = encode_xml(&sample_document()).unwrap();
        assert!(xml.contains("view=\"declared\""));
        assert!(xml.contains("core&lt;&amp;&quot;"));
        assert!(xml.contains("requirement=\"^2, &gt;=2.1&#10;next\""));
        assert!(xml.contains("<feature>json</feature>"));
        assert!(xml.ends_with("</dependency-graph>\n"));
    }

    #[test]
    fn csv_is_rfc4180_escaped_and_marks_record_types() {
        let bytes = encode_csv(&sample_document()).unwrap();
        let csv = String::from_utf8(bytes).unwrap();
        assert!(csv.starts_with("record_type,view,graph_digest"));
        assert!(csv.contains("node,declared"));
        assert!(csv.contains("edge,declared"));
        assert!(csv.contains("\"^2, >=2.1\nnext\""));
        assert_eq!(csv.lines().next().unwrap().split(',').count(), CSV_HEADER.len());
    }

    #[test]
    fn messagepack_is_a_named_map_with_all_document_keys() {
        let bytes = encode_messagepack(&sample_document()).unwrap();
        let first = *bytes.first().unwrap();
        assert!(matches!(first, 0x80..=0x8f | 0xde | 0xdf));
        for key in [b"schema".as_slice(), b"view", b"graph_digest"] {
            assert!(
                bytes.windows(key.len()).any(|window| window == key),
                "missing MessagePack key {}",
                String::from_utf8_lossy(key)
            );
        }
    }

    #[test]
    fn protobuf_uses_the_committed_typed_schema_field_numbers() {
        let document = sample_document();
        let bytes = encode_protobuf(&document).unwrap();
        let fields = protobuf_fields(&bytes);
        assert_eq!(fields[0].0, 1, "schema is field 1");
        assert_eq!(fields[1].0, 2, "graph digest is field 2");
        assert_eq!(fields[2].0, 10, "declared graph is oneof field 10");
        assert_eq!(fields[0].1, document.schema.as_bytes());
        assert_eq!(
            fields[1].1,
            document.graph_digest.as_deref().unwrap().as_bytes()
        );
        let declared = protobuf_fields(fields[2].1);
        assert_eq!(declared[0].0, 1, "package identity is field 1");
        assert_eq!(declared[1].0, 2, "dependency is field 2");
    }

    #[test]
    fn validators_are_per_representation_but_digest_is_shared() {
        let document = sample_document();
        let json5 = respond(
            &HeaderMap::new(),
            ExportFormat::Json5,
            &document,
            "acme_app_1.0.0",
        )
        .unwrap();
        let xml = respond(
            &HeaderMap::new(),
            ExportFormat::Xml,
            &document,
            "acme_app_1.0.0",
        )
        .unwrap();
        assert_ne!(json5.headers().get(header::ETAG), xml.headers().get(header::ETAG));
        assert_eq!(
            json5.headers().get(DEPENDENCY_GRAPH_DIGEST_HEADER),
            xml.headers().get(DEPENDENCY_GRAPH_DIGEST_HEADER)
        );
        assert_eq!(json5.headers().get(AUTHORITATIVE_HEADER).unwrap(), "true");
    }

    fn protobuf_fields(mut bytes: &[u8]) -> Vec<(u32, &[u8])> {
        let mut fields = Vec::new();
        while !bytes.is_empty() {
            let (key, used) = read_varint(bytes);
            bytes = &bytes[used..];
            let field = (key >> 3) as u32;
            let wire = key & 7;
            assert_eq!(wire, 2, "test fixture expects length-delimited fields");
            let (length, used) = read_varint(bytes);
            bytes = &bytes[used..];
            let length = length as usize;
            fields.push((field, &bytes[..length]));
            bytes = &bytes[length..];
        }
        fields
    }

    fn read_varint(bytes: &[u8]) -> (u64, usize) {
        let mut value = 0_u64;
        for (index, byte) in bytes.iter().copied().enumerate() {
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return (value, index + 1);
            }
        }
        panic!("unterminated varint")
    }
}
