use zed_interfaces::{DependencyGraphData, DependencyGraphDocument, PackageVersionIdentity};

use crate::error::{ApiErr, ApiResult};

use super::{bool_name, completeness_name, dependency_kind_name, representation_too_large};

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

pub(super) fn encode(document: &DependencyGraphDocument) -> ApiResult<Vec<u8>> {
    let digest = document.graph_digest.as_deref().unwrap_or_default();
    let mut output = String::new();
    csv_record(&mut output, &CSV_HEADER)?;

    match &document.graph {
        DependencyGraphData::Declared {
            package,
            dependencies,
        } => {
            let package_row = csv_row(
                "node",
                "declared",
                digest,
                Some(package),
                None,
                "",
                "",
                None,
                None,
                "",
                "[]",
                "",
                "",
                &document.schema,
            );
            csv_record(&mut output, &package_row)?;
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
                let row = csv_row(
                    "edge",
                    "declared",
                    digest,
                    Some(package),
                    Some(&target),
                    &dependency.requirement,
                    dependency_kind_name(dependency.kind),
                    Some(dependency.optional),
                    Some(dependency.default_features),
                    dependency.target.as_deref().unwrap_or_default(),
                    &features,
                    "",
                    "",
                    &document.schema,
                );
                csv_record(&mut output, &row)?;
            }
        }
        DependencyGraphData::Resolved {
            completeness,
            roots,
            nodes,
            edges,
            ..
        } => {
            let completeness = completeness_name(*completeness);
            for root in roots {
                let row = csv_row(
                    "root",
                    "resolved",
                    digest,
                    Some(root),
                    None,
                    "",
                    "",
                    None,
                    None,
                    "",
                    "[]",
                    "",
                    completeness,
                    &document.schema,
                );
                csv_record(&mut output, &row)?;
            }
            for node in nodes {
                let features = serde_json::to_string(&node.features).map_err(|error| {
                    ApiErr::from(anyhow::anyhow!("serialize node CSV features: {error}"))
                })?;
                let row = csv_row(
                    "node",
                    "resolved",
                    digest,
                    Some(&node.id),
                    None,
                    "",
                    "",
                    None,
                    None,
                    "",
                    &features,
                    node.artifact_digest.as_deref().unwrap_or_default(),
                    completeness,
                    &document.schema,
                );
                csv_record(&mut output, &row)?;
            }
            for edge in edges {
                let features = serde_json::to_string(&edge.features).map_err(|error| {
                    ApiErr::from(anyhow::anyhow!("serialize edge CSV features: {error}"))
                })?;
                let row = csv_row(
                    "edge",
                    "resolved",
                    digest,
                    Some(&edge.from),
                    Some(&edge.to),
                    edge.requirement.as_deref().unwrap_or_default(),
                    dependency_kind_name(edge.kind),
                    Some(edge.optional),
                    None,
                    edge.target.as_deref().unwrap_or_default(),
                    &features,
                    "",
                    completeness,
                    &document.schema,
                );
                csv_record(&mut output, &row)?;
            }
        }
    }
    Ok(output.into_bytes())
}

#[allow(clippy::too_many_arguments)]
fn csv_row(
    record_type: &str,
    view: &str,
    graph_digest: &str,
    from: Option<&PackageVersionIdentity>,
    to: Option<&PackageVersionIdentity>,
    requirement: &str,
    kind: &str,
    optional: Option<bool>,
    default_features: Option<bool>,
    target: &str,
    features_json: &str,
    artifact_digest: &str,
    completeness: &str,
    schema: &str,
) -> [String; 20] {
    let from = from.cloned().unwrap_or_else(empty_identity);
    let to = to.cloned().unwrap_or_else(empty_identity);
    [
        record_type.to_string(),
        view.to_string(),
        graph_digest.to_string(),
        from.registry_id,
        from.org,
        from.name,
        from.version,
        to.registry_id,
        to.org,
        to.name,
        to.version,
        requirement.to_string(),
        kind.to_string(),
        optional.map(bool_name).unwrap_or_default().to_string(),
        default_features
            .map(bool_name)
            .unwrap_or_default()
            .to_string(),
        target.to_string(),
        features_json.to_string(),
        artifact_digest.to_string(),
        completeness.to_string(),
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

fn csv_record<T: AsRef<str>, const N: usize>(
    output: &mut String,
    fields: &[T; N],
) -> ApiResult<()> {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            push_bounded(output, ",")?;
        }
        csv_field(output, field.as_ref())?;
    }
    push_bounded(output, "\r\n")
}

fn csv_field(output: &mut String, value: &str) -> ApiResult<()> {
    // CSV is commonly opened directly in spreadsheet software. RFC 4180
    // quoting alone does not stop a cell beginning with =, +, -, @, tab, or a
    // line break from being interpreted as a formula. Prefix such fields with
    // an apostrophe inside the quoted cell; CSV is explicitly a
    // non-authoritative analytics projection, so safety takes precedence over
    // byte-for-byte field recovery here.
    let spreadsheet_unsafe = value
        .chars()
        .next()
        .is_some_and(|character| matches!(character, '\t' | '\r' | '\n'))
        || value
            .trim_start()
            .chars()
            .next()
            .is_some_and(|character| matches!(character, '=' | '+' | '-' | '@'));
    let needs_quotes = spreadsheet_unsafe
        || value
            .bytes()
            .any(|byte| matches!(byte, b',' | b'\"' | b'\r' | b'\n'));

    let quote_expansion = value.bytes().filter(|byte| *byte == b'\"').count();
    let encoded_len = value
        .len()
        .checked_add(quote_expansion)
        .and_then(|length| length.checked_add(if spreadsheet_unsafe { 1 } else { 0 }))
        .and_then(|length| length.checked_add(if needs_quotes { 2 } else { 0 }))
        .ok_or_else(representation_too_large)?;
    ensure_room(output.len(), encoded_len)?;

    if !needs_quotes {
        output.push_str(value);
        return Ok(());
    }
    output.push('"');
    if spreadsheet_unsafe {
        output.push('\'');
    }
    for character in value.chars() {
        if character == '"' {
            output.push_str("\"\"");
        } else {
            output.push(character);
        }
    }
    output.push('"');
    Ok(())
}

fn push_bounded(output: &mut String, value: &str) -> ApiResult<()> {
    ensure_room(output.len(), value.len())?;
    output.push_str(value);
    Ok(())
}

fn ensure_room(current: usize, additional: usize) -> ApiResult<()> {
    let length = current
        .checked_add(additional)
        .ok_or_else(representation_too_large)?;
    if length as u64 > zed_interfaces::DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES {
        return Err(representation_too_large());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::sample_document;
    use super::*;

    #[test]
    fn is_rfc4180_escaped_and_marks_record_types() {
        let bytes = encode(&sample_document()).unwrap();
        let csv = String::from_utf8(bytes).unwrap();
        assert!(csv.starts_with("record_type,view,graph_digest"));
        assert!(csv.contains("node,declared"));
        assert!(csv.contains("edge,declared"));
        assert!(csv.contains("\"^2, >=2.1\nnext\""));
        assert_eq!(
            csv.lines().next().unwrap().split(',').count(),
            CSV_HEADER.len()
        );
    }

    #[test]
    fn neutralizes_spreadsheet_formula_cells() {
        for hostile in ["=1+1", "+cmd", "-2+3", "@SUM(A1:A2)", " \t=1", "\n=1"] {
            let mut output = String::new();
            csv_field(&mut output, hostile).unwrap();
            assert!(
                output.starts_with("\"'"),
                "formula-like cell was not neutralized: {output:?}"
            );
        }

        let mut safe = String::new();
        csv_field(&mut safe, "sha256:abc").unwrap();
        assert_eq!(safe, "sha256:abc");
    }

    #[test]
    fn leaves_non_applicable_boolean_columns_empty() {
        let row = csv_row(
            "node",
            "resolved",
            "sha256:digest",
            None,
            None,
            "",
            "",
            None,
            None,
            "",
            "[]",
            "",
            "complete",
            "zpkg/dependency-graph/v1",
        );
        assert_eq!(row[13], "", "optional is not applicable to a node");
        assert_eq!(
            row[14], "",
            "default_features does not exist on resolved nodes or edges"
        );
    }
}
