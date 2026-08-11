use std::fmt::Write as _;

use axum::http::StatusCode;
use zed_interfaces::{
    DependencyGraphData, DependencyGraphDocument, DependencyGraphProjection,
    PackageVersionIdentity, ResolutionProvenance,
};

use crate::error::{ApiErr, ApiResult};

use super::{bool_name, completeness_name, dependency_kind_name, representation_too_large};

pub(super) fn encode(document: &DependencyGraphDocument) -> ApiResult<Vec<u8>> {
    let mut output = XmlOutput::new();
    output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")?;
    output.push_str("<dependency-graph")?;
    xml_attribute(&mut output, "schema", &document.schema)?;
    if let Some(digest) = &document.graph_digest {
        xml_attribute(&mut output, "graph-digest", digest)?;
    }

    match &document.graph {
        DependencyGraphData::Declared {
            package,
            dependencies,
        } => {
            xml_attribute(&mut output, "view", "declared")?;
            output.push_str(">\n  ")?;
            xml_identity(&mut output, "package", package)?;
            writeln!(output, "  <dependencies count=\"{}\">", dependencies.len())
                .map_err(|_| representation_too_large())?;
            for dependency in dependencies {
                output.push_str("    <dependency")?;
                xml_attribute(&mut output, "registry-id", &dependency.registry_id)?;
                xml_attribute(&mut output, "org", &dependency.org)?;
                xml_attribute(&mut output, "name", &dependency.name)?;
                xml_attribute(&mut output, "requirement", &dependency.requirement)?;
                xml_attribute(&mut output, "kind", dependency_kind_name(dependency.kind))?;
                xml_attribute(&mut output, "optional", bool_name(dependency.optional))?;
                xml_attribute(
                    &mut output,
                    "default-features",
                    bool_name(dependency.default_features),
                )?;
                if let Some(target) = &dependency.target {
                    xml_attribute(&mut output, "target", target)?;
                }
                if dependency.features.is_empty() {
                    output.push_str(" />\n")?;
                } else {
                    output.push_str(">\n")?;
                    xml_features(&mut output, &dependency.features, 6)?;
                    output.push_str("    </dependency>\n")?;
                }
            }
            output.push_str("  </dependencies>\n</dependency-graph>\n")?;
        }
        DependencyGraphData::Resolved {
            completeness,
            roots,
            nodes,
            edges,
            provenance,
            parent_graph_digest,
            projection,
        } => {
            xml_attribute(&mut output, "view", "resolved")?;
            xml_attribute(
                &mut output,
                "completeness",
                completeness_name(*completeness),
            )?;
            output.push_str(">\n  <roots>\n")?;
            for root in roots {
                output.push_str("    ")?;
                xml_identity(&mut output, "root", root)?;
            }
            output.push_str("  </roots>\n  <nodes>\n")?;
            for node in nodes {
                output.push_str("    <node")?;
                xml_identity_attributes(&mut output, &node.id)?;
                if let Some(digest) = &node.artifact_digest {
                    xml_attribute(&mut output, "artifact-digest", digest)?;
                }
                if node.features.is_empty() {
                    output.push_str(" />\n")?;
                } else {
                    output.push_str(">\n")?;
                    xml_features(&mut output, &node.features, 6)?;
                    output.push_str("    </node>\n")?;
                }
            }
            output.push_str("  </nodes>\n  <edges>\n")?;
            for edge in edges {
                output.push_str("    <edge")?;
                xml_attribute(&mut output, "kind", dependency_kind_name(edge.kind))?;
                xml_attribute(&mut output, "optional", bool_name(edge.optional))?;
                if let Some(requirement) = &edge.requirement {
                    xml_attribute(&mut output, "requirement", requirement)?;
                }
                if let Some(target) = &edge.target {
                    xml_attribute(&mut output, "target", target)?;
                }
                output.push_str(">\n      ")?;
                xml_identity(&mut output, "from", &edge.from)?;
                output.push_str("      ")?;
                xml_identity(&mut output, "to", &edge.to)?;
                if !edge.features.is_empty() {
                    xml_features(&mut output, &edge.features, 6)?;
                }
                output.push_str("    </edge>\n")?;
            }
            output.push_str("  </edges>\n  ")?;
            xml_provenance(&mut output, provenance)?;
            if let Some(parent) = parent_graph_digest {
                output.push_str("  <parent-graph")?;
                xml_attribute(&mut output, "digest", parent)?;
                output.push_str(" />\n")?;
            }
            if let Some(projection) = projection {
                output.push_str("  ")?;
                xml_projection(&mut output, projection)?;
            }
            output.push_str("</dependency-graph>\n")?;
        }
    }
    Ok(output.into_bytes())
}

fn xml_identity(
    output: &mut XmlOutput,
    tag: &str,
    identity: &PackageVersionIdentity,
) -> ApiResult<()> {
    write!(output, "<{tag}").map_err(|_| representation_too_large())?;
    xml_identity_attributes(output, identity)?;
    output.push_str(" />\n")
}

fn xml_identity_attributes(
    output: &mut XmlOutput,
    identity: &PackageVersionIdentity,
) -> ApiResult<()> {
    xml_attribute(output, "registry-id", &identity.registry_id)?;
    xml_attribute(output, "org", &identity.org)?;
    xml_attribute(output, "name", &identity.name)?;
    xml_attribute(output, "version", &identity.version)
}

fn xml_features(output: &mut XmlOutput, features: &[String], spaces: usize) -> ApiResult<()> {
    let indent = " ".repeat(spaces);
    writeln!(output, "{indent}<features>").map_err(|_| representation_too_large())?;
    for feature in features {
        write!(output, "{indent}  <feature>").map_err(|_| representation_too_large())?;
        xml_text(output, feature)?;
        output.push_str("</feature>\n")?;
    }
    writeln!(output, "{indent}</features>").map_err(|_| representation_too_large())?;
    Ok(())
}

fn xml_provenance(output: &mut XmlOutput, provenance: &ResolutionProvenance) -> ApiResult<()> {
    output.push_str("<provenance")?;
    xml_attribute(output, "resolver-version", &provenance.resolver_version)?;
    xml_attribute(output, "target", &provenance.target)?;
    xml_attribute(output, "lock-digest", &provenance.lock_digest)?;
    output.push_str(">\n")?;
    if !provenance.enabled_features.is_empty() {
        xml_features(output, &provenance.enabled_features, 4)?;
    }
    output.push_str("    <registry-snapshots>\n")?;
    for snapshot in &provenance.registry_snapshots {
        output.push_str("      <registry-snapshot")?;
        xml_attribute(output, "registry-id", &snapshot.registry_id)?;
        xml_attribute(output, "checkpoint-digest", &snapshot.checkpoint_digest)?;
        output.push_str(" />\n")?;
    }
    output.push_str("    </registry-snapshots>\n  </provenance>\n")
}

fn xml_projection(output: &mut XmlOutput, projection: &DependencyGraphProjection) -> ApiResult<()> {
    output.push_str("<projection")?;
    if let Some(target) = &projection.target {
        xml_attribute(output, "target", target)?;
    }
    if let Some(max_depth) = projection.max_depth {
        xml_attribute(output, "max-depth", &max_depth.to_string())?;
    }
    if projection.features.is_empty() && projection.kinds.is_empty() {
        return output.push_str(" />\n");
    }
    output.push_str(">\n")?;
    if !projection.features.is_empty() {
        xml_features(output, &projection.features, 4)?;
    }
    if !projection.kinds.is_empty() {
        output.push_str("    <kinds>\n")?;
        for kind in &projection.kinds {
            writeln!(output, "      <kind>{}</kind>", dependency_kind_name(*kind))
                .map_err(|_| representation_too_large())?;
        }
        output.push_str("    </kinds>\n")?;
    }
    output.push_str("  </projection>\n")
}

fn xml_attribute(output: &mut XmlOutput, name: &str, value: &str) -> ApiResult<()> {
    write!(output, " {name}=\"").map_err(|_| representation_too_large())?;
    xml_escaped(output, value, true)?;
    output.push_str("\"")
}

fn xml_text(output: &mut XmlOutput, value: &str) -> ApiResult<()> {
    xml_escaped(output, value, false)
}

fn xml_escaped(output: &mut XmlOutput, value: &str, attribute: bool) -> ApiResult<()> {
    for character in value.chars() {
        if !is_xml_10_character(character) {
            return Err(ApiErr {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                code: "graph_not_representable",
                message: "dependency graph contains a character XML 1.0 cannot represent"
                    .to_string(),
            });
        }
        match character {
            '&' => output.push_str("&amp;")?,
            '<' => output.push_str("&lt;")?,
            '>' => output.push_str("&gt;")?,
            '"' if attribute => output.push_str("&quot;")?,
            '\'' if attribute => output.push_str("&apos;")?,
            '\t' if attribute => output.push_str("&#9;")?,
            '\n' if attribute => output.push_str("&#10;")?,
            // XML processors normalize a literal carriage return to linefeed
            // even in element text, so use a character reference in both
            // contexts to keep this projection lossless.
            '\r' => output.push_str("&#13;")?,
            character => output.push_char(character)?,
        }
    }
    Ok(())
}

const fn is_xml_10_character(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r')
        || matches!(character as u32, 0x20..=0xd7ff | 0xe000..=0xfffd | 0x10000..=0x10ffff)
}

struct XmlOutput {
    value: String,
}

impl XmlOutput {
    fn new() -> Self {
        Self {
            value: String::new(),
        }
    }

    fn push_str(&mut self, value: &str) -> ApiResult<()> {
        let length = self
            .value
            .len()
            .checked_add(value.len())
            .ok_or_else(representation_too_large)?;
        if length as u64 > zed_interfaces::DEPENDENCY_GRAPH_DEFAULT_MAX_ENCODED_BYTES {
            return Err(representation_too_large());
        }
        self.value.push_str(value);
        Ok(())
    }

    fn push_char(&mut self, character: char) -> ApiResult<()> {
        let mut bytes = [0_u8; 4];
        self.push_str(character.encode_utf8(&mut bytes))
    }

    fn into_bytes(self) -> Vec<u8> {
        self.value.into_bytes()
    }
}

impl std::fmt::Write for XmlOutput {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.push_str(value).map_err(|_| std::fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::super::sample_document;
    use super::*;

    #[test]
    fn escapes_attributes_and_preserves_graph_fields() {
        let xml = String::from_utf8(encode(&sample_document()).unwrap()).unwrap();
        assert!(xml.contains("view=\"declared\""));
        assert!(xml.contains("core&lt;&amp;&quot;"));
        assert!(xml.contains("requirement=\"^2, &gt;=2.1&#10;next\""));
        assert!(xml.contains("<feature>json</feature>"));
        assert!(xml.ends_with("</dependency-graph>\n"));
    }

    #[test]
    fn preserves_carriage_returns_and_rejects_invalid_xml_characters() {
        let mut document = sample_document();
        {
            let DependencyGraphData::Declared { dependencies, .. } = &mut document.graph else {
                panic!("declared fixture");
            };
            dependencies[0].features.push("line\rreturn".to_string());
        }
        document = document.finalize().unwrap();
        let xml = String::from_utf8(encode(&document).unwrap()).unwrap();
        assert!(xml.contains("<feature>line&#13;return</feature>"));

        {
            let DependencyGraphData::Declared { dependencies, .. } = &mut document.graph else {
                unreachable!();
            };
            dependencies[0].features.push("nul\0byte".to_string());
        }
        document = document.finalize().unwrap();
        let error = encode(&document).unwrap_err();
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error.code, "graph_not_representable");
    }
}
