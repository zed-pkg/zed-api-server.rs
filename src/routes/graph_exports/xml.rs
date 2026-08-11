use std::fmt::Write as _;

use zed_interfaces::{
    DependencyGraphData, DependencyGraphDocument, DependencyGraphProjection,
    PackageVersionIdentity, ResolutionProvenance,
};

use super::{bool_name, completeness_name, dependency_kind_name};

pub(super) fn encode(document: &DependencyGraphDocument) -> String {
    let mut output = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    output.push_str("<dependency-graph");
    xml_attribute(&mut output, "schema", &document.schema);
    if let Some(digest) = &document.graph_digest {
        xml_attribute(&mut output, "graph-digest", digest);
    }

    match &document.graph {
        DependencyGraphData::Declared {
            package,
            dependencies,
        } => {
            xml_attribute(&mut output, "view", "declared");
            output.push_str(">\n  ");
            xml_identity(&mut output, "package", package);
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
                    output.push_str(">\n");
                    xml_features(&mut output, &dependency.features, 6);
                    output.push_str("    </dependency>\n");
                }
            }
            output.push_str("  </dependencies>\n</dependency-graph>\n");
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
            xml_attribute(&mut output, "view", "resolved");
            xml_attribute(
                &mut output,
                "completeness",
                completeness_name(*completeness),
            );
            output.push_str(">\n  <roots>\n");
            for root in roots {
                output.push_str("    ");
                xml_identity(&mut output, "root", root);
            }
            output.push_str("  </roots>\n  <nodes>\n");
            for node in nodes {
                output.push_str("    <node");
                xml_identity_attributes(&mut output, &node.id);
                if let Some(digest) = &node.artifact_digest {
                    xml_attribute(&mut output, "artifact-digest", digest);
                }
                if node.features.is_empty() {
                    output.push_str(" />\n");
                } else {
                    output.push_str(">\n");
                    xml_features(&mut output, &node.features, 6);
                    output.push_str("    </node>\n");
                }
            }
            output.push_str("  </nodes>\n  <edges>\n");
            for edge in edges {
                output.push_str("    <edge");
                xml_attribute(&mut output, "kind", dependency_kind_name(edge.kind));
                xml_attribute(&mut output, "optional", bool_name(edge.optional));
                if let Some(requirement) = &edge.requirement {
                    xml_attribute(&mut output, "requirement", requirement);
                }
                if let Some(target) = &edge.target {
                    xml_attribute(&mut output, "target", target);
                }
                output.push_str(">\n      ");
                xml_identity(&mut output, "from", &edge.from);
                output.push_str("      ");
                xml_identity(&mut output, "to", &edge.to);
                if !edge.features.is_empty() {
                    xml_features(&mut output, &edge.features, 6);
                }
                output.push_str("    </edge>\n");
            }
            output.push_str("  </edges>\n  ");
            xml_provenance(&mut output, provenance);
            if let Some(parent) = parent_graph_digest {
                output.push_str("  <parent-graph");
                xml_attribute(&mut output, "digest", parent);
                output.push_str(" />\n");
            }
            if let Some(projection) = projection {
                output.push_str("  ");
                xml_projection(&mut output, projection);
            }
            output.push_str("</dependency-graph>\n");
        }
    }
    output
}

fn xml_identity(output: &mut String, tag: &str, identity: &PackageVersionIdentity) {
    write!(output, "<{tag}").expect("writing to a String cannot fail");
    xml_identity_attributes(output, identity);
    output.push_str(" />\n");
}

fn xml_identity_attributes(output: &mut String, identity: &PackageVersionIdentity) {
    xml_attribute(output, "registry-id", &identity.registry_id);
    xml_attribute(output, "org", &identity.org);
    xml_attribute(output, "name", &identity.name);
    xml_attribute(output, "version", &identity.version);
}

fn xml_features(output: &mut String, features: &[String], spaces: usize) {
    let indent = " ".repeat(spaces);
    writeln!(output, "{indent}<features>").expect("writing to a String cannot fail");
    for feature in features {
        writeln!(
            output,
            "{indent}  <feature>{}</feature>",
            escape_xml_text(feature)
        )
        .expect("writing to a String cannot fail");
    }
    writeln!(output, "{indent}</features>").expect("writing to a String cannot fail");
}

fn xml_provenance(output: &mut String, provenance: &ResolutionProvenance) {
    output.push_str("<provenance");
    xml_attribute(output, "resolver-version", &provenance.resolver_version);
    xml_attribute(output, "target", &provenance.target);
    xml_attribute(output, "lock-digest", &provenance.lock_digest);
    output.push_str(">\n");
    if !provenance.enabled_features.is_empty() {
        xml_features(output, &provenance.enabled_features, 4);
    }
    output.push_str("    <registry-snapshots>\n");
    for snapshot in &provenance.registry_snapshots {
        output.push_str("      <registry-snapshot");
        xml_attribute(output, "registry-id", &snapshot.registry_id);
        xml_attribute(output, "checkpoint-digest", &snapshot.checkpoint_digest);
        output.push_str(" />\n");
    }
    output.push_str("    </registry-snapshots>\n  </provenance>\n");
}

fn xml_projection(output: &mut String, projection: &DependencyGraphProjection) {
    output.push_str("<projection");
    if let Some(target) = &projection.target {
        xml_attribute(output, "target", target);
    }
    if let Some(max_depth) = projection.max_depth {
        xml_attribute(output, "max-depth", &max_depth.to_string());
    }
    if projection.features.is_empty() && projection.kinds.is_empty() {
        output.push_str(" />\n");
        return;
    }
    output.push_str(">\n");
    if !projection.features.is_empty() {
        xml_features(output, &projection.features, 4);
    }
    if !projection.kinds.is_empty() {
        output.push_str("    <kinds>\n");
        for kind in &projection.kinds {
            writeln!(output, "      <kind>{}</kind>", dependency_kind_name(*kind))
                .expect("writing to a String cannot fail");
        }
        output.push_str("    </kinds>\n");
    }
    output.push_str("  </projection>\n");
}

fn xml_attribute(output: &mut String, name: &str, value: &str) {
    write!(output, " {name}=\"{}\"", escape_xml_attribute(value))
        .expect("writing to a String cannot fail");
}

fn escape_xml_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('\t', "&#9;")
        .replace('\n', "&#10;")
        .replace('\r', "&#13;")
}

fn escape_xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::super::sample_document;
    use super::*;

    #[test]
    fn escapes_attributes_and_preserves_graph_fields() {
        let xml = encode(&sample_document());
        assert!(xml.contains("view=\"declared\""));
        assert!(xml.contains("core&lt;&amp;&quot;"));
        assert!(xml.contains("requirement=\"^2, &gt;=2.1&#10;next\""));
        assert!(xml.contains("<feature>json</feature>"));
        assert!(xml.ends_with("</dependency-graph>\n"));
    }
}
