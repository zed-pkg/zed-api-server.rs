use zed_interfaces::{
    DeclaredDependency, DependencyGraphData, DependencyGraphDocument, DependencyGraphProjection,
    PackageVersionIdentity, RegistrySnapshot, ResolutionProvenance, ResolvedDependencyEdge,
    ResolvedDependencyNode,
};

use super::{completeness_code, dependency_kind_code};

pub(super) fn encode(document: &DependencyGraphDocument) -> Vec<u8> {
    let mut output = Vec::new();
    proto_string(1, &document.schema, &mut output);
    if let Some(digest) = &document.graph_digest {
        proto_string(2, digest, &mut output);
    }
    match &document.graph {
        DependencyGraphData::Declared {
            package,
            dependencies,
        } => {
            let mut graph = Vec::new();
            proto_message(1, &proto_identity(package), &mut graph);
            for dependency in dependencies {
                proto_message(2, &proto_declared_dependency(dependency), &mut graph);
            }
            proto_message(10, &graph, &mut output);
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
            let mut graph = Vec::new();
            proto_enum(1, completeness_code(*completeness), &mut graph);
            for root in roots {
                proto_message(2, &proto_identity(root), &mut graph);
            }
            for node in nodes {
                proto_message(3, &proto_resolved_node(node), &mut graph);
            }
            for edge in edges {
                proto_message(4, &proto_resolved_edge(edge), &mut graph);
            }
            proto_message(5, &proto_provenance(provenance), &mut graph);
            if let Some(parent) = parent_graph_digest {
                proto_string(6, parent, &mut graph);
            }
            if let Some(projection) = projection {
                proto_message(7, &proto_projection(projection), &mut graph);
            }
            proto_message(11, &graph, &mut output);
        }
    }
    output
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
    proto_enum(5, dependency_kind_code(dependency.kind), &mut output);
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

fn proto_resolved_node(node: &ResolvedDependencyNode) -> Vec<u8> {
    let mut output = Vec::new();
    proto_message(1, &proto_identity(&node.id), &mut output);
    if let Some(digest) = &node.artifact_digest {
        proto_string(2, digest, &mut output);
    }
    for feature in &node.features {
        proto_string(3, feature, &mut output);
    }
    output
}

fn proto_resolved_edge(edge: &ResolvedDependencyEdge) -> Vec<u8> {
    let mut output = Vec::new();
    proto_message(1, &proto_identity(&edge.from), &mut output);
    proto_message(2, &proto_identity(&edge.to), &mut output);
    proto_enum(3, dependency_kind_code(edge.kind), &mut output);
    if let Some(requirement) = &edge.requirement {
        proto_string(4, requirement, &mut output);
    }
    if let Some(target) = &edge.target {
        proto_string(5, target, &mut output);
    }
    proto_bool(6, edge.optional, &mut output);
    for feature in &edge.features {
        proto_string(7, feature, &mut output);
    }
    output
}

fn proto_snapshot(snapshot: &RegistrySnapshot) -> Vec<u8> {
    let mut output = Vec::new();
    proto_string(1, &snapshot.registry_id, &mut output);
    proto_string(2, &snapshot.checkpoint_digest, &mut output);
    output
}

fn proto_provenance(provenance: &ResolutionProvenance) -> Vec<u8> {
    let mut output = Vec::new();
    proto_string(1, &provenance.resolver_version, &mut output);
    proto_string(2, &provenance.target, &mut output);
    for feature in &provenance.enabled_features {
        proto_string(3, feature, &mut output);
    }
    for snapshot in &provenance.registry_snapshots {
        proto_message(4, &proto_snapshot(snapshot), &mut output);
    }
    proto_string(5, &provenance.lock_digest, &mut output);
    output
}

fn proto_projection(projection: &DependencyGraphProjection) -> Vec<u8> {
    let mut output = Vec::new();
    if let Some(target) = &projection.target {
        proto_string(1, target, &mut output);
    }
    for feature in &projection.features {
        proto_string(2, feature, &mut output);
    }
    for kind in &projection.kinds {
        proto_enum(3, dependency_kind_code(*kind), &mut output);
    }
    if let Some(max_depth) = projection.max_depth {
        proto_u64(4, u64::from(max_depth), &mut output);
    }
    output
}

fn proto_string(field: u32, value: &str, output: &mut Vec<u8>) {
    proto_message(field, value.as_bytes(), output);
}

fn proto_message(field: u32, value: &[u8], output: &mut Vec<u8>) {
    proto_varint(u64::from(field) << 3 | 2, output);
    proto_varint(value.len() as u64, output);
    output.extend_from_slice(value);
}

fn proto_enum(field: u32, value: u64, output: &mut Vec<u8>) {
    proto_u64(field, value, output);
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

#[cfg(test)]
mod tests {
    use super::super::sample_document;
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum WireValue<'a> {
        Varint(u64),
        Bytes(&'a [u8]),
    }

    #[test]
    fn uses_the_committed_typed_schema_field_numbers() {
        let document = sample_document();
        let bytes = encode(&document);
        let fields = protobuf_fields(&bytes);
        assert_eq!(fields[0].0, 1, "schema is field 1");
        assert_eq!(fields[1].0, 2, "graph digest is field 2");
        assert_eq!(fields[2].0, 10, "declared graph is oneof field 10");
        assert_eq!(fields[0].1, WireValue::Bytes(document.schema.as_bytes()));
        assert_eq!(
            fields[1].1,
            WireValue::Bytes(document.graph_digest.as_deref().unwrap().as_bytes())
        );
        let WireValue::Bytes(declared_bytes) = fields[2].1 else {
            panic!("declared graph is a message");
        };
        let declared = protobuf_fields(declared_bytes);
        assert_eq!(declared[0].0, 1, "package identity is field 1");
        assert_eq!(declared[1].0, 2, "dependency is field 2");
    }

    #[test]
    fn resolved_projection_covers_the_typed_schema() {
        let document = zed_interfaces::golden_fixture_documents()
            .into_iter()
            .find(|(name, _)| *name == "projected")
            .unwrap()
            .1;
        let encoded = encode(&document);
        let fields = protobuf_fields(&encoded);
        let WireValue::Bytes(resolved_bytes) = fields
            .iter()
            .find(|(field, _)| *field == 11)
            .expect("resolved oneof arm")
            .1
        else {
            panic!("resolved graph is a message");
        };
        let resolved = protobuf_fields(resolved_bytes);
        assert_eq!(field_varints(&resolved, 1), vec![2]);
        assert_eq!(field_count(&resolved, 2), 1, "root");
        assert_eq!(field_count(&resolved, 3), 3, "nodes");
        assert_eq!(field_count(&resolved, 4), 2, "edges");
        assert_eq!(field_count(&resolved, 5), 1, "provenance");
        assert_eq!(field_count(&resolved, 6), 1, "parent graph digest");

        let projection = resolved
            .iter()
            .find_map(|(field, value)| match (*field == 7, value) {
                (true, WireValue::Bytes(value)) => Some(*value),
                _ => None,
            })
            .unwrap();
        let projection = protobuf_fields(projection);
        assert_eq!(field_varints(&projection, 3), vec![1], "runtime kind");
        assert_eq!(field_varints(&projection, 4), vec![1], "max depth");
    }

    #[test]
    fn committed_schema_declares_every_field_the_encoder_uses() {
        let schema = include_str!("../../../proto/zpkg_dependency_graph_v1.proto");
        for declaration in [
            "string schema = 1;",
            "string graph_digest = 2;",
            "DeclaredGraph declared = 10;",
            "ResolvedGraph resolved = 11;",
            "DeclaredDependency dependencies = 2;",
            "ResolutionProvenance provenance = 5;",
            "optional DependencyGraphProjection projection = 7;",
        ] {
            assert!(
                schema.contains(declaration),
                "protobuf contract lost declaration {declaration:?}"
            );
        }
    }

    fn field_count(fields: &[(u32, WireValue<'_>)], number: u32) -> usize {
        fields.iter().filter(|(field, _)| *field == number).count()
    }

    fn field_varints(fields: &[(u32, WireValue<'_>)], number: u32) -> Vec<u64> {
        fields
            .iter()
            .filter_map(|(field, value)| match (*field == number, value) {
                (true, WireValue::Varint(value)) => Some(*value),
                _ => None,
            })
            .collect()
    }

    fn protobuf_fields(mut bytes: &[u8]) -> Vec<(u32, WireValue<'_>)> {
        let mut fields = Vec::new();
        while !bytes.is_empty() {
            let (key, used) = read_varint(bytes);
            bytes = &bytes[used..];
            let field = (key >> 3) as u32;
            let wire = key & 7;
            match wire {
                0 => {
                    let (value, used) = read_varint(bytes);
                    bytes = &bytes[used..];
                    fields.push((field, WireValue::Varint(value)));
                }
                2 => {
                    let (length, used) = read_varint(bytes);
                    bytes = &bytes[used..];
                    let length = usize::try_from(length).unwrap();
                    fields.push((field, WireValue::Bytes(&bytes[..length])));
                    bytes = &bytes[length..];
                }
                _ => panic!("unsupported wire type {wire}"),
            }
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
