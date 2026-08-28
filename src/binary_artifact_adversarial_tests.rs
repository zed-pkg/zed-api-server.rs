#![cfg(test)]

use std::io::{Cursor, Read, Write};

use sha2::{Digest, Sha256};
use zed_interfaces::artifact::ArtifactFormat;
use zed_interfaces::binary_artifact::{
    BINARY_ARTIFACT_SCHEMA_V1, BINARY_PACKAGE_MANIFEST_PATH, BinaryArchiveFormatV1,
    BinaryArtifactManifestV1, BinaryFileV1, BinaryPackageIdentityV1, BinaryPlatformV1,
    BinarySourceProvenanceV1,
};
use zed_interfaces::manifest::Manifest;
use zed_interfaces::registry::PublishMeta;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::binary_artifact::verify_publish;

const DESCRIPTOR: &str = "pkg/.zpkg-binary.json";
const PAYLOAD: &str = "pkg/bin/hello";

#[derive(Clone)]
struct Entry {
    name: String,
    bytes: Vec<u8>,
    mode: u32,
    compression: CompressionMethod,
}

fn manifest() -> Manifest {
    Manifest::parse(
        r#"[package]
org = "acme"
name = "hello-bin-adversarial"
version = "1.2.3"
description = "server-side hostile ZIP fixture"
license = "MIT"

[package.repository]
vcs = "git"
url = "https://github.com/acme/hello-bin-adversarial"

[bin]
hello = "bin/hello"
"#,
    )
    .expect("valid fixture manifest")
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_archive() -> (PublishMeta, Vec<u8>) {
    let manifest = manifest();
    let manifest_bytes = manifest
        .to_toml_string()
        .expect("serialize fixture manifest")
        .into_bytes();
    let payload = b"hello binary\n";
    let descriptor = BinaryArtifactManifestV1 {
        schema: BINARY_ARTIFACT_SCHEMA_V1.to_owned(),
        package: BinaryPackageIdentityV1 {
            org: manifest.package.org.clone(),
            name: manifest.package.name.clone(),
            version: manifest.package.version.clone(),
        },
        platform: BinaryPlatformV1 {
            target: "x86_64-unknown-linux-gnu".to_owned(),
            os: "linux".to_owned(),
            arch: "x86_64".to_owned(),
            libc: Some("gnu".to_owned()),
            abi: None,
        },
        format: BinaryArchiveFormatV1::Zip,
        package_manifest: BINARY_PACKAGE_MANIFEST_PATH.to_owned(),
        expanded_size: (manifest_bytes.len() + payload.len()) as u64,
        files: vec![
            BinaryFileV1 {
                path: BINARY_PACKAGE_MANIFEST_PATH.to_owned(),
                sha256: sha256(&manifest_bytes),
                size: manifest_bytes.len() as u64,
                executable: false,
            },
            BinaryFileV1 {
                path: "bin/hello".to_owned(),
                sha256: sha256(payload),
                size: payload.len() as u64,
                executable: true,
            },
        ],
        entrypoints: manifest.bin.clone(),
        source: Some(BinarySourceProvenanceV1 {
            repository: manifest.package.repository.url.clone(),
            vcs_tag: manifest.vcs_tag(),
            vcs_commit: Some("0123456789abcdef".to_owned()),
        }),
    };
    let descriptor_bytes = descriptor
        .canonical_json_bytes()
        .expect("canonical descriptor");
    let epoch = zip::DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).expect("valid ZIP epoch");
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes, mode) in [
        (DESCRIPTOR, descriptor_bytes.as_slice(), 0o644),
        ("pkg/.zpkg.toml", manifest_bytes.as_slice(), 0o644),
        (PAYLOAD, payload.as_slice(), 0o755),
    ] {
        writer
            .start_file(
                name,
                SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Deflated)
                    .unix_permissions(mode)
                    .last_modified_time(epoch),
            )
            .expect("start fixture ZIP entry");
        writer.write_all(bytes).expect("write fixture ZIP entry");
    }
    let archive = writer.finish().expect("finish fixture ZIP").into_inner();
    let meta = PublishMeta {
        manifest,
        vcs_tag: "v1.2.3".to_owned(),
        vcs_commit: Some("0123456789abcdef".to_owned()),
        sha256: sha256(&archive),
        size: archive.len() as u64,
        format: ArtifactFormat::Zip,
        mirrors: Vec::new(),
        published_at: None,
        signatures: Vec::new(),
    };
    verify_publish(&meta, &archive)
        .expect("valid server fixture")
        .expect("binary descriptor detected");
    (meta, archive)
}

fn read_entries(bytes: &[u8]) -> Vec<Entry> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).expect("parse fixture ZIP");
    let mut entries = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).expect("open fixture entry");
        assert!(file.is_file(), "fixture should contain files only");
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("read fixture entry");
        entries.push(Entry {
            name: file.name().to_owned(),
            bytes: contents,
            mode: file.unix_mode().unwrap_or(0o644) & 0o777,
            compression: file.compression(),
        });
    }
    entries
}

fn write_entries(entries: &[Entry]) -> Vec<u8> {
    let epoch = zip::DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).expect("valid ZIP epoch");
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for entry in entries {
        writer
            .start_file(
                &entry.name,
                SimpleFileOptions::default()
                    .compression_method(entry.compression)
                    .unix_permissions(entry.mode)
                    .last_modified_time(epoch),
            )
            .expect("start mutated ZIP entry");
        writer
            .write_all(&entry.bytes)
            .expect("write mutated ZIP entry");
    }
    writer.finish().expect("finish mutated ZIP").into_inner()
}

fn mutate(mut mutation: impl FnMut(&mut Vec<Entry>)) -> (PublishMeta, Vec<u8>) {
    let (mut meta, valid) = valid_archive();
    let mut entries = read_entries(&valid);
    mutation(&mut entries);
    let archive = write_entries(&entries);
    meta.size = archive.len() as u64;
    meta.sha256 = sha256(&archive);
    (meta, archive)
}

fn rewrite_equal_length_filename(bytes: &mut [u8], from: &str, to: &str) {
    assert_eq!(
        from.len(),
        to.len(),
        "ZIP filename rewrite must be in place"
    );
    let from = from.as_bytes();
    let to = to.as_bytes();
    let mut replacements = 0usize;
    let mut offset = 0usize;
    while offset + from.len() <= bytes.len() {
        if &bytes[offset..offset + from.len()] == from {
            bytes[offset..offset + to.len()].copy_from_slice(to);
            replacements += 1;
            offset += to.len();
        } else {
            offset += 1;
        }
    }
    assert!(
        replacements >= 2,
        "expected to rewrite local and central ZIP filenames"
    );
}

fn duplicate_via_header_alias(original: &str, alias: &str) -> (PublishMeta, Vec<u8>) {
    let (mut meta, mut archive) = mutate(|entries| {
        let mut duplicate = entries
            .iter()
            .find(|entry| entry.name == original)
            .expect("entry to duplicate")
            .clone();
        duplicate.name = alias.to_owned();
        entries.push(duplicate);
    });
    rewrite_equal_length_filename(&mut archive, alias, original);
    meta.size = archive.len() as u64;
    meta.sha256 = sha256(&archive);
    (meta, archive)
}

fn rename_via_header_alias(
    original: &str,
    placeholder: &str,
    alias: &str,
) -> (PublishMeta, Vec<u8>) {
    let (mut meta, mut archive) = mutate(|entries| {
        entries
            .iter_mut()
            .find(|entry| entry.name == original)
            .expect("entry to rename")
            .name = placeholder.to_owned();
    });
    rewrite_equal_length_filename(&mut archive, placeholder, alias);
    meta.size = archive.len() as u64;
    meta.sha256 = sha256(&archive);
    (meta, archive)
}

fn descriptor(entries: &mut [Entry]) -> &mut Entry {
    entries
        .iter_mut()
        .find(|entry| entry.name == DESCRIPTOR)
        .expect("descriptor entry")
}

fn payload(entries: &mut [Entry]) -> &mut Entry {
    entries
        .iter_mut()
        .find(|entry| entry.name == PAYLOAD)
        .expect("payload entry")
}

fn assert_invalid_any(meta: &PublishMeta, archive: &[u8], expected: &[&str]) {
    let error = verify_publish(meta, archive)
        .expect_err("hostile binary upload must fail closed")
        .to_string();
    let normalized = error.to_ascii_lowercase();
    assert!(
        expected
            .iter()
            .any(|needle| normalized.contains(&needle.to_ascii_lowercase())),
        "expected error containing one of {expected:?}, got `{error}`"
    );
}

fn assert_invalid(meta: &PublishMeta, archive: &[u8], expected: &str) {
    assert_invalid_any(meta, archive, &[expected]);
}

#[test]
fn server_rejects_duplicate_descriptor_and_portable_aliases() {
    let (meta, archive) = duplicate_via_header_alias(DESCRIPTOR, "pkg/.zpkg-binary.js0n");
    assert_invalid_any(&meta, &archive, &["copies", "duplicate", "collide"]);

    let (meta, archive) = mutate(|entries| {
        descriptor(entries).name = "pkg/.ZPKG-BINARY.JSON".to_owned();
    });
    assert_invalid(&meta, &archive, "must be exactly");

    // ZipWriter normalizes backslashes before writing. Patch an equal-length
    // placeholder in both headers so this remains a genuinely hostile archive.
    let (meta, archive) = rename_via_header_alias(
        DESCRIPTOR,
        "pkg/.zpkg-binary.js0n",
        "pkg\\.zpkg-binary.json",
    );
    assert_invalid(&meta, &archive, "must be exactly");
}

#[test]
fn server_rejects_unlisted_missing_tampered_and_mode_mismatched_payloads() {
    let (meta, archive) = mutate(|entries| {
        entries.push(Entry {
            name: "pkg/share/unlisted.txt".to_owned(),
            bytes: b"not declared".to_vec(),
            mode: 0o644,
            compression: CompressionMethod::Deflated,
        });
    });
    assert_invalid(&meta, &archive, "unlisted payload");

    let (meta, archive) = mutate(|entries| {
        entries.retain(|entry| entry.name != PAYLOAD);
    });
    assert_invalid(&meta, &archive, "missing payload");

    let (meta, archive) = mutate(|entries| {
        payload(entries).bytes.extend_from_slice(b"tampered");
    });
    assert_invalid_any(&meta, &archive, &["mismatch", "descriptor-declared size"]);

    let (meta, archive) = mutate(|entries| {
        payload(entries).mode = 0o644;
    });
    assert_invalid(&meta, &archive, "executable mode");
}

#[test]
fn server_rejects_unsafe_and_portably_colliding_paths() {
    let cases = [
        ("pkg/../escape", "not beneath"),
        ("/pkg/escape", "canonically encoded"),
        ("outside.txt", "not beneath"),
        ("pkg\\escape", "canonically encoded"),
        ("pkg/BIN/hello", "collide"),
    ];
    for (name, expected) in cases {
        let (meta, archive) = mutate(|entries| {
            entries.push(Entry {
                name: name.to_owned(),
                bytes: b"hostile path".to_vec(),
                mode: 0o644,
                compression: CompressionMethod::Stored,
            });
        });
        assert_invalid(&meta, &archive, expected);
    }

    let (meta, archive) = duplicate_via_header_alias(PAYLOAD, "pkg/bin/hell0");
    assert_invalid_any(&meta, &archive, &["collide", "duplicate"]);
}

#[test]
fn server_rejects_host_filesystem_path_ambiguities() {
    let too_long = format!("pkg/{}", "a".repeat(256));
    let cases = [
        too_long.as_str(),
        "pkg/share/trailing.",
        "pkg/share/trailing ",
        "pkg/share/a?.txt",
        "pkg/share/stream:payload",
        "pkg/bin/NUL.txt",
        "pkg/bin/com9.exe",
    ];
    for name in cases {
        let (meta, archive) = mutate(|entries| {
            entries.push(Entry {
                name: name.to_owned(),
                bytes: b"hostile path".to_vec(),
                mode: 0o644,
                compression: CompressionMethod::Stored,
            });
        });
        assert_invalid(&meta, &archive, "invalid value");
    }

    let (meta, archive) = mutate(|entries| {
        for name in ["pkg/share/É.txt", "pkg/share/é.txt"] {
            entries.push(Entry {
                name: name.to_owned(),
                bytes: name.as_bytes().to_vec(),
                mode: 0o644,
                compression: CompressionMethod::Stored,
            });
        }
    });
    assert_invalid(&meta, &archive, "portable path rules");

    for names in [
        ["pkg/share", "pkg/share/tool"],
        ["pkg/share/tool", "pkg/share"],
    ] {
        let (meta, archive) = mutate(|entries| {
            for name in names {
                entries.push(Entry {
                    name: name.to_owned(),
                    bytes: name.as_bytes().to_vec(),
                    mode: 0o644,
                    compression: CompressionMethod::Stored,
                });
            }
        });
        assert_invalid(&meta, &archive, "ancestor");
    }

    let (meta, archive) = mutate(|entries| {
        entries.push(Entry {
            name: "pkg/share/".to_owned(),
            bytes: b"directories must not carry data".to_vec(),
            mode: 0o755,
            compression: CompressionMethod::Stored,
        });
    });
    assert_invalid(&meta, &archive, "directory entry");
}

#[test]
fn server_rejects_noncanonical_and_relationship_lying_descriptors() {
    let (meta, archive) = mutate(|entries| {
        let descriptor = descriptor(entries);
        let value: serde_json::Value =
            serde_json::from_slice(&descriptor.bytes).expect("parse descriptor");
        descriptor.bytes = serde_json::to_vec_pretty(&value).expect("pretty descriptor");
    });
    assert_invalid(&meta, &archive, "not canonical JSON");

    let (meta, archive) = mutate(|entries| {
        let descriptor = descriptor(entries);
        let mut value: serde_json::Value =
            serde_json::from_slice(&descriptor.bytes).expect("parse descriptor");
        value
            .as_object_mut()
            .expect("descriptor object")
            .insert("unexpected".to_owned(), serde_json::json!(true));
        descriptor.bytes = serde_json::to_vec(&value).expect("serialize descriptor");
    });
    assert_invalid(&meta, &archive, "unknown field");

    let (meta, archive) = mutate(|entries| {
        let descriptor = descriptor(entries);
        let mut value: serde_json::Value =
            serde_json::from_slice(&descriptor.bytes).expect("parse descriptor");
        let size = value["expanded_size"].as_u64().expect("expanded_size");
        value["expanded_size"] = serde_json::json!(size + 1);
        descriptor.bytes = serde_json::to_vec(&value).expect("serialize descriptor");
    });
    assert_invalid(&meta, &archive, "expanded_size");
}

fn patch_zip_headers(bytes: &mut [u8], mut patch: impl FnMut(&mut [u8], usize, bool)) {
    let mut patched = 0usize;
    for offset in 0..bytes.len().saturating_sub(4) {
        let signature = &bytes[offset..offset + 4];
        if signature == b"PK\x03\x04" {
            patch(bytes, offset, false);
            patched += 1;
        } else if signature == b"PK\x01\x02" {
            patch(bytes, offset, true);
            patched += 1;
        }
    }
    assert!(patched >= 2, "expected local and central ZIP headers");
}

fn inject_first_central_extra(bytes: &mut Vec<u8>, extra: &[u8]) -> usize {
    let eocd = bytes
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .expect("fixture EOCD");
    let central = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    assert_eq!(&bytes[central..central + 4], b"PK\x01\x02");
    let name_len =
        u16::from_le_bytes(bytes[central + 28..central + 30].try_into().unwrap()) as usize;
    let old_extra_len =
        u16::from_le_bytes(bytes[central + 30..central + 32].try_into().unwrap()) as usize;
    let new_extra_len = old_extra_len + extra.len();
    bytes[central + 30..central + 32]
        .copy_from_slice(&u16::try_from(new_extra_len).unwrap().to_le_bytes());
    let insertion = central + 46 + name_len + old_extra_len;
    bytes.splice(insertion..insertion, extra.iter().copied());

    let moved_eocd = eocd + extra.len();
    let old_central_size =
        u32::from_le_bytes(bytes[moved_eocd + 12..moved_eocd + 16].try_into().unwrap());
    bytes[moved_eocd + 12..moved_eocd + 16].copy_from_slice(
        &old_central_size
            .checked_add(u32::try_from(extra.len()).unwrap())
            .unwrap()
            .to_le_bytes(),
    );
    central
}

#[test]
fn server_rejects_data_descriptors_and_unnecessary_per_entry_zip64() {
    let (mut meta, mut archive) = valid_archive();
    patch_zip_headers(&mut archive, |bytes, offset, central| {
        let flag_offset = offset + if central { 8 } else { 6 };
        let flags = u16::from_le_bytes([bytes[flag_offset], bytes[flag_offset + 1]]) | 0x0008;
        bytes[flag_offset..flag_offset + 2].copy_from_slice(&flags.to_le_bytes());
    });
    meta.size = archive.len() as u64;
    meta.sha256 = sha256(&archive);
    assert_invalid(&meta, &archive, "data descriptors");

    let (mut meta, mut archive) = valid_archive();
    inject_first_central_extra(&mut archive, &[0x01, 0x00, 0x00, 0x00]);
    meta.size = archive.len() as u64;
    meta.sha256 = sha256(&archive);
    assert_invalid(&meta, &archive, "ZIP64 extra field");

    let (mut meta, mut archive) = valid_archive();
    let eocd = archive
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .unwrap();
    let central = u32::from_le_bytes(archive[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let expanded = u32::from_le_bytes(archive[central + 24..central + 28].try_into().unwrap());
    let mut zip64_extra = vec![0x01, 0x00, 0x08, 0x00];
    zip64_extra.extend_from_slice(&u64::from(expanded).to_le_bytes());
    let central = inject_first_central_extra(&mut archive, &zip64_extra);
    archive[central + 6..central + 8].copy_from_slice(&45_u16.to_le_bytes());
    archive[central + 24..central + 28].copy_from_slice(&u32::MAX.to_le_bytes());
    meta.size = archive.len() as u64;
    meta.sha256 = sha256(&archive);
    assert_invalid(&meta, &archive, "ZIP64 sentinel");
}

#[test]
fn server_rejects_encryption_unsupported_compression_and_ratio_bombs() {
    let (mut meta, mut archive) = valid_archive();
    patch_zip_headers(&mut archive, |bytes, offset, central| {
        let flag_offset = offset + if central { 8 } else { 6 };
        let flags = u16::from_le_bytes([bytes[flag_offset], bytes[flag_offset + 1]]) | 1;
        bytes[flag_offset..flag_offset + 2].copy_from_slice(&flags.to_le_bytes());
    });
    meta.size = archive.len() as u64;
    meta.sha256 = sha256(&archive);
    assert_invalid_any(
        &meta,
        &archive,
        &["encrypted", "password required", "decrypt"],
    );

    let (mut meta, mut archive) = valid_archive();
    patch_zip_headers(&mut archive, |bytes, offset, central| {
        let method_offset = offset + if central { 10 } else { 8 };
        bytes[method_offset..method_offset + 2].copy_from_slice(&12_u16.to_le_bytes());
    });
    meta.size = archive.len() as u64;
    meta.sha256 = sha256(&archive);
    assert_invalid_any(
        &meta,
        &archive,
        &[
            "unsupported compression",
            "compression method not supported",
        ],
    );

    let (meta, archive) = mutate(|entries| {
        entries.push(Entry {
            name: "pkg/share/high-ratio.bin".to_owned(),
            bytes: vec![0; 8 * 1024 * 1024],
            mode: 0o644,
            compression: CompressionMethod::Deflated,
        });
    });
    assert_invalid(&meta, &archive, "compression ratio");
}
