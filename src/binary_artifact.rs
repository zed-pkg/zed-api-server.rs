//! Server-side verification for self-describing native-binary ZIP uploads.
//!
//! The compatibility publish route still accepts ordinary source ZIPs. A ZIP
//! becomes a binary artifact only when it contains the reserved canonical
//! `pkg/.zpkg-binary.json` descriptor. Once that descriptor is present, the
//! complete `zpkg.binary-artifact/v1` profile is mandatory and is verified
//! before any VCS lookup, blob write, or metadata transaction.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Cursor, Read};

use sha2::{Digest, Sha256};
use zed_interfaces::artifact::ArtifactFormat;
use zed_interfaces::binary_artifact::{
    BINARY_ARCHIVE_ROOT, BINARY_DESCRIPTOR_PATH, BINARY_PACKAGE_MANIFEST_PATH,
    BinaryArtifactManifestV1, validate_safe_relative_path,
};
use zed_interfaces::manifest::Manifest;
use zed_interfaces::registry::PublishMeta;

const DEFAULT_MAX_BINARY_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_MAX_BINARY_EXPANDED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_MAX_BINARY_ENTRIES: usize = 200_000;
const DEFAULT_MAX_BINARY_COMPRESSION_RATIO: u64 = 1_000;
const MAX_DESCRIPTOR_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PACKAGE_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const BINARY_DESCRIPTOR_ARCHIVE_PATH: &str = "pkg/.zpkg-binary.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryArtifactError {
    message: String,
}

impl BinaryArtifactError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for BinaryArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BinaryArtifactError {}

type BinaryResult<T> = Result<T, BinaryArtifactError>;

/// Verify a ZIP when it opts into the reserved binary descriptor profile.
///
/// Ordinary source ZIPs return `Ok(None)`. A reserved descriptor spelling that
/// is malformed, duplicated, case-folded, or backslash-normalized is rejected
/// rather than treated as a source archive, preventing profile downgrade by
/// path ambiguity.
pub fn verify_publish(
    meta: &PublishMeta,
    archive_bytes: &[u8],
) -> BinaryResult<Option<BinaryArtifactManifestV1>> {
    if meta.format != ArtifactFormat::Zip {
        return Ok(None);
    }
    if archive_bytes.len() as u64 != meta.size {
        return Err(BinaryArtifactError::new(format!(
            "publish metadata declares {} bytes, but the upload contains {}",
            meta.size,
            archive_bytes.len()
        )));
    }

    match descriptor_presence(archive_bytes)? {
        DescriptorPresence::Absent => Ok(None),
        DescriptorPresence::Present => verify_binary_zip(meta, archive_bytes).map(Some),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DescriptorPresence {
    Absent,
    Present,
}

fn descriptor_presence(archive_bytes: &[u8]) -> BinaryResult<DescriptorPresence> {
    let archive = zip::ZipArchive::new(Cursor::new(archive_bytes))
        .map_err(|error| invalid(format!("invalid ZIP archive: {error}")))?;
    let mut offset = usize::try_from(archive.central_directory_start())
        .map_err(|_| invalid("ZIP central-directory offset does not fit usize"))?;
    let mut exact = 0_usize;
    let mut entries = 0_usize;
    let mut encoding_violation: Option<String> = None;

    // `ZipArchive` stores central-directory entries in a map keyed by raw
    // filename, so asking it to iterate silently hides duplicate names. Walk
    // the already-located central directory directly and compare its raw count
    // with the map's deduplicated length. This reads bounded headers only,
    // never inflates attacker content, and does not retain every hostile name.
    while archive_bytes.get(offset..offset.saturating_add(4)) == Some(b"PK\x01\x02") {
        const CENTRAL_HEADER_BYTES: usize = 46;
        let header = archive_bytes
            .get(offset..offset.saturating_add(CENTRAL_HEADER_BYTES))
            .ok_or_else(|| invalid("truncated ZIP central-directory header"))?;
        let name_len = usize::from(u16::from_le_bytes([header[28], header[29]]));
        let extra_len = usize::from(u16::from_le_bytes([header[30], header[31]]));
        let comment_len = usize::from(u16::from_le_bytes([header[32], header[33]]));
        let flags = u16::from_le_bytes([header[8], header[9]]);
        if flags & 0x0008 != 0 && encoding_violation.is_none() {
            encoding_violation = Some(
                "binary ZIP entries must not use general-purpose bit 3 data descriptors".to_owned(),
            );
        }
        let compressed_size = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
        let expanded_size = u32::from_le_bytes([header[24], header[25], header[26], header[27]]);
        let disk_start = u16::from_le_bytes([header[34], header[35]]);
        let local_header_offset =
            u32::from_le_bytes([header[42], header[43], header[44], header[45]]);
        if (compressed_size == u32::MAX
            || expanded_size == u32::MAX
            || disk_start == u16::MAX
            || local_header_offset == u32::MAX)
            && encoding_violation.is_none()
        {
            encoding_violation =
                Some("binary ZIP contains an unnecessary per-entry ZIP64 sentinel".to_owned());
        }
        let name_start = offset
            .checked_add(CENTRAL_HEADER_BYTES)
            .ok_or_else(|| invalid("ZIP central-directory offset overflow"))?;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(|| invalid("ZIP central-directory filename length overflow"))?;
        let raw = archive_bytes
            .get(name_start..name_end)
            .ok_or_else(|| invalid("truncated ZIP central-directory filename"))?;
        let extra_end = name_end
            .checked_add(extra_len)
            .ok_or_else(|| invalid("ZIP central-directory extra-field length overflow"))?;
        let extra = archive_bytes
            .get(name_end..extra_end)
            .ok_or_else(|| invalid("truncated ZIP central-directory extra field"))?;
        match contains_zip64_extra(extra) {
            Some(true) if encoding_violation.is_none() => {
                encoding_violation = Some(
                    "binary ZIP contains an unnecessary per-entry ZIP64 extra field".to_owned(),
                );
            }
            None if encoding_violation.is_none() => {
                encoding_violation = Some(
                    "binary ZIP contains a malformed central-directory extra field".to_owned(),
                );
            }
            Some(_) | None => {}
        }
        if raw == BINARY_DESCRIPTOR_ARCHIVE_PATH.as_bytes() {
            exact += 1;
        } else if let Ok(name) = std::str::from_utf8(raw)
            && normalized_archive_path(name).as_deref() == Some(BINARY_DESCRIPTOR_ARCHIVE_PATH)
        {
            return Err(invalid(format!(
                "reserved binary descriptor path must be exactly `{BINARY_DESCRIPTOR_ARCHIVE_PATH}`, got `{name}`"
            )));
        }

        entries = entries
            .checked_add(1)
            .ok_or_else(|| invalid("ZIP central-directory entry count overflow"))?;
        offset = extra_end
            .checked_add(comment_len)
            .ok_or_else(|| invalid("ZIP central-directory entry length overflow"))?;
        if offset > archive_bytes.len() {
            return Err(invalid("truncated ZIP central-directory entry"));
        }
    }
    if entries != archive.len() {
        return Err(invalid(format!(
            "ZIP central directory contains duplicate or inconsistently indexed entries: raw count {entries}, parser exposes {}",
            archive.len()
        )));
    }
    match exact {
        0 => Ok(DescriptorPresence::Absent),
        1 => {
            if let Some(message) = encoding_violation {
                Err(invalid(message))
            } else {
                Ok(DescriptorPresence::Present)
            }
        }
        count => Err(invalid(format!(
            "binary ZIP contains {count} copies of `{BINARY_DESCRIPTOR_ARCHIVE_PATH}`"
        ))),
    }
}

fn contains_zip64_extra(extra: &[u8]) -> Option<bool> {
    let mut offset = 0_usize;
    while offset < extra.len() {
        let header = extra.get(offset..offset.checked_add(4)?)?;
        let kind = u16::from_le_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let data_end = offset
            .checked_add(4)
            .and_then(|start| start.checked_add(len))?;
        if data_end > extra.len() {
            return None;
        }
        if kind == 0x0001 {
            return Some(true);
        }
        offset = data_end;
    }
    Some(false)
}

fn verify_binary_zip(
    meta: &PublishMeta,
    archive_bytes: &[u8],
) -> BinaryResult<BinaryArtifactManifestV1> {
    if archive_bytes.len() as u64 > max_binary_archive_bytes() {
        return Err(invalid(format!(
            "binary ZIP is {} bytes, above the {}-byte limit",
            archive_bytes.len(),
            max_binary_archive_bytes()
        )));
    }
    require_canonical_zip_magic(archive_bytes)?;

    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes))
        .map_err(|error| invalid(format!("invalid binary ZIP: {error}")))?;
    if archive
        .has_overlapping_files()
        .map_err(|error| invalid(format!("checking overlapping ZIP entries failed: {error}")))?
    {
        return Err(invalid(
            "binary ZIP contains overlapping file ranges; refusing",
        ));
    }
    if archive.len() > max_binary_entries() {
        return Err(invalid(format!(
            "binary ZIP has {} entries, above the {}-entry limit",
            archive.len(),
            max_binary_entries()
        )));
    }

    let mut regular_files = BTreeSet::<String>::new();
    let mut portable_paths = BTreeMap::<String, String>::new();
    let mut portable_regular_files = BTreeSet::<String>::new();
    let mut descriptor_bytes: Option<Vec<u8>> = None;
    let mut package_manifest_bytes: Option<Vec<u8>> = None;
    let mut expanded_total = 0_u64;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| invalid(format!("opening ZIP entry {index} failed: {error}")))?;
        let raw_name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| invalid(format!("ZIP entry {index} name is not UTF-8")))?;

        if entry.encrypted() {
            return Err(invalid(format!("ZIP entry `{raw_name}` is encrypted")));
        }
        if !matches!(
            entry.compression(),
            zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
        ) {
            return Err(invalid(format!(
                "ZIP entry `{raw_name}` uses unsupported compression {:?}",
                entry.compression()
            )));
        }
        if entry.is_symlink() {
            return Err(invalid(format!("ZIP entry `{raw_name}` is a symlink")));
        }
        if !entry.is_file() && !entry.is_dir() {
            return Err(invalid(format!(
                "ZIP entry `{raw_name}` is neither a regular file nor a directory"
            )));
        }
        if entry.is_dir() && entry.size() != 0 {
            return Err(invalid(format!(
                "ZIP directory entry `{raw_name}` carries {} bytes of data",
                entry.size()
            )));
        }
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170000;
            let allowed = kind == 0
                || (entry.is_file() && kind == 0o100000)
                || (entry.is_dir() && kind == 0o040000);
            if !allowed {
                return Err(invalid(format!(
                    "ZIP entry `{raw_name}` carries unsupported Unix file type {kind:o}"
                )));
            }
        }

        let enclosed = entry
            .enclosed_name()
            .ok_or_else(|| invalid(format!("ZIP entry `{raw_name}` escapes the archive root")))?;
        let normalized = enclosed.to_string_lossy().replace('\\', "/");
        if entry.is_dir() && normalized.trim_end_matches('/') == BINARY_ARCHIVE_ROOT {
            if raw_name != format!("{BINARY_ARCHIVE_ROOT}/") {
                return Err(invalid(format!(
                    "ZIP root directory `{raw_name}` is not canonically encoded"
                )));
            }
            continue;
        }

        let relative = normalized
            .strip_prefix(&format!("{BINARY_ARCHIVE_ROOT}/"))
            .ok_or_else(|| {
                invalid(format!(
                    "ZIP entry `{raw_name}` is not beneath `{BINARY_ARCHIVE_ROOT}/`"
                ))
            })?
            .trim_end_matches('/')
            .to_owned();
        validate_safe_relative_path("ZIP entry path", &relative)
            .map_err(|error| invalid(error.to_string()))?;
        let canonical_name = if entry.is_dir() {
            format!("{BINARY_ARCHIVE_ROOT}/{relative}/")
        } else {
            format!("{BINARY_ARCHIVE_ROOT}/{relative}")
        };
        if raw_name != canonical_name {
            return Err(invalid(format!(
                "ZIP entry `{raw_name}` is not canonically encoded as `{canonical_name}`"
            )));
        }

        let portable = portable_path_key(&relative);
        if let Some(existing) = portable_paths.get(&portable) {
            return Err(invalid(format!(
                "ZIP entries `{existing}` and `{relative}` collide under portable path rules"
            )));
        }
        for (separator, _) in portable.match_indices('/') {
            let ancestor = &portable[..separator];
            if let Some(existing) = portable_regular_files.get(ancestor) {
                return Err(invalid(format!(
                    "ZIP file `{existing}` is an ancestor of `{relative}`"
                )));
            }
        }
        if entry.is_file() {
            let descendant_prefix = format!("{portable}/");
            if let Some((_, existing)) = portable_paths
                .range(descendant_prefix.clone()..)
                .next()
                .filter(|(path, _)| path.starts_with(&descendant_prefix))
            {
                return Err(invalid(format!(
                    "ZIP file `{relative}` is an ancestor of `{existing}`"
                )));
            }
        }
        portable_paths.insert(portable.clone(), relative.clone());
        if entry.is_dir() {
            continue;
        }
        portable_regular_files.insert(portable);
        if !regular_files.insert(relative.clone()) {
            return Err(invalid(format!(
                "binary ZIP contains duplicate file `{relative}`"
            )));
        }

        enforce_compression_ratio(raw_name, entry.size(), entry.compressed_size())?;
        expanded_total = expanded_total
            .checked_add(entry.size())
            .ok_or_else(|| invalid("binary ZIP expanded size overflows u64"))?;
        if expanded_total > max_binary_expanded_bytes() {
            return Err(invalid(format!(
                "binary ZIP expands past the {}-byte limit",
                max_binary_expanded_bytes()
            )));
        }

        if relative == BINARY_DESCRIPTOR_PATH {
            if descriptor_bytes.is_some() {
                return Err(invalid("binary ZIP has multiple descriptors"));
            }
            descriptor_bytes = Some(read_small_entry(
                &mut entry,
                MAX_DESCRIPTOR_BYTES,
                BINARY_DESCRIPTOR_PATH,
            )?);
        } else if relative == BINARY_PACKAGE_MANIFEST_PATH {
            if package_manifest_bytes.is_some() {
                return Err(invalid("binary ZIP has multiple package manifests"));
            }
            package_manifest_bytes = Some(read_small_entry(
                &mut entry,
                MAX_PACKAGE_MANIFEST_BYTES,
                BINARY_PACKAGE_MANIFEST_PATH,
            )?);
        }
    }

    let descriptor_bytes = descriptor_bytes.ok_or_else(|| {
        invalid(format!(
            "binary ZIP is missing `{BINARY_DESCRIPTOR_ARCHIVE_PATH}`"
        ))
    })?;
    let descriptor: BinaryArtifactManifestV1 =
        serde_json::from_slice(&descriptor_bytes).map_err(|error| {
            invalid(format!(
                "parsing `{BINARY_DESCRIPTOR_ARCHIVE_PATH}` failed: {error}"
            ))
        })?;
    let package_manifest_bytes = package_manifest_bytes.ok_or_else(|| {
        invalid(format!(
            "binary ZIP is missing `pkg/{BINARY_PACKAGE_MANIFEST_PATH}`"
        ))
    })?;
    let package_manifest_text = std::str::from_utf8(&package_manifest_bytes)
        .map_err(|_| invalid("embedded `.zpkg.toml` is not UTF-8"))?;
    let embedded_manifest = Manifest::parse(package_manifest_text)
        .map_err(|error| invalid(format!("parsing embedded `.zpkg.toml` failed: {error}")))?;
    descriptor
        .validate_against_manifest(&embedded_manifest)
        .map_err(|error| invalid(error.to_string()))?;
    let canonical_descriptor = descriptor
        .canonical_json_bytes()
        .map_err(|error| invalid(error.to_string()))?;
    if descriptor_bytes != canonical_descriptor {
        return Err(invalid(format!(
            "`{BINARY_DESCRIPTOR_ARCHIVE_PATH}` is not canonical JSON"
        )));
    }
    if embedded_manifest != meta.manifest {
        return Err(invalid(
            "embedded `.zpkg.toml` does not exactly match publish metadata",
        ));
    }

    ensure_descriptor_matches_publish(&descriptor, meta)?;

    let descriptor_paths = descriptor
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    for archive_file in &regular_files {
        if archive_file == BINARY_DESCRIPTOR_PATH {
            continue;
        }
        if !descriptor_paths.contains(archive_file.as_str()) {
            return Err(invalid(format!(
                "binary ZIP contains unlisted payload file `{archive_file}`"
            )));
        }
    }
    for descriptor_file in &descriptor.files {
        if !regular_files.contains(&descriptor_file.path) {
            return Err(invalid(format!(
                "binary descriptor lists missing payload file `{}`",
                descriptor_file.path
            )));
        }
    }
    if descriptor.files.len().saturating_add(1) != regular_files.len() {
        return Err(invalid(
            "binary descriptor and archive payload counts differ",
        ));
    }

    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes))
        .map_err(|error| invalid(format!("reopening binary ZIP failed: {error}")))?;
    for expected in &descriptor.files {
        let archive_name = format!("{BINARY_ARCHIVE_ROOT}/{}", expected.path);
        let mut entry = archive.by_name(&archive_name).map_err(|error| {
            invalid(format!(
                "opening `{archive_name}` for integrity verification failed: {error}"
            ))
        })?;
        if let Some(mode) = entry.unix_mode() {
            let executable = mode & 0o111 != 0;
            if executable != expected.executable {
                return Err(invalid(format!(
                    "payload `{}` executable mode disagrees with `{BINARY_DESCRIPTOR_ARCHIVE_PATH}`",
                    expected.path
                )));
            }
        }
        let actual = hash_zip_entry(&mut entry, expected.size)?;
        if actual != expected.sha256 {
            return Err(invalid(format!(
                "payload digest mismatch for `{}`: expected {}, got {actual}",
                expected.path, expected.sha256
            )));
        }
    }

    Ok(descriptor)
}

fn ensure_descriptor_matches_publish(
    descriptor: &BinaryArtifactManifestV1,
    meta: &PublishMeta,
) -> BinaryResult<()> {
    let package = &meta.manifest.package;
    let source = descriptor.source.as_ref().ok_or_else(|| {
        invalid("binary publication requires source provenance in `.zpkg-binary.json`")
    })?;
    if source.repository != package.repository.url {
        return Err(invalid(
            "binary descriptor source repository does not match publish metadata",
        ));
    }
    if source.vcs_tag != meta.vcs_tag {
        return Err(invalid(
            "binary descriptor source tag does not match publish metadata",
        ));
    }
    if source.vcs_commit != meta.vcs_commit {
        return Err(invalid(
            "binary descriptor source commit does not match publish metadata",
        ));
    }
    Ok(())
}

fn read_small_entry<R: Read>(reader: &mut R, limit: u64, name: &str) -> BinaryResult<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| invalid(format!("reading `{name}` failed: {error}")))?;
    if bytes.len() as u64 > limit {
        return Err(invalid(format!(
            "ZIP entry `{name}` exceeds the {limit}-byte limit"
        )));
    }
    Ok(bytes)
}

fn hash_zip_entry<R: Read>(reader: &mut R, expected_size: u64) -> BinaryResult<String> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| invalid(format!("reading ZIP payload failed: {error}")))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| invalid("ZIP payload size overflows u64"))?;
        if size > expected_size {
            return Err(invalid("ZIP payload exceeds its descriptor-declared size"));
        }
        hasher.update(&buffer[..read]);
    }
    if size != expected_size {
        return Err(invalid(format!(
            "ZIP payload size mismatch: expected {expected_size}, got {size}"
        )));
    }
    Ok(hex::encode(hasher.finalize()))
}

fn require_canonical_zip_magic(archive_bytes: &[u8]) -> BinaryResult<()> {
    if archive_bytes.get(..4) != Some(b"PK\x03\x04") {
        return Err(invalid(
            "binary artifact is not a canonical ZIP; self-extracting prefixes are forbidden",
        ));
    }
    Ok(())
}

fn enforce_compression_ratio(name: &str, expanded: u64, compressed: u64) -> BinaryResult<()> {
    if expanded == 0 {
        return Ok(());
    }
    if compressed == 0 {
        return Err(invalid(format!(
            "ZIP entry `{name}` has zero compressed bytes"
        )));
    }
    let ratio = expanded.saturating_add(compressed - 1) / compressed;
    if ratio > max_binary_compression_ratio() {
        return Err(invalid(format!(
            "ZIP entry `{name}` has compression ratio {ratio}:1, above the {}:1 limit",
            max_binary_compression_ratio()
        )));
    }
    Ok(())
}

fn portable_path_key(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

/// Normalize only for detecting aliases of the reserved binary marker.
///
/// This is deliberately *not* used as an extraction path. ZIP producers and
/// host filesystems disagree about repeated separators, dot components,
/// backslashes, case, and trailing dots/spaces. If any of those spellings
/// resolve to the binary descriptor on a supported host, the upload has opted
/// into the binary profile and must either use the one canonical spelling or
/// fail closed. Otherwise an archive can bypass verification on one host and
/// materialize the reserved marker on another.
fn normalized_archive_path(path: &str) -> Option<String> {
    let portable = path.replace('\\', "/");
    let mut components = Vec::new();
    for raw in portable.split('/') {
        match raw {
            "" | "." => continue,
            ".." => {
                components.pop()?;
                continue;
            }
            _ => {}
        }

        // Win32 strips trailing dots and spaces from ordinary path
        // components. Treat those host aliases as reserved too.
        let component = raw.trim_end_matches(['.', ' ']);
        if component.is_empty() {
            continue;
        }
        components.push(component.to_lowercase());
    }
    Some(components.join("/"))
}

fn max_binary_archive_bytes() -> u64 {
    env_u64(
        "ZED_MAX_BINARY_ARCHIVE_BYTES",
        DEFAULT_MAX_BINARY_ARCHIVE_BYTES,
    )
}

fn max_binary_expanded_bytes() -> u64 {
    env_u64(
        "ZED_MAX_BINARY_EXPANDED_BYTES",
        DEFAULT_MAX_BINARY_EXPANDED_BYTES,
    )
}

fn max_binary_entries() -> usize {
    bounded_usize_override(
        std::env::var("ZED_MAX_BINARY_ENTRIES").ok().as_deref(),
        DEFAULT_MAX_BINARY_ENTRIES,
    )
}

fn max_binary_compression_ratio() -> u64 {
    env_u64(
        "ZED_MAX_BINARY_COMPRESSION_RATIO",
        DEFAULT_MAX_BINARY_COMPRESSION_RATIO,
    )
}

fn env_u64(name: &str, ceiling: u64) -> u64 {
    bounded_u64_override(std::env::var(name).ok().as_deref(), ceiling)
}

fn bounded_u64_override(value: Option<&str>, ceiling: u64) -> u64 {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map_or(ceiling, |value| value.min(ceiling))
}

fn bounded_usize_override(value: Option<&str>, ceiling: usize) -> usize {
    value
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map_or(ceiling, |value| value.min(ceiling))
}

fn invalid(message: impl Into<String>) -> BinaryArtifactError {
    BinaryArtifactError::new(message)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use zed_interfaces::binary_artifact::{
        BINARY_ARTIFACT_SCHEMA_V1, BinaryArchiveFormatV1, BinaryFileV1, BinaryPackageIdentityV1,
        BinaryPlatformV1, BinarySourceProvenanceV1,
    };

    fn manifest() -> Manifest {
        Manifest::parse(
            r#"[package]
org = "acme"
name = "hello-bin"
version = "1.2.3"
description = "test binary"
license = "MIT"

[package.repository]
vcs = "git"
url = "https://github.com/acme/hello-bin"

[bin]
hello = "bin/hello"
"#,
        )
        .unwrap()
    }

    fn sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn binary_archive(payload: &[u8], descriptor_payload: &[u8]) -> (PublishMeta, Vec<u8>) {
        let manifest = manifest();
        let manifest_bytes = manifest.to_toml_string().unwrap().into_bytes();
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
            expanded_size: (manifest_bytes.len() + descriptor_payload.len()) as u64,
            files: vec![
                BinaryFileV1 {
                    path: BINARY_PACKAGE_MANIFEST_PATH.to_owned(),
                    sha256: sha256(&manifest_bytes),
                    size: manifest_bytes.len() as u64,
                    executable: false,
                },
                BinaryFileV1 {
                    path: "bin/hello".to_owned(),
                    sha256: sha256(descriptor_payload),
                    size: descriptor_payload.len() as u64,
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
        let descriptor_bytes = descriptor.canonical_json_bytes().unwrap();
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let epoch = zip::DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).unwrap();
        writer
            .start_file(
                BINARY_DESCRIPTOR_ARCHIVE_PATH,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .unix_permissions(0o644)
                    .last_modified_time(epoch),
            )
            .unwrap();
        writer.write_all(&descriptor_bytes).unwrap();
        writer
            .start_file(
                "pkg/.zpkg.toml",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .unix_permissions(0o644)
                    .last_modified_time(epoch),
            )
            .unwrap();
        writer.write_all(&manifest_bytes).unwrap();
        writer
            .start_file(
                "pkg/bin/hello",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .unix_permissions(0o755)
                    .last_modified_time(epoch),
            )
            .unwrap();
        writer.write_all(payload).unwrap();
        let archive = writer.finish().unwrap().into_inner();
        let meta = PublishMeta {
            manifest,
            vcs_tag: "v1.2.3".to_owned(),
            vcs_commit: Some("0123456789abcdef".to_owned()),
            sha256: sha256(&archive),
            size: archive.len() as u64,
            format: ArtifactFormat::Zip,
        };
        (meta, archive)
    }

    fn generic_zip() -> (PublishMeta, Vec<u8>) {
        let manifest = manifest();
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("pkg/source.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"source").unwrap();
        let archive = writer.finish().unwrap().into_inner();
        let meta = PublishMeta {
            manifest,
            vcs_tag: "v1.2.3".to_owned(),
            vcs_commit: None,
            sha256: sha256(&archive),
            size: archive.len() as u64,
            format: ArtifactFormat::Zip,
        };
        (meta, archive)
    }

    #[test]
    fn verifies_a_self_describing_binary_upload() {
        let (meta, archive) = binary_archive(b"hello binary\n", b"hello binary\n");
        let descriptor = verify_publish(&meta, &archive).unwrap().unwrap();
        assert_eq!(descriptor.platform.target, "x86_64-unknown-linux-gnu");
        assert_eq!(descriptor.entrypoints["hello"], "bin/hello");
    }

    #[test]
    fn ordinary_source_zip_remains_compatible() {
        let (meta, archive) = generic_zip();
        assert!(verify_publish(&meta, &archive).unwrap().is_none());
    }

    #[test]
    fn binary_limit_overrides_can_only_lower_v1_ceilings() {
        assert_eq!(bounded_u64_override(None, 1_000), 1_000);
        assert_eq!(bounded_u64_override(Some("invalid"), 1_000), 1_000);
        assert_eq!(bounded_u64_override(Some("0"), 1_000), 1_000);
        assert_eq!(bounded_u64_override(Some("250"), 1_000), 250);
        assert_eq!(bounded_u64_override(Some("1001"), 1_000), 1_000);

        assert_eq!(bounded_usize_override(None, 200_000), 200_000);
        assert_eq!(bounded_usize_override(Some("1000"), 200_000), 1_000);
        assert_eq!(bounded_usize_override(Some("200001"), 200_000), 200_000);
    }

    #[test]
    fn rejects_payload_bytes_that_disagree_with_the_descriptor() {
        let (meta, archive) = binary_archive(b"tampered\n", b"hello binary\n");
        let error = verify_publish(&meta, &archive).unwrap_err().to_string();
        assert!(error.contains("size mismatch") || error.contains("digest mismatch"));
    }

    #[test]
    fn rejects_reserved_descriptor_case_folding() {
        let manifest = manifest();
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "pkg/.ZPKG-BINARY.JSON",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(b"{}").unwrap();
        let archive = writer.finish().unwrap().into_inner();
        let meta = PublishMeta {
            manifest,
            vcs_tag: "v1.2.3".to_owned(),
            vcs_commit: None,
            sha256: sha256(&archive),
            size: archive.len() as u64,
            format: ArtifactFormat::Zip,
        };
        assert!(
            verify_publish(&meta, &archive)
                .unwrap_err()
                .to_string()
                .contains("must be exactly")
        );
    }

    #[test]
    fn rejects_reserved_descriptor_path_aliases() {
        for alias in [
            "./pkg/.zpkg-binary.json",
            "/pkg/.zpkg-binary.json",
            "pkg//.zpkg-binary.json",
            "pkg/./.zpkg-binary.json",
            "pkg/staging/../.zpkg-binary.json",
            "pkg/.zpKg-binary.json",
            "pkg/.zpkg-binary.json.",
            "pkg/.zpkg-binary.json ",
        ] {
            let manifest = manifest();
            let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
            writer
                .start_file(alias, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"{}").unwrap();
            let archive = writer.finish().unwrap().into_inner();
            let meta = PublishMeta {
                manifest,
                vcs_tag: "v1.2.3".to_owned(),
                vcs_commit: None,
                sha256: sha256(&archive),
                size: archive.len() as u64,
                format: ArtifactFormat::Zip,
            };
            let error = verify_publish(&meta, &archive).unwrap_err().to_string();
            assert!(
                error.contains("must be exactly"),
                "alias `{alias}` unexpectedly produced `{error}`"
            );
        }
    }

    #[test]
    fn rejects_self_extracting_binary_prefix() {
        let (mut meta, archive) = binary_archive(b"hello binary\n", b"hello binary\n");
        let mut prefixed = b"MZ".to_vec();
        prefixed.extend(archive);
        meta.size = prefixed.len() as u64;
        meta.sha256 = sha256(&prefixed);
        assert!(
            verify_publish(&meta, &prefixed)
                .unwrap_err()
                .to_string()
                .contains("self-extracting")
        );
    }
}
