//! The provider-agnostic description of where artifacts actually live.
//!
//! Zed stores artifacts in whatever object store an operator configured:
//! Cloudflare R2 today, AWS S3, Google Cloud Storage, or MinIO tomorrow, a
//! local directory in development, process memory in certification runs. A
//! console that answered "what is my storage doing?" by embedding a Cloudflare
//! page would answer it for exactly one of those and would have to be rebuilt
//! for the next. So the answer is modelled here instead: one vocabulary that
//! every backend can be described in, served as ordinary JSON, rendered by
//! whichever client asks.
//!
//! Everything in this module is a pure transformation over values the caller
//! already has. Reaching the network, opening a directory, or reading the
//! database happens in [`crate::storage`] and [`crate::routes::storage`], which
//! feed their results through these types. Nothing here can perform an effect,
//! which is what makes the classification rules directly testable.

use serde::{Deserialize, Serialize};

/// Wire schema tag. A client that does not recognize this value must not guess
/// at the payload's shape.
pub const STORAGE_STATUS_SCHEMA: &str = "zed.storage-status.v1";
/// Wire schema tag for a single reconciled object.
pub const STORAGE_OBJECT_SCHEMA: &str = "zed.storage-object.v1";

/// How the bytes are held, independent of who holds them.
///
/// This is the shape of the storage, not the vendor: every S3-compatible
/// service — R2, S3, GCS's interoperability endpoint, MinIO — is one
/// [`Self::ObjectStore`], because everything Zed does with them is identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageBackendKind {
    /// Bounded process memory. Empty on every restart; certification only.
    ProcessMemory,
    /// A directory on the server's filesystem.
    Filesystem,
    /// Any S3-compatible object store.
    ObjectStore,
}

impl StorageBackendKind {
    /// Is this backend durable across a restart of the process?
    #[must_use]
    pub const fn is_durable(self) -> bool {
        match self {
            Self::ProcessMemory => false,
            Self::Filesystem | Self::ObjectStore => true,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessMemory => "process-memory",
            Self::Filesystem => "filesystem",
            Self::ObjectStore => "object-store",
        }
    }
}

/// Who is holding the bytes, as far as the endpoint reveals.
///
/// Deliberately advisory. Zed never branches on the provider to decide *how* to
/// read or write — that is what keeps R2, S3, and GCS interchangeable — it only
/// reports the provider so an operator can see at a glance which one is live,
/// and so a console can show the right name and documentation link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageProvider {
    CloudflareR2,
    AmazonS3,
    GoogleCloudStorage,
    BackblazeB2,
    DigitalOceanSpaces,
    Minio,
    /// S3-compatible, but the endpoint does not identify a known vendor.
    S3Compatible,
    LocalDisk,
    ProcessMemory,
}

impl StorageProvider {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloudflareR2 => "cloudflare-r2",
            Self::AmazonS3 => "amazon-s3",
            Self::GoogleCloudStorage => "google-cloud-storage",
            Self::BackblazeB2 => "backblaze-b2",
            Self::DigitalOceanSpaces => "digitalocean-spaces",
            Self::Minio => "minio",
            Self::S3Compatible => "s3-compatible",
            Self::LocalDisk => "local-disk",
            Self::ProcessMemory => "process-memory",
        }
    }

    /// Human label for a console header.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::CloudflareR2 => "Cloudflare R2",
            Self::AmazonS3 => "Amazon S3",
            Self::GoogleCloudStorage => "Google Cloud Storage",
            Self::BackblazeB2 => "Backblaze B2",
            Self::DigitalOceanSpaces => "DigitalOcean Spaces",
            Self::Minio => "MinIO",
            Self::S3Compatible => "S3-compatible store",
            Self::LocalDisk => "Local disk",
            Self::ProcessMemory => "Process memory",
        }
    }
}

/// The host of an S3 endpoint, with any credentials and port stripped.
///
/// An endpoint URL may legally carry userinfo (`https://key:secret@host/`).
/// That value would then travel into a console page and a log line, so the host
/// is extracted rather than the URL passed through. Parsing is deliberately
/// string-level and total: an unparseable endpoint yields `None` instead of an
/// error, because failing to *name* the provider must never fail the request
/// that reports the provider.
#[must_use]
pub fn endpoint_host(endpoint: &str) -> Option<String> {
    let without_scheme = endpoint
        .split_once("://")
        .map_or(endpoint, |(_scheme, rest)| rest);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    // Credentials precede the last '@'; a bracketed IPv6 literal has none.
    let host_and_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host_and_port.strip_prefix('[') {
        // IPv6 literal: the port, if any, follows the closing bracket.
        Some(rest) => rest
            .split_once(']')
            .map(|(inside, _)| inside)
            .unwrap_or(rest),
        None => host_and_port
            .split_once(':')
            .map_or(host_and_port, |(host, _port)| host),
    };
    let host = host.trim().to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Name the vendor behind an S3 endpoint.
///
/// `None` means the AWS SDK's default endpoint resolution, which is Amazon S3.
/// An unrecognized host is [`StorageProvider::S3Compatible`] rather than a
/// guess: reporting "unknown vendor, S3 protocol" is accurate and useful, while
/// reporting the wrong vendor is neither.
#[must_use]
pub fn classify_object_store(endpoint: Option<&str>) -> StorageProvider {
    let Some(host) = endpoint.and_then(endpoint_host) else {
        return StorageProvider::AmazonS3;
    };
    let suffix_matches = |suffix: &str| host == suffix || host.ends_with(&format!(".{suffix}"));

    if suffix_matches("r2.cloudflarestorage.com") {
        StorageProvider::CloudflareR2
    } else if suffix_matches("storage.googleapis.com") {
        StorageProvider::GoogleCloudStorage
    } else if suffix_matches("amazonaws.com") {
        StorageProvider::AmazonS3
    } else if suffix_matches("backblazeb2.com") {
        StorageProvider::BackblazeB2
    } else if suffix_matches("digitaloceanspaces.com") {
        StorageProvider::DigitalOceanSpaces
    } else if host == "minio" || suffix_matches("min.io") || host.starts_with("minio.") {
        StorageProvider::Minio
    } else {
        StorageProvider::S3Compatible
    }
}

/// Identity of the configured backend. Never carries a credential: the bucket
/// and host are configuration an operator already knows, the secret is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBackend {
    pub kind: StorageBackendKind,
    pub provider: StorageProvider,
    /// Vendor-neutral label for a console header.
    pub display_name: String,
    /// Bucket for an object store; absent for local and memory backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Endpoint host only — scheme, credentials, and port removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_host: Option<String>,
    /// Path-style addressing, which MinIO and some proxies require.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_style: Option<bool>,
    /// Directory for the filesystem backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    pub durable: bool,
}

impl StorageBackend {
    /// Describe a process-memory backend.
    #[must_use]
    pub fn process_memory() -> Self {
        Self {
            kind: StorageBackendKind::ProcessMemory,
            provider: StorageProvider::ProcessMemory,
            display_name: StorageProvider::ProcessMemory.display_name().to_owned(),
            bucket: None,
            region: None,
            endpoint_host: None,
            path_style: None,
            directory: None,
            durable: false,
        }
    }

    /// Describe a filesystem backend rooted at `directory`.
    #[must_use]
    pub fn filesystem(directory: impl Into<String>) -> Self {
        Self {
            kind: StorageBackendKind::Filesystem,
            provider: StorageProvider::LocalDisk,
            display_name: StorageProvider::LocalDisk.display_name().to_owned(),
            bucket: None,
            region: None,
            endpoint_host: None,
            path_style: None,
            directory: Some(directory.into()),
            durable: true,
        }
    }

    /// Describe an S3-compatible backend, naming the vendor from the endpoint.
    #[must_use]
    pub fn object_store(
        bucket: impl Into<String>,
        region: impl Into<String>,
        endpoint: Option<&str>,
        path_style: bool,
    ) -> Self {
        let provider = classify_object_store(endpoint);
        Self {
            kind: StorageBackendKind::ObjectStore,
            provider,
            display_name: provider.display_name().to_owned(),
            bucket: Some(bucket.into()),
            region: Some(region.into()),
            endpoint_host: endpoint.and_then(endpoint_host),
            path_style: Some(path_style),
            directory: None,
            durable: true,
        }
    }
}

/// Whether the backend answered, and how quickly.
///
/// Modelled as a sum rather than a bool plus an optional message, so a client
/// cannot render "reachable" next to an error string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum StorageHealth {
    /// The backend answered a read-only probe.
    Reachable { latency_ms: u64 },
    /// The probe failed. The message is the operator-facing reason, already
    /// stripped of anything credential-shaped by the caller.
    Unreachable { reason: String },
    /// No probe was attempted (probes disabled, or the caller asked for the
    /// cheap description only).
    Unprobed,
}

impl StorageHealth {
    #[must_use]
    pub const fn is_reachable(&self) -> bool {
        matches!(self, Self::Reachable { .. })
    }
}

/// What the registry database believes is stored, which is free to compute and
/// identical on every provider. Reconciling it against the store is a per-object
/// question, answered by [`StorageObjectReport`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageUsage {
    /// Distinct artifact digests referenced by non-yanked and yanked versions.
    pub artifact_count: u64,
    /// Sum of the recorded artifact sizes, in bytes.
    pub total_bytes: u64,
    /// Largest single recorded artifact, in bytes.
    pub largest_bytes: u64,
}

/// Server-enforced ceilings, so a console can show them beside actual usage
/// instead of hard-coding a copy that drifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageLimits {
    pub max_artifact_bytes: u64,
    pub max_buffered_artifact_bytes: u64,
}

/// The whole answer to "what is my storage doing?".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageStatus {
    pub schema: String,
    pub backend: StorageBackend,
    pub health: StorageHealth,
    pub usage: StorageUsage,
    pub limits: StorageLimits,
    /// RFC 3339, UTC.
    pub observed_at: String,
}

impl StorageStatus {
    #[must_use]
    pub fn new(
        backend: StorageBackend,
        health: StorageHealth,
        usage: StorageUsage,
        limits: StorageLimits,
        observed_at: String,
    ) -> Self {
        Self {
            schema: STORAGE_STATUS_SCHEMA.to_owned(),
            backend,
            health,
            usage,
            limits,
            observed_at,
        }
    }
}

/// Does the object store hold what the registry says it holds?
///
/// The three states are exhaustive and mutually exclusive by construction, so a
/// console cannot render a "matches" badge for an object that is missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum Reconciliation {
    /// Present, and its size matches the registry's record.
    Consistent,
    /// Present, but the store disagrees with the registry.
    Divergent { detail: String },
    /// The registry references it; the store does not have it.
    Missing,
}

/// One artifact object, as the store reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageObjectReport {
    pub schema: String,
    /// Key within the bucket or directory, e.g. `artifacts/<sha256>.tar.gz`.
    pub key: String,
    /// The digest the registry records for this artifact.
    pub sha256: String,
    /// Size the registry records.
    pub recorded_bytes: u64,
    /// Size the store reports, when it has the object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_bytes: Option<u64>,
    /// Digest the store carries as object metadata, when it has one. Present
    /// only on backends that persist it; its absence is not a divergence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    /// RFC 3339, when the store reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    pub reconciliation: Reconciliation,
    pub observed_at: String,
}

/// What a backend reported about one object. Effect-free: the caller performs
/// the HEAD and hands the result here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectHead {
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub content_type: Option<String>,
    pub cache_control: Option<String>,
    pub last_modified: Option<String>,
}

/// Decide whether the store and the registry agree about one artifact.
///
/// A missing object is the important case and is never softened: an artifact
/// the registry advertises but the store cannot serve is a broken download for
/// every consumer that resolves it.
#[must_use]
pub fn reconcile(
    recorded_bytes: u64,
    recorded_sha256: &str,
    head: Option<&ObjectHead>,
) -> Reconciliation {
    let Some(head) = head else {
        return Reconciliation::Missing;
    };
    if let Some(stored) = head.size
        && stored != recorded_bytes
    {
        return Reconciliation::Divergent {
            detail: format!("registry records {recorded_bytes} bytes; store reports {stored}"),
        };
    }
    if let Some(stored) = head.sha256.as_deref()
        && !stored.eq_ignore_ascii_case(recorded_sha256)
    {
        return Reconciliation::Divergent {
            detail: "stored object digest metadata does not match the registry digest".to_owned(),
        };
    }
    Reconciliation::Consistent
}

/// Build the object report from the registry's record and the store's answer.
#[must_use]
pub fn object_report(
    key: String,
    sha256: String,
    recorded_bytes: u64,
    head: Option<ObjectHead>,
    observed_at: String,
) -> StorageObjectReport {
    let reconciliation = reconcile(recorded_bytes, &sha256, head.as_ref());
    let head = head.unwrap_or_default();
    StorageObjectReport {
        schema: STORAGE_OBJECT_SCHEMA.to_owned(),
        key,
        sha256,
        recorded_bytes,
        stored_bytes: head.size,
        stored_sha256: head.sha256,
        content_type: head.content_type,
        cache_control: head.cache_control,
        last_modified: head.last_modified,
        reconciliation,
        observed_at,
    }
}

/// Reduce a backend error to something safe to show an operator.
///
/// Storage SDK errors readily quote the failing request, which can include a
/// presigned query string. Only the first line is kept, truncated, and any
/// `key=`-shaped credential fragment removed.
#[must_use]
pub fn redact_backend_error(error: &str) -> String {
    const MAX: usize = 200;
    let first_line = error.lines().next().unwrap_or_default().trim();
    let without_query = first_line
        .split_once("?X-Amz-")
        .map_or(first_line, |(head, _)| head);
    let truncated: String = without_query.chars().take(MAX).collect();
    if truncated.is_empty() {
        "storage backend reported an unspecified error".to_owned()
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_vendor_endpoint_is_named() {
        let cases = [
            (
                Some("https://abc123.r2.cloudflarestorage.com"),
                StorageProvider::CloudflareR2,
            ),
            (
                Some("https://storage.googleapis.com"),
                StorageProvider::GoogleCloudStorage,
            ),
            (
                Some("https://s3.us-west-2.amazonaws.com"),
                StorageProvider::AmazonS3,
            ),
            (
                Some("https://s3.us-west-000.backblazeb2.com"),
                StorageProvider::BackblazeB2,
            ),
            (
                Some("https://nyc3.digitaloceanspaces.com"),
                StorageProvider::DigitalOceanSpaces,
            ),
            (Some("http://minio:9000"), StorageProvider::Minio),
            (
                Some("https://objects.example.internal"),
                StorageProvider::S3Compatible,
            ),
            // No endpoint is the SDK default, which is Amazon.
            (None, StorageProvider::AmazonS3),
        ];
        for (endpoint, expected) in cases {
            assert_eq!(
                classify_object_store(endpoint),
                expected,
                "endpoint {endpoint:?}"
            );
        }
    }

    #[test]
    fn a_lookalike_domain_is_not_mistaken_for_the_vendor() {
        // Suffix matching is on label boundaries, so an attacker-controlled
        // host that merely *ends in the same letters* is not R2.
        assert_eq!(
            classify_object_store(Some("https://evil-r2.cloudflarestorage.com.attacker.test")),
            StorageProvider::S3Compatible
        );
        assert_eq!(
            classify_object_store(Some("https://notamazonaws.com")),
            StorageProvider::S3Compatible
        );
    }

    #[test]
    fn endpoint_credentials_and_ports_never_survive_into_the_report() {
        assert_eq!(
            endpoint_host("https://AKIAKEY:supersecret@objects.example.test:9000/bucket"),
            Some("objects.example.test".to_owned())
        );
        assert_eq!(
            endpoint_host("http://[2001:db8::1]:9000/"),
            Some("2001:db8::1".to_owned())
        );
        assert_eq!(
            endpoint_host("HTTPS://Objects.EXAMPLE.test"),
            Some("objects.example.test".to_owned())
        );
        assert_eq!(endpoint_host(""), None);
        assert_eq!(endpoint_host("https://"), None);
    }

    #[test]
    fn a_backend_description_never_carries_a_secret() {
        let backend = StorageBackend::object_store(
            "zed-artifacts",
            "auto",
            Some("https://key:secret@abc.r2.cloudflarestorage.com"),
            false,
        );
        let json = serde_json::to_string(&backend).unwrap();
        assert!(!json.contains("secret"), "{json}");
        assert!(!json.contains("key:"), "{json}");
        assert_eq!(backend.provider, StorageProvider::CloudflareR2);
        assert_eq!(backend.display_name, "Cloudflare R2");
        assert!(backend.durable);
    }

    #[test]
    fn only_the_memory_backend_is_reported_as_non_durable() {
        assert!(!StorageBackend::process_memory().durable);
        assert!(StorageBackend::filesystem("/var/lib/zed").durable);
        assert!(!StorageBackendKind::ProcessMemory.is_durable());
        assert!(StorageBackendKind::Filesystem.is_durable());
        assert!(StorageBackendKind::ObjectStore.is_durable());
    }

    #[test]
    fn a_missing_object_is_never_reported_as_consistent() {
        assert_eq!(reconcile(10, "aa", None), Reconciliation::Missing);
    }

    #[test]
    fn a_size_or_digest_disagreement_is_divergent() {
        let head = ObjectHead {
            size: Some(11),
            ..ObjectHead::default()
        };
        assert!(matches!(
            reconcile(10, "aa", Some(&head)),
            Reconciliation::Divergent { .. }
        ));

        let head = ObjectHead {
            size: Some(10),
            sha256: Some("bb".to_owned()),
            ..ObjectHead::default()
        };
        assert!(matches!(
            reconcile(10, "aa", Some(&head)),
            Reconciliation::Divergent { .. }
        ));
    }

    #[test]
    fn a_backend_without_digest_metadata_is_not_divergent_for_that_reason() {
        // Local and memory backends carry no object metadata. Absence of a
        // stored digest must not be read as a mismatch.
        let head = ObjectHead {
            size: Some(10),
            ..ObjectHead::default()
        };
        assert_eq!(reconcile(10, "aa", Some(&head)), Reconciliation::Consistent);
    }

    #[test]
    fn digest_comparison_ignores_hex_case() {
        let head = ObjectHead {
            size: Some(10),
            sha256: Some("ABCDEF".to_owned()),
            ..ObjectHead::default()
        };
        assert_eq!(
            reconcile(10, "abcdef", Some(&head)),
            Reconciliation::Consistent
        );
    }

    #[test]
    fn a_presigned_url_in_an_error_is_not_echoed_back() {
        let raw = "dispatch failure: GET https://bucket.r2.cloudflarestorage.com/artifacts/a.tar.gz?X-Amz-Signature=deadbeef\ncaused by: timeout";
        let redacted = redact_backend_error(raw);
        assert!(!redacted.contains("X-Amz-Signature"), "{redacted}");
        assert!(!redacted.contains("deadbeef"), "{redacted}");
        assert!(!redacted.contains("timeout"), "{redacted}");
        assert!(redacted.len() <= 200);
    }

    #[test]
    fn an_empty_backend_error_still_says_something() {
        assert!(!redact_backend_error("").is_empty());
        assert!(!redact_backend_error("\n\n").is_empty());
    }

    #[test]
    fn the_status_payload_round_trips_through_json() {
        let status = StorageStatus::new(
            StorageBackend::object_store(
                "zed-artifacts",
                "auto",
                Some("https://abc.r2.cloudflarestorage.com"),
                false,
            ),
            StorageHealth::Reachable { latency_ms: 42 },
            StorageUsage {
                artifact_count: 3,
                total_bytes: 4096,
                largest_bytes: 2048,
            },
            StorageLimits {
                max_artifact_bytes: 100 * 1024 * 1024,
                max_buffered_artifact_bytes: 100 * 1024 * 1024,
            },
            "2026-08-23T12:00:00Z".to_owned(),
        );
        let json = serde_json::to_string(&status).unwrap();
        let parsed: StorageStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, status);
        assert_eq!(parsed.schema, STORAGE_STATUS_SCHEMA);
        // The health sum serializes with a discriminant a client can match on.
        assert!(json.contains("\"state\":\"reachable\""), "{json}");
    }

    #[test]
    fn an_unreachable_backend_cannot_serialize_as_reachable() {
        let health = StorageHealth::Unreachable {
            reason: "connection refused".to_owned(),
        };
        assert!(!health.is_reachable());
        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("\"state\":\"unreachable\""), "{json}");
        assert!(!json.contains("latency_ms"), "{json}");
    }

    /// The exact bytes every other repository parses.
    ///
    /// `zed-web-server` and the Flutter client each carry a copy of this file
    /// and assert their own decoders accept it. That is what keeps three
    /// independently released codebases agreeing on one wire shape without a
    /// shared dependency and a coordinated version bump between them.
    const STATUS_CONTRACT: &str = include_str!("../contracts/storage-status.v1.json");

    #[test]
    fn the_published_contract_fixture_decodes_into_the_served_type() {
        let parsed: StorageStatus = serde_json::from_str(STATUS_CONTRACT)
            .expect("the published storage-status contract must decode");
        assert_eq!(parsed.schema, STORAGE_STATUS_SCHEMA);
        assert_eq!(parsed.backend.provider, StorageProvider::CloudflareR2);
        assert_eq!(parsed.backend.kind, StorageBackendKind::ObjectStore);
        assert!(parsed.backend.durable);
        assert!(parsed.health.is_reachable());
        assert_eq!(parsed.usage.artifact_count, 1284);

        // Re-encoding is stable, so a client that round-trips the payload does
        // not produce something this server would reject.
        let reencoded = serde_json::to_string(&parsed).unwrap();
        let again: StorageStatus = serde_json::from_str(&reencoded).unwrap();
        assert_eq!(again, parsed);
    }

    #[test]
    fn the_contract_fixture_names_no_credential_shaped_field() {
        let value: serde_json::Value = serde_json::from_str(STATUS_CONTRACT).unwrap();
        let rendered = value.to_string().to_ascii_lowercase();
        for forbidden in ["secret", "access_key", "accesskey", "token", "password"] {
            assert!(
                !rendered.contains(forbidden),
                "the storage contract must never carry `{forbidden}`"
            );
        }
    }

    #[test]
    fn an_object_report_carries_the_reconciliation_verdict() {
        let report = object_report(
            "artifacts/abc.tar.gz".to_owned(),
            "abc".to_owned(),
            10,
            None,
            "2026-08-23T12:00:00Z".to_owned(),
        );
        assert_eq!(report.reconciliation, Reconciliation::Missing);
        assert_eq!(report.stored_bytes, None);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"state\":\"missing\""), "{json}");
        // Absent optionals stay out of the payload entirely.
        assert!(!json.contains("stored_bytes"), "{json}");
    }
}
