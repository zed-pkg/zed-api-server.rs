use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aws_sdk_s3::presigning::PresigningConfig;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::StorageConfig;
use crate::storage_report::{ObjectHead, StorageBackend, StorageHealth, redact_backend_error};

/// Artifact storage: bounded process memory for disposable certification,
/// local disk for development/self-hosting, or any S3-compatible endpoint
/// (AWS S3, Cloudflare R2, MinIO) for durable production storage.
pub enum ArtifactStore {
    Memory {
        objects: Arc<RwLock<HashMap<String, Bytes>>>,
        max_bytes: u64,
    },
    Local {
        dir: PathBuf,
    },
    S3 {
        client: aws_sdk_s3::Client,
        bucket: String,
    },
}

/// Hard ceiling on any artifact we are willing to hold in memory at once.
/// Archive extraction always buffers; the process-memory backend and S3/local
/// file extraction share this independent per-object safety net. An object
/// that predates a lowered upload limit, or one written out of band into a
/// bucket, must not be able to pull an unbounded allocation into the server.
pub const MAX_BUFFERED_ARTIFACT_BYTES: u64 = 100 * 1024 * 1024;

/// Artifacts are content-addressed and immutable, so every download path must
/// advertise the same long-lived immutable caching contract. The process-memory
/// and local backends set this header on the response directly (see
/// `routes::artifacts`); the s3/R2 backend serves a 302 to a presigned URL, so
/// the header must be baked into the stored object and the presigned request or
/// it is silently lost on the redirect.
const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
const ARTIFACT_SHA256_METADATA_KEY: &str = "zpkg-sha256";
const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
struct ExpectedArtifact<'a> {
    len: u64,
    sha256: &'a str,
    content_type: &'a str,
}

/// How a download should be served to the client.
pub enum Download {
    /// 302 to a presigned URL (S3/R2).
    Redirect(String),
    /// Ref-counted immutable bytes from the process-memory backend.
    Bytes { bytes: Bytes },
    /// An open file to stream from disk (local backend). Never buffered: the
    /// route wraps this in a streaming body, so serving a 100 MB artifact
    /// costs a read buffer rather than 100 MB of resident memory.
    File { file: tokio::fs::File, len: u64 },
}

impl ArtifactStore {
    pub async fn from_config(config: &StorageConfig) -> Result<Self> {
        match config {
            StorageConfig::Memory { max_bytes } => Ok(Self::Memory {
                objects: Arc::new(RwLock::new(HashMap::new())),
                max_bytes: *max_bytes,
            }),
            StorageConfig::Local { dir } => {
                let dir = PathBuf::from(dir);
                tokio::fs::create_dir_all(&dir).await?;
                Ok(Self::Local { dir })
            }
            StorageConfig::S3 {
                bucket,
                endpoint_url,
                region,
                force_path_style,
            } => {
                let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_config::Region::new(region.clone()));
                if let Some(endpoint) = endpoint_url {
                    loader = loader.endpoint_url(endpoint);
                }
                let shared = loader.load().await;
                let s3_config = aws_sdk_s3::config::Builder::from(&shared)
                    .force_path_style(*force_path_style)
                    .build();
                Ok(Self::S3 {
                    client: aws_sdk_s3::Client::from_conf(s3_config),
                    bucket: bucket.clone(),
                })
            }
        }
    }

    fn local_path(dir: &std::path::Path, key: &str) -> PathBuf {
        // Keys are server-generated (`artifacts/<sha>.<ext>`), never user input.
        dir.join(key)
    }

    /// Store bytes whose digest was already recomputed by the caller.
    ///
    /// The digest is persisted as object metadata and is also used to verify a
    /// failed/raced S3-compatible PUT. Only a byte-for-byte, length- and
    /// metadata-identical object is accepted as an idempotent recovery.
    pub async fn put_verified(
        &self,
        key: &str,
        bytes: Bytes,
        content_type: &str,
        sha256: &str,
    ) -> Result<()> {
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            anyhow::bail!("artifact sha256 must be 64 lowercase hexadecimal characters");
        }
        let expected = ExpectedArtifact {
            len: bytes.len() as u64,
            sha256,
            content_type,
        };
        match self {
            Self::Memory { objects, max_bytes } => {
                // The write lock makes capacity accounting and insertion one
                // transaction. Content-addressed keys are immutable across all
                // backends: an identical retry succeeds, while a collision can
                // never replace the bytes already visible to readers.
                let mut objects = objects.write().await;
                if let Some(existing) = objects.get(key) {
                    if existing == &bytes {
                        return Ok(());
                    }
                    anyhow::bail!(
                        "in-memory artifact `{key}` already exists with different immutable content"
                    );
                }
                let retained_bytes = objects
                    .values()
                    .try_fold(0u64, |total, value| total.checked_add(value.len() as u64))
                    .context("in-memory artifact byte accounting overflowed")?;
                let next_bytes = retained_bytes
                    .checked_add(bytes.len() as u64)
                    .context("in-memory artifact byte accounting overflowed")?;
                if next_bytes > *max_bytes {
                    anyhow::bail!(
                        "in-memory artifact store capacity exceeded: write would use {next_bytes} \
                         bytes, limit is {max_bytes} bytes"
                    );
                }
                objects.insert(key.to_string(), bytes);
                Ok(())
            }
            Self::Local { dir } => {
                let path = Self::local_path(dir, key);
                Self::put_local(&path, bytes, &expected).await
            }
            Self::S3 { client, bucket } => {
                let put = client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    // Never overwrite an immutable content-addressed key. R2
                    // and S3 both implement wildcard If-None-Match; an existing
                    // object takes the verified recovery path below.
                    .if_none_match("*")
                    .content_type(content_type)
                    .cache_control(IMMUTABLE_CACHE_CONTROL)
                    .metadata(ARTIFACT_SHA256_METADATA_KEY, sha256)
                    .body(bytes.into())
                    .send()
                    .await;
                match put {
                    Ok(_) => Ok(()),
                    Err(err) => {
                        // Keys are content-addressed (`artifacts/<sha256>.<ext>`),
                        // so a concurrent publish of the same artifact races on the
                        // identical key with byte-identical content. R2 can
                        // rate-limit concurrent writes to one key, but mere
                        // existence is not proof of idempotence: an out-of-band
                        // or corrupt object could occupy the key. Recover only
                        // after a bounded GET proves the length, actual digest,
                        // content type, immutable cache policy, and digest
                        // metadata all match this publication.
                        match Self::s3_object_matches(
                            client, bucket, key, &expected,
                        )
                        .await
                        {
                            Ok(true) => Ok(()),
                            Ok(false) => Err(err).context(
                                "s3 put_object failed and the existing object did not match the expected immutable artifact",
                            ),
                            Err(verify_error) => Err(err).context(format!(
                                "s3 put_object failed and recovery verification failed: {verify_error:#}"
                            )),
                        }
                    }
                }
            }
        }
    }

    async fn put_local(path: &Path, bytes: Bytes, expected: &ExpectedArtifact<'_>) -> Result<()> {
        if let Some(matches) = Self::local_object_matches(path, expected).await? {
            if matches {
                return Ok(());
            }
            anyhow::bail!(
                "local artifact {} already exists with different immutable content",
                path.display()
            );
        }

        let parent = path
            .parent()
            .context("local artifact path has no parent directory")?;
        tokio::fs::create_dir_all(parent).await?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("local artifact path has no UTF-8 file name")?;
        let temporary = parent.join(format!(".{file_name}.upload-{}.tmp", Uuid::new_v4()));

        let result: Result<()> = async {
            let mut file = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .await
                .with_context(|| {
                    format!(
                        "creating local artifact staging file {}",
                        temporary.display()
                    )
                })?;
            file.write_all(&bytes).await.with_context(|| {
                format!(
                    "writing local artifact staging file {}",
                    temporary.display()
                )
            })?;
            file.flush().await?;
            file.sync_all().await.with_context(|| {
                format!(
                    "syncing local artifact staging file {}",
                    temporary.display()
                )
            })?;
            drop(file);

            // A hard link is a same-filesystem, atomic, no-clobber promotion.
            // Unlike rename on Unix it cannot silently replace an immutable
            // object that appeared between the preflight check and promotion.
            match tokio::fs::hard_link(&temporary, path).await {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    match Self::local_object_matches(path, expected).await? {
                        Some(true) => Ok(()),
                        Some(false) => anyhow::bail!(
                            "local artifact {} won a race with different immutable content",
                            path.display()
                        ),
                        None => Err(error).with_context(|| {
                            format!("promoting local artifact {}", path.display())
                        }),
                    }
                }
                Err(error) => Err(error)
                    .with_context(|| format!("promoting local artifact {}", path.display())),
            }
        }
        .await;

        let cleanup = tokio::fs::remove_file(&temporary).await;
        if let Err(error) = cleanup
            && error.kind() != ErrorKind::NotFound
            && result.is_ok()
        {
            return Err(error).with_context(|| {
                format!(
                    "removing local artifact staging file {}",
                    temporary.display()
                )
            });
        }
        if result.is_ok() {
            Self::sync_directory(parent).await?;
        }
        result
    }

    async fn local_object_matches(
        path: &Path,
        expected: &ExpectedArtifact<'_>,
    ) -> Result<Option<bool>> {
        let metadata = match tokio::fs::metadata(path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() || metadata.len() != expected.len {
            return Ok(Some(false));
        }
        let file = tokio::fs::File::open(path).await?;
        let (len, sha256) = Self::hash_async_reader(file, expected.len).await?;
        Ok(Some(len == expected.len && sha256 == expected.sha256))
    }

    #[cfg(unix)]
    async fn sync_directory(path: &Path) -> Result<()> {
        tokio::fs::File::open(path).await?.sync_all().await?;
        Ok(())
    }

    #[cfg(not(unix))]
    async fn sync_directory(_path: &Path) -> Result<()> {
        Ok(())
    }

    async fn s3_object_matches(
        client: &aws_sdk_s3::Client,
        bucket: &str,
        key: &str,
        expected: &ExpectedArtifact<'_>,
    ) -> Result<bool> {
        let object = client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .context("s3 recovery get_object failed")?;
        if !Self::object_metadata_matches(
            object.content_length(),
            object.content_type(),
            object.cache_control(),
            object.metadata(),
            expected,
        ) {
            return Ok(false);
        }

        let (len, sha256) =
            Self::hash_async_reader(object.body.into_async_read(), expected.len).await?;
        Ok(len == expected.len && sha256 == expected.sha256)
    }

    fn object_metadata_matches(
        content_length: Option<i64>,
        content_type: Option<&str>,
        cache_control: Option<&str>,
        metadata: Option<&HashMap<String, String>>,
        expected: &ExpectedArtifact<'_>,
    ) -> bool {
        content_length.and_then(|len| u64::try_from(len).ok()) == Some(expected.len)
            && content_type == Some(expected.content_type)
            && cache_control == Some(IMMUTABLE_CACHE_CONTROL)
            && metadata
                .and_then(|values| values.get(ARTIFACT_SHA256_METADATA_KEY))
                .map(String::as_str)
                == Some(expected.sha256)
    }

    async fn hash_async_reader(
        mut reader: impl tokio::io::AsyncRead + Unpin,
        expected_len: u64,
    ) -> Result<(u64, String)> {
        let mut hasher = Sha256::new();
        let mut len = 0_u64;
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            len = len
                .checked_add(read as u64)
                .context("artifact length overflowed u64 while hashing")?;
            if len > expected_len {
                return Ok((len, String::new()));
            }
            hasher.update(&buffer[..read]);
        }
        Ok((len, hex::encode(hasher.finalize())))
    }

    pub async fn download(&self, key: &str) -> Result<Download> {
        match self {
            Self::Memory { objects, .. } => {
                let bytes = objects
                    .read()
                    .await
                    .get(key)
                    .cloned()
                    .with_context(|| format!("in-memory artifact {key} not found"))?;
                Ok(Download::Bytes { bytes })
            }
            Self::Local { dir } => {
                let file = tokio::fs::File::open(Self::local_path(dir, key)).await?;
                let len = file.metadata().await?.len();
                Ok(Download::File { file, len })
            }
            Self::S3 { client, bucket } => {
                let presigned = client
                    .get_object()
                    .bucket(bucket)
                    .key(key)
                    // Override the response Cache-Control on the presigned GET so
                    // the immutable contract holds even for objects stored before
                    // put-time cache metadata was set. Without this the 302 target
                    // returns whatever (if anything) the object was stored with.
                    .response_cache_control(IMMUTABLE_CACHE_CONTROL)
                    .presigned(PresigningConfig::expires_in(Duration::from_secs(600))?)
                    .await
                    .context("s3 presign failed")?;
                Ok(Download::Redirect(presigned.uri().to_string()))
            }
        }
    }

    /// Full artifact bytes regardless of backend (for /v1/files extraction,
    /// which must seek within the archive). Refuses anything larger than
    /// [`MAX_BUFFERED_ARTIFACT_BYTES`] before allocating a new buffer.
    pub async fn get_bytes(&self, key: &str) -> Result<Vec<u8>> {
        match self {
            Self::Memory { objects, .. } => {
                let bytes = objects
                    .read()
                    .await
                    .get(key)
                    .cloned()
                    .with_context(|| format!("in-memory artifact {key} not found"))?;
                Self::guard_buffered(key, bytes.len() as u64)?;
                Ok(bytes.to_vec())
            }
            Self::Local { dir } => {
                let path = Self::local_path(dir, key);
                let len = tokio::fs::metadata(&path).await?.len();
                Self::guard_buffered(key, len)?;
                Ok(tokio::fs::read(&path).await?)
            }
            Self::S3 { client, bucket } => {
                let object = client
                    .get_object()
                    .bucket(bucket)
                    .key(key)
                    .send()
                    .await
                    .context("s3 get_object failed")?;
                // Trust the object's declared length only to reject early; the
                // collected body is re-checked below in case it lied.
                if let Some(len) = object.content_length() {
                    Self::guard_buffered(key, len.max(0) as u64)?;
                }
                let bytes = object.body.collect().await?.into_bytes().to_vec();
                Self::guard_buffered(key, bytes.len() as u64)?;
                Ok(bytes)
            }
        }
    }

    fn guard_buffered(key: &str, len: u64) -> Result<()> {
        if len > MAX_BUFFERED_ARTIFACT_BYTES {
            anyhow::bail!(
                "artifact {key} is {len} bytes, over the {MAX_BUFFERED_ARTIFACT_BYTES}-byte \
                 in-memory ceiling; refusing to buffer it"
            );
        }
        Ok(())
    }
}

/// Read-only introspection, for the storage console.
///
/// These are the only methods that describe the backend rather than move bytes
/// through it. Each returns a value from [`crate::storage_report`]; none of them
/// can mutate the store, and none of them is provider-specific — the same three
/// calls answer the same three questions on R2, S3, GCS, MinIO, a directory, or
/// process memory.
impl ArtifactStore {
    /// Identity of this backend: what kind it is, which vendor is behind it,
    /// and the non-secret configuration an operator would recognize.
    ///
    /// Derived from live state rather than re-read from configuration, so the
    /// console cannot report a bucket the process is not actually using.
    #[must_use]
    pub fn describe(&self, config: &StorageConfig) -> StorageBackend {
        match (self, config) {
            (Self::Memory { .. }, _) => StorageBackend::process_memory(),
            (Self::Local { dir }, _) => StorageBackend::filesystem(dir.display().to_string()),
            (
                Self::S3 { bucket, .. },
                StorageConfig::S3 {
                    endpoint_url,
                    region,
                    force_path_style,
                    ..
                },
            ) => StorageBackend::object_store(
                bucket,
                region,
                endpoint_url.as_deref(),
                *force_path_style,
            ),
            // The store was built from this config, so the arms above are
            // exhaustive in practice. Describing the live variant with unknown
            // endpoint details still beats claiming a backend we do not have.
            (Self::S3 { bucket, .. }, _) => {
                StorageBackend::object_store(bucket, String::new(), None, false)
            }
        }
    }

    /// Ask the backend whether it is answering, without reading an object.
    ///
    /// A bucket-level HEAD is the cheapest S3-compatible liveness question and
    /// is priced as a request rather than as a listing. Failures are reported,
    /// never propagated: a console that 500s when storage is down cannot tell
    /// anyone that storage is down.
    pub async fn probe(&self) -> StorageHealth {
        let started = Instant::now();
        let outcome: Result<()> = match self {
            Self::Memory { .. } => Ok(()),
            Self::Local { dir } => tokio::fs::metadata(dir)
                .await
                .map_err(anyhow::Error::from)
                .and_then(|meta| {
                    if meta.is_dir() {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!("{} is not a directory", dir.display()))
                    }
                }),
            Self::S3 { client, bucket } => client
                .head_bucket()
                .bucket(bucket)
                .send()
                .await
                .map(|_| ())
                .map_err(|error| anyhow::anyhow!("{error}")),
        };
        match outcome {
            Ok(()) => StorageHealth::Reachable {
                latency_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            },
            Err(error) => StorageHealth::Unreachable {
                reason: redact_backend_error(&format!("{error}")),
            },
        }
    }

    /// What the backend knows about one object, without downloading it.
    ///
    /// `Ok(None)` is "the store does not have this key" — an ordinary answer
    /// for a console reconciling the registry against the store. `Err` is
    /// reserved for a backend that could not be asked at all.
    pub async fn head(&self, key: &str) -> Result<Option<ObjectHead>> {
        match self {
            Self::Memory { objects, .. } => {
                Ok(objects.read().await.get(key).map(|bytes| ObjectHead {
                    size: Some(bytes.len() as u64),
                    ..ObjectHead::default()
                }))
            }
            Self::Local { dir } => match tokio::fs::metadata(Self::local_path(dir, key)).await {
                Ok(meta) => Ok(Some(ObjectHead {
                    size: Some(meta.len()),
                    last_modified: meta
                        .modified()
                        .ok()
                        .and_then(|time| {
                            time.duration_since(std::time::UNIX_EPOCH)
                                .ok()
                                .and_then(|since| i64::try_from(since.as_millis()).ok())
                        })
                        .and_then(rfc3339_from_millis),
                    ..ObjectHead::default()
                })),
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error).context("reading local artifact metadata"),
            },
            Self::S3 { client, bucket } => {
                let response = client.head_object().bucket(bucket).key(key).send().await;
                match response {
                    Ok(object) => Ok(Some(ObjectHead {
                        size: object.content_length().map(|len| len.max(0) as u64),
                        sha256: object
                            .metadata()
                            .and_then(|meta| meta.get(ARTIFACT_SHA256_METADATA_KEY).cloned()),
                        content_type: object.content_type().map(str::to_owned),
                        cache_control: object.cache_control().map(str::to_owned),
                        last_modified: object
                            .last_modified()
                            .and_then(|time| time.to_millis().ok())
                            .and_then(rfc3339_from_millis),
                    })),
                    // A HEAD on an absent key is a 404, which the SDK surfaces
                    // as a typed NotFound rather than a transport failure.
                    Err(error) => {
                        let rendered = format!("{error}");
                        if is_not_found(&rendered) {
                            Ok(None)
                        } else {
                            Err(anyhow::anyhow!(redact_backend_error(&rendered)))
                        }
                    }
                }
            }
        }
    }
}

/// Milliseconds since the Unix epoch as an RFC 3339 UTC timestamp.
fn rfc3339_from_millis(millis: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(millis)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Does a rendered S3 error describe an absent key?
///
/// Matched on the rendered error rather than the typed variant so the same
/// predicate holds across S3-compatible services, which do not agree on how the
/// SDK models a missing object.
fn is_not_found(rendered: &str) -> bool {
    let lowered = rendered.to_ascii_lowercase();
    lowered.contains("notfound")
        || lowered.contains("not found")
        || lowered.contains("nosuchkey")
        || lowered.contains("status code: 404")
}

pub fn artifact_key(sha256: &str, extension: &str) -> String {
    format!("artifacts/{sha256}.{extension}")
}

/// Guessable public-R2 aliases so a client can fetch without `registry.zpkg.net`.
/// The content-addressed [`artifact_key`] remains the canonical object; these
/// extra keys are copies of the same bytes. Layout matches
/// `zed-interfaces::source::r2_object_keys` (duplicated here because this
/// crate's interfaces pin predates that module).
pub fn guessable_alias_keys(
    org: &str,
    name: &str,
    version: &str,
    vcs_tag: &str,
    extension: &str,
    repo_url: &str,
) -> Vec<String> {
    let (owner, repo) = crate::verify::parse_github(repo_url)
        .unwrap_or_else(|| (org.to_string(), name.to_string()));
    let mut keys = Vec::new();
    if safe_r2_segments(&[&owner, &repo, vcs_tag, name, version, extension]) {
        keys.push(format!(
            "github/{owner}/{repo}/{vcs_tag}/{name}-{version}.{extension}"
        ));
    }
    if safe_r2_segments(&[org, name, version, extension]) {
        keys.push(format!(
            "packages/{org}/{name}/{version}/{name}-{version}.{extension}"
        ));
    }
    keys
}

fn safe_r2_segments(parts: &[&str]) -> bool {
    parts.iter().all(|part| {
        !part.is_empty()
            && !part.contains('\0')
            && !part.contains('\\')
            && part
                .split('/')
                .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
    })
}

impl ArtifactStore {
    /// Write extra public keys after the canonical content-addressed put.
    /// Process-memory backends skip this: in-process tests talk to the API,
    /// not the CDN, and alias copies would triple the capacity accounting.
    pub async fn put_public_aliases(
        &self,
        keys: &[String],
        bytes: Bytes,
        content_type: &str,
        sha256: &str,
    ) -> Result<()> {
        match self {
            Self::Memory { .. } => Ok(()),
            Self::Local { .. } | Self::S3 { .. } => {
                for key in keys {
                    self.put_verified(key, bytes.clone(), content_type, sha256)
                        .await?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn keys_are_sha_addressed() {
        assert_eq!(artifact_key("abc123", "tar.gz"), "artifacts/abc123.tar.gz");
    }

    #[test]
    fn guessable_aliases_follow_github_and_package_layout() {
        assert_eq!(
            guessable_alias_keys(
                "zed-pkg",
                "zed-cli",
                "0.1.0",
                "v0.1.0",
                "tar.gz",
                "https://github.com/zed-pkg/zed-cli",
            ),
            vec![
                "github/zed-pkg/zed-cli/v0.1.0/zed-cli-0.1.0.tar.gz".to_string(),
                "packages/zed-pkg/zed-cli/0.1.0/zed-cli-0.1.0.tar.gz".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn memory_store_roundtrips_without_disk() {
        let store = ArtifactStore::from_config(&StorageConfig::Memory { max_bytes: 64 })
            .await
            .unwrap();
        let payload = Bytes::from_static(b"zed-memory-artifact");
        let expected = payload.clone();
        let sha256 = digest(&payload);

        store
            .put_verified(
                "artifacts/test.tar.gz",
                payload,
                "application/gzip",
                &sha256,
            )
            .await
            .unwrap();

        match store.download("artifacts/test.tar.gz").await.unwrap() {
            Download::Bytes { bytes } => assert_eq!(bytes, expected),
            _ => panic!("memory backend returned a non-memory download"),
        }
        assert_eq!(
            store.get_bytes("artifacts/test.tar.gz").await.unwrap(),
            expected.to_vec()
        );
    }

    #[tokio::test]
    async fn memory_store_enforces_total_capacity_atomically() {
        let store = ArtifactStore::from_config(&StorageConfig::Memory { max_bytes: 4 })
            .await
            .unwrap();
        let first = Bytes::from_static(b"1234");
        let first_sha256 = digest(&first);
        store
            .put_verified(
                "artifacts/one",
                first,
                "application/octet-stream",
                &first_sha256,
            )
            .await
            .unwrap();

        let second = Bytes::from_static(b"5");
        let second_sha256 = digest(&second);
        let error = store
            .put_verified(
                "artifacts/two",
                second,
                "application/octet-stream",
                &second_sha256,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("capacity exceeded"));

        match store.download("artifacts/one").await.unwrap() {
            Download::Bytes { bytes } => assert_eq!(bytes, Bytes::from_static(b"1234")),
            _ => panic!("memory backend returned a non-memory download"),
        }
    }

    #[tokio::test]
    async fn memory_store_never_overwrites_a_digest_collision() {
        let store = ArtifactStore::from_config(&StorageConfig::Memory { max_bytes: 64 })
            .await
            .unwrap();
        let key = "artifacts/collision.zip";
        let original = Bytes::from_static(b"expected bytes");
        let sha256 = digest(&original);
        store
            .put_verified(key, original.clone(), "application/zip", &sha256)
            .await
            .unwrap();

        let error = store
            .put_verified(
                key,
                Bytes::from_static(b"different bytes"),
                "application/zip",
                &sha256,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("different immutable content"));
        assert_eq!(store.get_bytes(key).await.unwrap(), original.to_vec());
    }

    #[tokio::test]
    async fn verified_put_rejects_a_noncanonical_digest() {
        let store = ArtifactStore::from_config(&StorageConfig::Memory { max_bytes: 64 })
            .await
            .unwrap();
        let error = store
            .put_verified(
                "artifacts/test.zip",
                Bytes::from_static(b"payload"),
                "application/zip",
                "ABC123",
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("64 lowercase hexadecimal"));
    }

    #[test]
    fn raced_object_recovery_requires_all_immutable_metadata() {
        let sha256 = "a".repeat(64);
        let expected = ExpectedArtifact {
            len: 7,
            sha256: &sha256,
            content_type: "application/zip",
        };
        let mut metadata =
            HashMap::from([(ARTIFACT_SHA256_METADATA_KEY.to_owned(), sha256.clone())]);

        assert!(ArtifactStore::object_metadata_matches(
            Some(7),
            Some("application/zip"),
            Some(IMMUTABLE_CACHE_CONTROL),
            Some(&metadata),
            &expected,
        ));
        assert!(!ArtifactStore::object_metadata_matches(
            Some(8),
            Some("application/zip"),
            Some(IMMUTABLE_CACHE_CONTROL),
            Some(&metadata),
            &expected,
        ));
        assert!(!ArtifactStore::object_metadata_matches(
            Some(7),
            Some("application/octet-stream"),
            Some(IMMUTABLE_CACHE_CONTROL),
            Some(&metadata),
            &expected,
        ));
        assert!(!ArtifactStore::object_metadata_matches(
            Some(7),
            Some("application/zip"),
            None,
            Some(&metadata),
            &expected,
        ));
        metadata.insert(ARTIFACT_SHA256_METADATA_KEY.to_owned(), "b".repeat(64));
        assert!(!ArtifactStore::object_metadata_matches(
            Some(7),
            Some("application/zip"),
            Some(IMMUTABLE_CACHE_CONTROL),
            Some(&metadata),
            &expected,
        ));
    }

    #[tokio::test]
    async fn local_store_atomically_promotes_concurrent_identical_puts() {
        let root = std::env::temp_dir().join(format!("zed-local-store-{}", Uuid::new_v4()));
        let store = Arc::new(
            ArtifactStore::from_config(&StorageConfig::Local {
                dir: root.to_string_lossy().to_string(),
            })
            .await
            .unwrap(),
        );
        let payload = Bytes::from_static(b"immutable native ZIP bytes");
        let sha256 = digest(&payload);
        let key = "artifacts/atomic.zip";

        let mut writes = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let payload = payload.clone();
            let sha256 = sha256.clone();
            writes.push(tokio::spawn(async move {
                store
                    .put_verified(key, payload, "application/zip", &sha256)
                    .await
            }));
        }
        for write in writes {
            write.await.unwrap().unwrap();
        }

        assert_eq!(store.get_bytes(key).await.unwrap(), payload.to_vec());
        let mut entries = tokio::fs::read_dir(root.join("artifacts")).await.unwrap();
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            names.push(entry.file_name().to_string_lossy().to_string());
        }
        names.sort();
        assert_eq!(names, vec!["atomic.zip".to_owned()]);
    }

    #[tokio::test]
    async fn local_store_never_overwrites_a_digest_collision() {
        let root = std::env::temp_dir().join(format!("zed-local-store-{}", Uuid::new_v4()));
        let store = ArtifactStore::from_config(&StorageConfig::Local {
            dir: root.to_string_lossy().to_string(),
        })
        .await
        .unwrap();
        let key = "artifacts/collision.zip";
        let payload = Bytes::from_static(b"expected bytes");
        let sha256 = digest(&payload);
        store
            .put_verified(key, payload.clone(), "application/zip", &sha256)
            .await
            .unwrap();
        let path = root.join(key);
        tokio::fs::write(&path, b"out-of-band corruption")
            .await
            .unwrap();

        let error = store
            .put_verified(key, payload, "application/zip", &sha256)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("different immutable content"));
        assert_eq!(
            tokio::fs::read(path).await.unwrap(),
            b"out-of-band corruption"
        );
    }
}
