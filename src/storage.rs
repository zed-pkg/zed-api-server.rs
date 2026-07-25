use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use aws_sdk_s3::presigning::PresigningConfig;
use bytes::Bytes;

use crate::config::StorageConfig;

/// Artifact storage: local disk for dev/self-host, or any S3-compatible
/// endpoint (AWS S3, Cloudflare R2, MinIO) for production.
pub enum ArtifactStore {
    Local {
        dir: PathBuf,
    },
    S3 {
        client: aws_sdk_s3::Client,
        bucket: String,
    },
}

/// Hard ceiling on any artifact we are willing to hold in memory at once.
/// Only the archive-extraction path ([`ArtifactStore::get_bytes`]) buffers;
/// downloads stream. This is a safety net independent of `MAX_ARTIFACT_BYTES`
/// (which bounds *uploads*): an object that predates a lowered config value,
/// or one written out of band into the bucket, must still not be able to pull
/// an unbounded allocation into the server.
pub const MAX_BUFFERED_ARTIFACT_BYTES: u64 = 100 * 1024 * 1024;

/// How a download should be served to the client.
pub enum Download {
    /// 302 to a presigned URL (S3/R2).
    Redirect(String),
    /// An open file to stream from disk (local backend). Never buffered: the
    /// route wraps this in a streaming body, so serving a 100 MB artifact
    /// costs a read buffer rather than 100 MB of resident memory.
    File { file: tokio::fs::File, len: u64 },
}

impl ArtifactStore {
    pub async fn from_config(config: &StorageConfig) -> Result<Self> {
        match config {
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

    /// Takes `Bytes` rather than `Vec<u8>`: the artifact arrives from the
    /// multipart reader as `Bytes`, and a `Vec` signature forced a second full
    /// copy of every upload (peak ~2x the artifact size per in-flight publish).
    /// Both backends consume `Bytes` without copying.
    pub async fn put(&self, key: &str, bytes: Bytes, content_type: &str) -> Result<()> {
        match self {
            Self::Local { dir } => {
                let path = Self::local_path(dir, key);
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(path, bytes).await?;
                Ok(())
            }
            Self::S3 { client, bucket } => {
                client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    .content_type(content_type)
                    .body(bytes.into())
                    .send()
                    .await
                    .context("s3 put_object failed")?;
                Ok(())
            }
        }
    }

    pub async fn download(&self, key: &str) -> Result<Download> {
        match self {
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
                    .presigned(PresigningConfig::expires_in(Duration::from_secs(600))?)
                    .await
                    .context("s3 presign failed")?;
                Ok(Download::Redirect(presigned.uri().to_string()))
            }
        }
    }

    /// Remove a stored artifact (best-effort cleanup paths).
    pub async fn delete(&self, key: &str) -> Result<()> {
        match self {
            Self::Local { dir } => {
                tokio::fs::remove_file(Self::local_path(dir, key)).await?;
                Ok(())
            }
            Self::S3 { client, bucket } => {
                client
                    .delete_object()
                    .bucket(bucket)
                    .key(key)
                    .send()
                    .await
                    .context("s3 delete_object failed")?;
                Ok(())
            }
        }
    }

    /// Full artifact bytes regardless of backend (for /v1/files extraction,
    /// which must seek within the archive). Refuses anything larger than
    /// [`MAX_BUFFERED_ARTIFACT_BYTES`] *before* allocating, so a huge object
    /// fails fast instead of ballooning the process.
    pub async fn get_bytes(&self, key: &str) -> Result<Vec<u8>> {
        match self {
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

pub fn artifact_key(sha256: &str, extension: &str) -> String {
    format!("artifacts/{sha256}.{extension}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_sha_addressed() {
        assert_eq!(artifact_key("abc123", "tar.gz"), "artifacts/abc123.tar.gz");
    }
}
