use std::fmt;

use anyhow::{Context, Result, bail};

/// All configuration comes from the environment (flags-2-env style); see the
/// README for the full table and the Cloudflare R2 mapping.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub database_url: String,
    /// Development-only compatibility switch. Production deploys must keep
    /// this false and run the explicit `migrate` command as a Kubernetes Job.
    pub auto_migrate: bool,
    pub storage: StorageConfig,
    pub public_base_url: String,
    /// Stable logical registry identity embedded in graph nodes. Unlike the
    /// public URL, this value must not change when an ingress alias changes.
    pub registry_id: String,
    pub verify_tags: TagPolicy,
    pub max_artifact_bytes: usize,
    pub max_orgs_per_token: u64,
    pub db_max_connections: u32,
    pub fiducia: Option<FiduciaConfig>,
    pub shared_auth: Option<SharedAuthConfig>,
}

/// Shared Auth is a separate data plane. The service credential is used only
/// for protected introspection and is intentionally redacted from Debug output.
#[derive(Clone)]
pub struct SharedAuthConfig {
    pub url: String,
    pub public_url: String,
    pub service_credential: String,
    pub audience: String,
    /// Exact OAuth authorized party (`azp`) permitted to call browser/account
    /// routes. The Rust field retains its legacy name for source compatibility;
    /// `SHARED_AUTH_AUTHORIZED_PARTY` is the canonical environment variable.
    pub application_id: String,
}

impl fmt::Debug for SharedAuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedAuthConfig")
            .field("url", &self.url)
            .field("public_url", &self.public_url)
            .field("service_credential", &"<redacted>")
            .field("audience", &self.audience)
            .field("authorized_party", &self.application_id)
            .finish()
    }
}

/// Optional fiducia lock service for distributed locks (see routes/orgs.rs).
/// Enabled by FIDUCIA_URL; absent → handlers fall back to their Postgres-only
/// serialization, which remains fully correct.
#[derive(Debug, Clone)]
pub struct FiduciaConfig {
    pub url: String,
    /// x-fiducia-internal-auth secret for direct-to-node calls; the hosted
    /// edge uses bearer auth instead.
    pub internal_secret: Option<String>,
    pub org_id: String,
}

#[derive(Debug, Clone)]
pub enum StorageConfig {
    /// Process-local, bounded artifact storage for disposable publish and
    /// install certification. Every restart starts empty; never use this as a
    /// durable production registry.
    Memory {
        max_bytes: u64,
    },
    Local {
        dir: String,
    },
    S3 {
        bucket: String,
        endpoint_url: Option<String>,
        region: String,
        force_path_style: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagPolicy {
    /// No verification (dev default).
    Off,
    /// Verify tags on github.com repos; warn-and-allow elsewhere.
    Github,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let storage = match env_or("STORAGE_BACKEND", "local").as_str() {
            "memory" => {
                let max_bytes = env_or("STORAGE_MEMORY_MAX_BYTES", "268435456")
                    .parse::<u64>()
                    .context("STORAGE_MEMORY_MAX_BYTES must be a number")?;
                if max_bytes == 0 {
                    bail!("STORAGE_MEMORY_MAX_BYTES must be greater than zero");
                }
                StorageConfig::Memory { max_bytes }
            }
            "local" => StorageConfig::Local {
                dir: env_or("STORAGE_LOCAL_DIR", ".data/artifacts"),
            },
            "s3" => StorageConfig::S3 {
                bucket: std::env::var("S3_BUCKET").context("S3_BUCKET is required for s3")?,
                endpoint_url: std::env::var("S3_ENDPOINT_URL").ok(),
                region: env_or("S3_REGION", "auto"),
                force_path_style: env_or("S3_FORCE_PATH_STYLE", "true") == "true",
            },
            other => bail!("STORAGE_BACKEND must be memory, local, or s3, got `{other}`"),
        };
        let verify_tags = match env_or("ZED_VERIFY_TAGS", "off").as_str() {
            "off" => TagPolicy::Off,
            "github" => TagPolicy::Github,
            other => bail!("ZED_VERIFY_TAGS must be off or github, got `{other}`"),
        };
        let shared_auth = match std::env::var("SHARED_AUTH_URL") {
            Ok(url) => {
                let url = nonempty("SHARED_AUTH_URL", url)?;
                let public_url = nonempty(
                    "SHARED_AUTH_PUBLIC_URL",
                    std::env::var("SHARED_AUTH_PUBLIC_URL").unwrap_or_else(|_| url.clone()),
                )?;
                let service_credential = nonempty(
                    "SHARED_AUTH_SERVICE_CREDENTIAL",
                    std::env::var("SHARED_AUTH_SERVICE_CREDENTIAL").context(
                        "SHARED_AUTH_SERVICE_CREDENTIAL is required when SHARED_AUTH_URL is set",
                    )?,
                )?;
                let audience = nonempty(
                    "SHARED_AUTH_AUDIENCE",
                    env_or("SHARED_AUTH_AUDIENCE", "zed-pkg"),
                )?;
                let application_id = match std::env::var("SHARED_AUTH_AUTHORIZED_PARTY") {
                    Ok(value) => nonempty("SHARED_AUTH_AUTHORIZED_PARTY", value)?,
                    Err(std::env::VarError::NotPresent) => nonempty(
                        "SHARED_AUTH_APPLICATION_ID",
                        env_or("SHARED_AUTH_APPLICATION_ID", "zpkg-web"),
                    )?,
                    Err(error) => {
                        return Err(error)
                            .context("SHARED_AUTH_AUTHORIZED_PARTY is not valid Unicode");
                    }
                };
                Some(SharedAuthConfig {
                    url,
                    public_url,
                    service_credential,
                    audience,
                    application_id,
                })
            }
            Err(std::env::VarError::NotPresent) => None,
            Err(error) => return Err(error).context("SHARED_AUTH_URL is not valid Unicode"),
        };
        Ok(Self {
            bind_addr: env_or("BIND_ADDR", "0.0.0.0:8080"),
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL is required")?,
            auto_migrate: env_or("AUTO_MIGRATE", "false") == "true",
            storage,
            public_base_url: env_or("PUBLIC_BASE_URL", "http://localhost:8080"),
            registry_id: validate_registry_id(env_or("ZED_REGISTRY_ID", "registry:zpkg-primary"))?,
            verify_tags,
            max_artifact_bytes: env_or("MAX_ARTIFACT_BYTES", "104857600")
                .parse()
                .context("MAX_ARTIFACT_BYTES must be a number")?,
            max_orgs_per_token: env_or("ZED_MAX_ORGS_PER_TOKEN", "5")
                .parse()
                .context("ZED_MAX_ORGS_PER_TOKEN must be a number")?,
            db_max_connections: env_or("DB_MAX_CONNECTIONS", "10")
                .parse()
                .context("DB_MAX_CONNECTIONS must be a number")?,
            fiducia: std::env::var("FIDUCIA_URL").ok().map(|url| FiduciaConfig {
                url,
                internal_secret: std::env::var("FIDUCIA_INTERNAL_SECRET").ok(),
                org_id: env_or("FIDUCIA_ORG_ID", "zed-registry"),
            }),
            shared_auth,
        })
    }
}

fn nonempty(key: &str, value: String) -> Result<String> {
    let value = value.trim().trim_end_matches('/').to_owned();
    if value.is_empty() {
        bail!("{key} cannot be empty");
    }
    Ok(value)
}

fn validate_registry_id(value: String) -> Result<String> {
    let value = value.trim().to_owned();
    let Some(suffix) = value.strip_prefix("registry:") else {
        bail!("ZED_REGISTRY_ID must start with `registry:`");
    };
    if suffix.is_empty()
        || suffix.len() > 128
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!(
            "ZED_REGISTRY_ID suffix must contain 1 to 128 ASCII letters, digits, dots, underscores, or hyphens"
        );
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_auth_debug_redacts_the_service_credential() {
        let config = SharedAuthConfig {
            url: "https://shared-auth.example.test".into(),
            public_url: "https://auth.example.test".into(),
            service_credential: "secret-value".into(),
            audience: "zed-pkg".into(),
            application_id: "zpkg-web".into(),
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret-value"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("zpkg-web"));
    }

    #[test]
    fn registry_identity_is_logical_and_not_an_ingress_url() {
        assert_eq!(
            validate_registry_id(" registry:zpkg-primary ".into()).unwrap(),
            "registry:zpkg-primary"
        );
        for invalid in [
            "",
            "https://registry.zpkg.net",
            "registry:",
            "registry:contains/slash",
            "registry:contains space",
        ] {
            assert!(validate_registry_id(invalid.into()).is_err(), "{invalid}");
        }
    }
}
