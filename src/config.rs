use anyhow::{Context, Result, bail};

/// All configuration comes from the environment (flags-2-env style); see the
/// README for the full table and the Cloudflare R2 mapping.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub database_url: String,
    pub auto_migrate: bool,
    pub storage: StorageConfig,
    pub public_base_url: String,
    pub verify_tags: TagPolicy,
    pub max_artifact_bytes: usize,
    pub max_orgs_per_token: u64,
    pub db_max_connections: u32,
    pub fiducia: Option<FiduciaConfig>,
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
        Ok(Self {
            bind_addr: env_or("BIND_ADDR", "0.0.0.0:8080"),
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL is required")?,
            auto_migrate: env_or("AUTO_MIGRATE", "true") == "true",
            storage,
            public_base_url: env_or("PUBLIC_BASE_URL", "http://localhost:8080"),
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
        })
    }
}
