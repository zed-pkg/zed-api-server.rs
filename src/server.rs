use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use migration::MigratorTrait;
use sea_orm::{ConnectOptions, Database};
use tracing_subscriber::EnvFilter;
use zed_orm_core::{ConnectPolicy, ReadContext, WriteContext};

use crate::config::Config;
use crate::shared_auth::SharedAuthClient;
use crate::state::AppState;
use crate::storage::ArtifactStore;
use crate::verify::TagVerifier;
use crate::{account_router, api_docs, ratelimit, registry_host, routes, tokens};

#[derive(Debug, PartialEq, Eq)]
enum ProcessCommand<'a> {
    CreateToken(&'a [String]),
    Healthcheck,
    Migrate,
    RevokeToken(&'a [String]),
    Serve,
}

/// Run the registry process or one of its local administrative commands.
pub(crate) async fn run() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = std::env::args().collect::<Vec<_>>();
    let command = process_command(&args);
    match command {
        ProcessCommand::CreateToken(arguments) => return tokens::create_token(arguments).await,
        ProcessCommand::RevokeToken(arguments) => return tokens::revoke_token(arguments).await,
        ProcessCommand::Healthcheck => return healthcheck().await,
        ProcessCommand::Migrate | ProcessCommand::Serve => {}
    }

    let cfg = Config::from_env()?;
    let db = connect_with_retry(&cfg).await?;
    let registry_write = connect_registry_write_with_retry(&cfg).await?;
    if command == ProcessCommand::Migrate {
        migrate_database(&db, &registry_write).await?;
        return Ok(());
    }
    if cfg.auto_migrate {
        tracing::warn!(
            "AUTO_MIGRATE=true is development-only; production must run `zed-api-server migrate` as a one-shot Job"
        );
        migrate_database(&db, &registry_write).await?;
    }
    let registry_read = connect_registry_read_with_retry(&cfg).await?;
    let store = ArtifactStore::from_config(&cfg.storage).await?;
    let storage_backend = store.describe(&cfg.storage);
    tracing::info!(
        backend = storage_backend.kind.as_str(),
        provider = storage_backend.provider.as_str(),
        durable = storage_backend.durable,
        "artifact storage configured"
    );
    let fiducia = cfg.fiducia.as_ref().map(|configuration| {
        tracing::info!("fiducia locks enabled at {}", configuration.url);
        Arc::new(match &configuration.internal_secret {
            Some(secret) => fiducia_client::FiduciaClient::internal(
                &configuration.url,
                secret,
                &configuration.org_id,
            ),
            None => fiducia_client::FiduciaClient::new(&configuration.url),
        })
    });
    let rate_limiter = if std::env::var("ZED_RATE_LIMIT_DISABLED").as_deref() == Ok("1") {
        tracing::warn!("per-token rate limiting is DISABLED (ZED_RATE_LIMIT_DISABLED=1)");
        None
    } else {
        let limiter = Arc::new(ratelimit::RateLimiter::from_env());
        ratelimit::spawn_sweeper(limiter.clone());
        Some(limiter)
    };
    let shared_auth = cfg.shared_auth.as_ref().map(|configuration| {
        Arc::new(
            SharedAuthClient::new(&configuration.url)
                .with_service_credential(configuration.service_credential.clone()),
        )
    });
    if shared_auth.is_none() {
        tracing::warn!(
            "SHARED_AUTH_URL is not configured; browser/account routes will fail closed with 503"
        );
    }
    let state = Arc::new(AppState {
        db,
        registry_read: Some(registry_read),
        registry_write: Some(registry_write),
        store,
        storage_backend,
        verifier: TagVerifier::new(cfg.verify_tags),
        public_base_url: cfg.public_base_url.trim_end_matches('/').to_string(),
        mirrors: cfg.mirrors.clone(),
        registry_id: cfg.registry_id,
        max_orgs_per_token: cfg.max_orgs_per_token,
        fiducia,
        rate_limiter,
        shared_auth,
        shared_auth_audience: cfg
            .shared_auth
            .as_ref()
            .map(|configuration| configuration.audience.clone())
            .unwrap_or_else(|| "zed-pkg".into()),
        shared_auth_application_id: cfg
            .shared_auth
            .as_ref()
            .map(|configuration| configuration.application_id.clone())
            .unwrap_or_else(|| "zpkg-web".into()),
        shared_auth_public_url: cfg
            .shared_auth
            .as_ref()
            .map(|configuration| configuration.public_url.clone()),
    });

    // Keep the state-free public documentation surface outside the registry
    // router so it cannot inherit token auth or per-token rate limiting.
    let app = axum::Router::new()
        .merge(api_docs::router())
        .merge(routes::router(state.clone(), cfg.max_artifact_bytes))
        .merge(account_router::router(state))
        // Defense in depth for the registry virtual host. Cloudflare runs the
        // same transition table at the edge, but direct-origin traffic must
        // not be able to bypass it with Host: registry.zpkg.net.
        .layer(axum::middleware::from_fn(
            registry_host::enforce_registry_host,
        ));
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("zed-api-server listening on {}", cfg.bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

fn process_command(args: &[String]) -> ProcessCommand<'_> {
    match args.get(1).map(String::as_str) {
        Some("create-token") => ProcessCommand::CreateToken(&args[2..]),
        Some("revoke-token") => ProcessCommand::RevokeToken(&args[2..]),
        Some("healthcheck") => ProcessCommand::Healthcheck,
        Some("migrate") => ProcessCommand::Migrate,
        _ => ProcessCommand::Serve,
    }
}

/// Apply the legacy machine-registry compatibility schema first, then the
/// canonical `zed_*` contract under zed-orm-core's own advisory lock.
async fn migrate_database(
    db: &sea_orm::DatabaseConnection,
    registry_write: &WriteContext,
) -> Result<()> {
    migration::Migrator::up(db, None)
        .await
        .context("legacy registry migrations failed")?;
    let report = zed_orm_core::migrations::migrate(registry_write)
        .await
        .context("canonical registry migrations failed")?;
    tracing::info!(
        migration = report.version,
        applied = report.applied,
        "canonical registry migration batch complete"
    );
    Ok(())
}

/// Connect to the legacy compatibility schema, retrying until it is reachable
/// or the bounded deadline passes.
async fn connect_with_retry(cfg: &Config) -> Result<sea_orm::DatabaseConnection> {
    let max_wait = database_connect_max_wait();
    let started = std::time::Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let mut connect_options = ConnectOptions::new(cfg.database_url.clone());
        connect_options
            .max_connections(cfg.db_max_connections)
            .connect_timeout(Duration::from_secs(5))
            .acquire_timeout(Duration::from_secs(8))
            .sqlx_logging(false);
        match Database::connect(connect_options).await {
            Ok(database) => {
                if attempt > 1 {
                    tracing::info!(attempt, "connected to Postgres after retry");
                }
                return Ok(database);
            }
            Err(error) if started.elapsed() >= max_wait => {
                return Err(anyhow::Error::new(error).context(format!(
                    "failed to connect to DATABASE_URL after {attempt} attempts over {}s",
                    started.elapsed().as_secs()
                )));
            }
            Err(error) => {
                tracing::warn!(%error, attempt, "Postgres not ready yet; retrying in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn connect_registry_write_with_retry(cfg: &Config) -> Result<WriteContext> {
    let max_wait = database_connect_max_wait();
    let started = std::time::Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let policy = ConnectPolicy::default().with_max_connections(cfg.db_max_connections);
        match zed_orm_core::connect_read_write_with_policy(&cfg.database_url, policy).await {
            Ok(context) => {
                if attempt > 1 {
                    tracing::info!(attempt, "connected canonical write context after retry");
                }
                return Ok(context);
            }
            Err(error) if started.elapsed() >= max_wait => {
                return Err(anyhow::Error::new(error).context(format!(
                    "failed to connect canonical registry write context after {attempt} attempts over {}s",
                    started.elapsed().as_secs()
                )));
            }
            Err(error) => {
                tracing::warn!(%error, attempt, "canonical write context not ready; retrying in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn connect_registry_read_with_retry(cfg: &Config) -> Result<ReadContext> {
    let max_wait = database_connect_max_wait();
    let started = std::time::Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let policy = ConnectPolicy::default().with_max_connections(cfg.db_max_connections);
        match zed_orm_core::connect_read_only_with_policy(&cfg.database_url, policy).await {
            Ok(context) => {
                if attempt > 1 {
                    tracing::info!(attempt, "connected canonical read context after retry");
                }
                return Ok(context);
            }
            Err(error) if started.elapsed() >= max_wait => {
                return Err(anyhow::Error::new(error).context(format!(
                    "failed to connect canonical registry read context after {attempt} attempts over {}s",
                    started.elapsed().as_secs()
                )));
            }
            Err(error) => {
                tracing::warn!(%error, attempt, "canonical read context not ready; retrying in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

fn database_connect_max_wait() -> Duration {
    Duration::from_secs(
        std::env::var("DB_CONNECT_MAX_WAIT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30),
    )
}

/// Probe the local `/healthz` endpoint for the container HEALTHCHECK.
async fn healthcheck() -> Result<()> {
    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let url = healthcheck_url(&bind);
    let response = reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .context("healthcheck request failed")?;
    if response.status().is_success() {
        Ok(())
    } else {
        anyhow::bail!("healthcheck returned HTTP {}", response.status());
    }
}

fn healthcheck_url(bind: &str) -> String {
    let port = bind.rsplit(':').next().unwrap_or("8080");
    format!("http://127.0.0.1:{port}/healthz")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn process_commands_keep_their_argument_boundaries() {
        let create = arguments(&["zed-api-server", "create-token", "--name", "ci"]);
        assert!(matches!(
            process_command(&create),
            ProcessCommand::CreateToken(values) if values == ["--name", "ci"]
        ));

        let revoke = arguments(&["zed-api-server", "revoke-token", "--name", "ci"]);
        assert!(matches!(
            process_command(&revoke),
            ProcessCommand::RevokeToken(values) if values == ["--name", "ci"]
        ));
        assert_eq!(
            process_command(&arguments(&["zed-api-server", "healthcheck"])),
            ProcessCommand::Healthcheck
        );
        assert_eq!(
            process_command(&arguments(&["zed-api-server", "migrate"])),
            ProcessCommand::Migrate
        );
        assert_eq!(
            process_command(&arguments(&["zed-api-server", "unknown"])),
            ProcessCommand::Serve
        );
    }

    #[test]
    fn healthcheck_uses_the_bound_listener_port() {
        assert_eq!(
            healthcheck_url("0.0.0.0:8080"),
            "http://127.0.0.1:8080/healthz"
        );
        assert_eq!(
            healthcheck_url("[::]:9090"),
            "http://127.0.0.1:9090/healthz"
        );
    }
}
