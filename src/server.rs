use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use migration::MigratorTrait;
use sea_orm::{ConnectOptions, Database};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::state::AppState;
use crate::storage::ArtifactStore;
use crate::verify::TagVerifier;
use crate::{auth, ratelimit, routes, tokens};

#[derive(Debug, PartialEq, Eq)]
enum ProcessCommand<'a> {
    CreateToken(&'a [String]),
    Healthcheck,
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
    match process_command(&args) {
        ProcessCommand::CreateToken(arguments) => return tokens::create_token(arguments).await,
        ProcessCommand::RevokeToken(arguments) => return tokens::revoke_token(arguments).await,
        ProcessCommand::Healthcheck => return healthcheck().await,
        ProcessCommand::Serve => {}
    }

    let cfg = Config::from_env()?;
    if auth::auth_disabled() {
        tracing::warn!(
            "AUTHENTICATION IS DISABLED (ZED_AUTH_DISABLED=1); every caller has admin authority"
        );
    }
    let db = connect_with_retry(&cfg).await?;
    if cfg.auto_migrate {
        migration::Migrator::up(&db, None)
            .await
            .context("migrations failed")?;
    }
    let store = ArtifactStore::from_config(&cfg.storage).await?;
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
    let state = Arc::new(AppState {
        db,
        store,
        verifier: TagVerifier::new(cfg.verify_tags),
        public_base_url: cfg.public_base_url.trim_end_matches('/').to_string(),
        max_orgs_per_token: cfg.max_orgs_per_token,
        fiducia,
        rate_limiter,
    });

    let app = routes::router(state, cfg.max_artifact_bytes);
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
        _ => ProcessCommand::Serve,
    }
}

/// Connect to Postgres, retrying until it is reachable or a bounded deadline
/// passes.
///
/// Unlike the read-only web server — which degrades to offline mode — the API
/// server genuinely requires a database, so this still fails hard once the
/// deadline is up. The retry covers the ordinary cold-start race against
/// Postgres and DNS; the established pool handles later reconnects.
async fn connect_with_retry(cfg: &Config) -> Result<sea_orm::DatabaseConnection> {
    let max_wait = Duration::from_secs(
        std::env::var("DB_CONNECT_MAX_WAIT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30),
    );
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
                    "failed to connect to DATABASE_URL after {attempt} attempts \
                     over {}s (DB_CONNECT_MAX_WAIT_SECS)",
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
