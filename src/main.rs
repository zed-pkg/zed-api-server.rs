mod auth;
mod config;
mod entities;
mod error;
mod files;
mod ratelimit;
mod rbac;
mod routes;
mod state;
mod storage;
mod tokens;
mod verify;

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

/// Connect to Postgres, retrying until it is reachable or a bounded deadline
/// passes.
///
/// Unlike the read-only web server — which degrades to offline mode — the API
/// server genuinely requires a database, so this still fails hard once the
/// deadline is up (k8s then restarts the pod). The retry exists to survive the
/// ordinary cold-start race: on a fresh rollout, a `docker compose up`, or a
/// node reboot, the server frequently wins the race against its own Postgres
/// and against CoreDNS, and a single no-retry `connect` turns that transient
/// "Temporary failure in name resolution" into CrashLoopBackOff.
///
/// Only the initial race needs covering: once the pool exists, sqlx
/// transparently re-establishes dropped connections across later DB restarts.
async fn connect_with_retry(cfg: &Config) -> Result<sea_orm::DatabaseConnection> {
    let max_wait = Duration::from_secs(
        std::env::var("DB_CONNECT_MAX_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30),
    );
    let started = std::time::Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let mut connect_opts = ConnectOptions::new(cfg.database_url.clone());
        connect_opts
            .max_connections(cfg.db_max_connections)
            .connect_timeout(Duration::from_secs(5))
            .acquire_timeout(Duration::from_secs(8))
            .sqlx_logging(false);
        match Database::connect(connect_opts).await {
            Ok(db) => {
                if attempt > 1 {
                    tracing::info!(attempt, "connected to Postgres after retry");
                }
                return Ok(db);
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

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("create-token") {
        return tokens::create_token(&args[2..]).await;
    }
    if args.get(1).map(String::as_str) == Some("revoke-token") {
        return tokens::revoke_token(&args[2..]).await;
    }
    if args.get(1).map(String::as_str) == Some("healthcheck") {
        return healthcheck().await;
    }

    let cfg = Config::from_env()?;
    let db = connect_with_retry(&cfg).await?;
    if cfg.auto_migrate {
        migration::Migrator::up(&db, None)
            .await
            .context("migrations failed")?;
    }
    let store = ArtifactStore::from_config(&cfg.storage).await?;
    let fiducia = cfg.fiducia.as_ref().map(|f| {
        tracing::info!("fiducia locks enabled at {}", f.url);
        std::sync::Arc::new(match &f.internal_secret {
            Some(secret) => fiducia_client::FiduciaClient::internal(&f.url, secret, &f.org_id),
            None => fiducia_client::FiduciaClient::new(&f.url),
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

/// `zed-api-server healthcheck`: probe the local `/healthz` endpoint and exit
/// non-zero if it is not healthy. Used by the container HEALTHCHECK, which has
/// no `curl`/`wget` in the slim runtime image.
async fn healthcheck() -> Result<()> {
    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let port = bind.rsplit(':').next().unwrap_or("8080");
    let url = format!("http://127.0.0.1:{port}/healthz");
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
