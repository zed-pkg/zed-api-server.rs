use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use zed_orm_core::{ConnectPolicy, ReadContext, WriteContext};

use crate::config::Config;
use crate::state::AppState;
use crate::storage::ArtifactStore;
use crate::verify::TagVerifier;

const DB_CONNECT_ATTEMPTS: u32 = 10;
const DB_CONNECT_BASE_DELAY: Duration = Duration::from_millis(250);

pub async fn run() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env()?;
    let command = std::env::args().nth(1);
    let db = connect_database(&cfg).await?;
    let registry_write = connect_registry_write(&cfg).await?;

    if command.as_deref() == Some("migrate") {
        migrate_database(&db, &registry_write).await?;
        tracing::info!("database migrations complete");
        return Ok(());
    }
    if command.is_some() {
        anyhow::bail!("unknown command; expected `migrate` or no command");
    }

    if cfg.auto_migrate {
        tracing::warn!(
            "AUTO_MIGRATE=true: running compatibility and canonical migrations in-process; production must use the discrete migration job"
        );
        migrate_database(&db, &registry_write).await?;
    }

    let registry_read = connect_registry_read(&cfg).await?;
    let store = ArtifactStore::from_config(&cfg.storage).await?;
    let verifier = TagVerifier::new(cfg.verify_tags);
    let fiducia = if let Some(f) = &cfg.fiducia {
        let mut builder = fiducia_client::FiduciaClientBuilder::new(&f.url).org_id(&f.org_id);
        if let Some(secret) = &f.internal_secret {
            builder = builder.internal_secret(secret);
        }
        match builder.build() {
            Ok(client) => Some(Arc::new(client)),
            Err(error) => {
                tracing::warn!(%error, "fiducia client unavailable; using Postgres serialization");
                None
            }
        }
    } else {
        None
    };
    let rate_limiter = crate::ratelimit::RateLimiter::from_env();
    let shared_auth = cfg.shared_auth.as_ref().map(|auth| {
        Arc::new(crate::shared_auth::SharedAuthClient::new(
            auth.url.clone(),
            auth.service_credential.clone(),
        ))
    });
    let state = Arc::new(AppState {
        db,
        registry_read: Some(registry_read),
        registry_write: Some(registry_write),
        store,
        verifier,
        public_base_url: cfg.public_base_url,
        max_orgs_per_token: cfg.max_orgs_per_token,
        fiducia,
        rate_limiter,
        shared_auth,
        shared_auth_audience: cfg
            .shared_auth
            .as_ref()
            .map(|auth| auth.audience.clone())
            .unwrap_or_else(|| "zed-pkg".to_owned()),
        shared_auth_application_id: cfg
            .shared_auth
            .as_ref()
            .map(|auth| auth.application_id.clone())
            .unwrap_or_else(|| "zpkg-web".to_owned()),
        shared_auth_public_url: cfg
            .shared_auth
            .as_ref()
            .map(|auth| auth.public_url.clone()),
    });

    let app = app(state, cfg.max_artifact_bytes);
    let listener = TcpListener::bind(&cfg.bind_addr)
        .await
        .with_context(|| format!("bind {}", cfg.bind_addr))?;
    tracing::info!(addr = %cfg.bind_addr, "zed registry listening");
    axum::serve(listener, app)
        .await
        .context("serve HTTP")?;
    Ok(())
}

async fn connect_database(cfg: &Config) -> anyhow::Result<DatabaseConnection> {
    let mut options = ConnectOptions::new(cfg.database_url.clone());
    options
        .max_connections(cfg.db_max_connections)
        .min_connections(1)
        .connect_timeout(Duration::from_secs(10))
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .sqlx_logging(false);

    let mut delay = DB_CONNECT_BASE_DELAY;
    for attempt in 1..=DB_CONNECT_ATTEMPTS {
        match Database::connect(options.clone()).await {
            Ok(db) => {
                tracing::info!(attempt, "legacy compatibility database connected");
                return Ok(db);
            }
            Err(error) if attempt < DB_CONNECT_ATTEMPTS => {
                tracing::warn!(attempt, %error, ?delay, "database connection failed; retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            Err(error) => return Err(error).context("connect to Postgres"),
        }
    }
    unreachable!("retry loop returns on success or final failure")
}

async fn connect_registry_write(cfg: &Config) -> anyhow::Result<WriteContext> {
    let policy = ConnectPolicy::default().with_max_connections(cfg.db_max_connections);
    let mut delay = DB_CONNECT_BASE_DELAY;
    for attempt in 1..=DB_CONNECT_ATTEMPTS {
        match zed_orm_core::connect_read_write_with_policy(&cfg.database_url, policy).await {
            Ok(context) => {
                tracing::info!(attempt, "canonical registry write context connected");
                return Ok(context);
            }
            Err(error) if attempt < DB_CONNECT_ATTEMPTS => {
                tracing::warn!(attempt, %error, ?delay, "canonical write context failed; retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            Err(error) => return Err(error).context("connect canonical registry write context"),
        }
    }
    unreachable!("retry loop returns on success or final failure")
}

async fn connect_registry_read(cfg: &Config) -> anyhow::Result<ReadContext> {
    let policy = ConnectPolicy::default().with_max_connections(cfg.db_max_connections);
    zed_orm_core::connect_read_only_with_policy(&cfg.database_url, policy)
        .await
        .context("connect canonical registry read context")
}

async fn migrate_database(
    db: &DatabaseConnection,
    registry_write: &WriteContext,
) -> anyhow::Result<()> {
    // Legacy compatibility tables remain available for the exact zed-cli `/v1`
    // contract during cutover. No browser/account code addresses them.
    migration::Migrator::up(db, None)
        .await
        .context("apply legacy compatibility migrations")?;
    let report = zed_orm_core::migrations::migrate(registry_write)
        .await
        .context("apply canonical zed_* registry contract")?;
    tracing::info!(
        version = %report.version,
        applied = report.applied,
        "canonical registry migration evaluated"
    );
    Ok(())
}

pub fn app(state: Arc<AppState>, max_artifact_bytes: usize) -> Router {
    crate::routes::router(state.clone(), max_artifact_bytes)
        .merge(crate::account_router::router(state))
}
