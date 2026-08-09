use std::sync::Arc;

use fiducia_client::FiduciaClient;
use sea_orm::DatabaseConnection;

use crate::shared_auth::SharedAuthClient;
use crate::storage::ArtifactStore;
use crate::verify::TagVerifier;

pub struct AppState {
    pub db: DatabaseConnection,
    pub store: ArtifactStore,
    pub verifier: TagVerifier,
    pub public_base_url: String,
    pub max_orgs_per_token: u64,
    /// Distributed lock service; None → Postgres-only serialization (correct,
    /// just without cross-replica FIFO queueing/observability).
    pub fiducia: Option<Arc<FiduciaClient>>,
    /// Per-token rate limiter; None disables limiting (tests, and
    /// `ZED_RATE_LIMIT_DISABLED=1` for single-tenant self-hosting).
    pub rate_limiter: Option<Arc<crate::ratelimit::RateLimiter>>,
    /// Protected Shared Auth introspection client for browser/account routes.
    /// None is tolerated only for healthchecks and legacy package-token routes;
    /// every account route fails with 503 rather than falling back to anonymous.
    pub shared_auth: Option<Arc<SharedAuthClient>>,
    pub shared_auth_audience: String,
    pub shared_auth_application_id: String,
    pub shared_auth_public_url: Option<String>,
}
