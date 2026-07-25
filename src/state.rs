use std::sync::Arc;

use fiducia_client::FiduciaClient;
use sea_orm::DatabaseConnection;

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
}
