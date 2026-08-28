use std::sync::Arc;

use fiducia_client::FiduciaClient;
use sea_orm::DatabaseConnection;
use zed_orm_core::{ReadContext, WriteContext};

use crate::shared_auth::SharedAuthClient;
use crate::storage::ArtifactStore;
use crate::verify::TagVerifier;

pub struct AppState {
    /// Transitional `/v1` metadata/token connection. New account and registry
    /// projection code must use the opaque canonical contexts below.
    pub db: DatabaseConnection,
    /// Canonical SELECT-only context. `None` is permitted only in isolated
    /// legacy unit tests; account routes fail closed when it is unavailable.
    pub registry_read: Option<ReadContext>,
    /// Canonical API write context. `None` is permitted only in isolated legacy
    /// unit tests; browser/account writes and production publish adoption fail
    /// closed when it is unavailable.
    pub registry_write: Option<WriteContext>,
    pub store: ArtifactStore,
    /// Static, credential-free description of the configured backend, resolved
    /// once at startup. Held on state rather than re-derived per request so the
    /// console can never report a backend the process is not actually using.
    pub storage_backend: crate::storage_report::StorageBackend,
    pub verifier: TagVerifier,
    pub public_base_url: String,
    /// Stable graph-node identity; deliberately independent of ingress URLs.
    pub registry_id: String,
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
