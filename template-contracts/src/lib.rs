//! Thin composition bundle for the canonical ORES server-template contracts.
//! Concrete runtime/domain types stay owned by their source crates and interfaces.

pub const ORES_MW_CONFIG: &str = include_str!("../../.ores-mw.toml");
pub const ORES_RATE_LIMIT_CONFIG: &str = include_str!("../../.ores-rl.toml");
pub const ORES_LRU_CONFIG: &str = include_str!("../../.ores-lru.toml");
pub const SHARED_AUTH_CONFIG: &str = include_str!("../../.shared-auth.toml");

pub struct ApiServerIntegrations<Middleware, Auth, RateLimit, Cache> {
    pub middleware: Middleware,
    pub auth: Auth,
    pub rate_limit: RateLimit,
    pub cache: Cache,
}

impl<Middleware, Auth, RateLimit, Cache> ApiServerIntegrations<Middleware, Auth, RateLimit, Cache> {
    #[must_use]
    pub const fn new(middleware: Middleware, auth: Auth, rate_limit: RateLimit, cache: Cache) -> Self {
        Self { middleware, auth, rate_limit, cache }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embeds_all_contracts() {
        assert!(ORES_MW_CONFIG.contains("schema_version = 1"));
        assert!(ORES_RATE_LIMIT_CONFIG.contains("ores.rate-limit.config.v1"));
        assert!(ORES_LRU_CONFIG.contains("ores.lru-config.v1"));
        assert!(SHARED_AUTH_CONFIG.contains("shared-auth-interfaces"));
    }
}
