//! Canonical per-package-token rate limiting.
//!
//! `.ores-rl.toml` owns the policy and names runtime secret inputs. The shared
//! `ores-rl-lib-core` owns token-bucket/Redis semantics. This module is only the
//! trusted application adapter: it derives an opaque HMAC identity from the
//! bearer token, invokes the canonical distributed limiter, and translates the
//! decision to HTTP. Raw bearer tokens are never stored in limiter state or
//! emitted to logs.

use std::path::Path;

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use ores_rl_lib_core::{
    Decision, DistributedDecision, OpaqueKey, RateLimitConfigIdentityScope, RateLimitConfigV1,
    RateLimitServerRuntimeEnvExt, RedisTokenBucketLimiter,
};
use sha2::Sha256;

const RATE_LIMIT_NAMESPACE: &str = "zed-pkg";

type HmacSha256 = Hmac<Sha256>;

pub struct RateLimiter {
    inner: RedisTokenBucketLimiter,
    hmac_key: Vec<u8>,
    key_version: String,
    request_cost: u64,
}

impl RateLimiter {
    /// Load and validate the exact repository contract, resolve only the secret
    /// values named by that contract, then connect the canonical Redis adapter.
    pub async fn load(repo_root: impl AsRef<Path>) -> Result<Self> {
        let config = RateLimitConfigV1::load_from_repo_root(repo_root.as_ref())
            .context("invalid .ores-rl.toml rate-limit contract")?;
        let server = config
            .server_view()
            .context("rate-limit contract has no server projection")?;
        let policy = server
            .policies
            .iter()
            .find(|policy| policy.policy_id == server.default_policy_id)
            .ok_or_else(|| anyhow::anyhow!("default rate-limit policy is missing"))?
            .clone();
        if policy.identity_scope != RateLimitConfigIdentityScope::AuthenticatedSubject {
            anyhow::bail!(
                "package-token middleware requires identityScope = authenticated-subject"
            );
        }
        let runtime = server
            .server
            .resolve_runtime_environment()
            .context("rate-limit runtime environment is incomplete")?;
        let redis_url = runtime
            .redis_url()
            .ok_or_else(|| anyhow::anyhow!("strict registry rate limiting requires Redis"))?;
        let core_policy = policy
            .to_core_policy()
            .context("default rate-limit policy is not executable")?;
        let inner = RedisTokenBucketLimiter::connect(
            redis_url,
            RATE_LIMIT_NAMESPACE,
            &policy.policy_id,
            core_policy,
        )
        .await
        .context("failed to connect canonical Redis token-bucket limiter")?;

        Ok(Self {
            inner,
            hmac_key: runtime.key_hmac().as_bytes().to_vec(),
            key_version: policy.key_version,
            request_cost: policy.request_cost,
        })
    }

    async fn check_token(&self, bearer: &str) -> Result<DistributedDecision> {
        let principal = derive_principal(&self.hmac_key, &self.key_version, bearer);
        self.inner
            .check(principal, self.request_cost)
            .await
            .context("canonical distributed rate-limit check failed")
    }
}

fn derive_principal(hmac_key: &[u8], key_version: &str, bearer: &str) -> OpaqueKey {
    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .expect("HMAC-SHA-256 accepts keys of any non-empty runtime length");
    mac.update(b"zed-pkg:rate-limit:");
    mac.update(key_version.as_bytes());
    mac.update(b":package-token\0");
    mac.update(bearer.as_bytes());
    let bytes: [u8; 32] = mac.finalize().into_bytes().into();
    OpaqueKey::from_bytes(bytes)
}

/// Axum middleware charging one unit per authenticated package-token request.
/// Anonymous reads remain governed at ingress because the application does not
/// possess a trustworthy client-IP identity behind the proxy boundary.
pub async fn layer(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::state::AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let Some(limiter) = state.rate_limiter.as_ref() else {
        tracing::error!("canonical rate limiter missing from application state");
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "error": "rate_limit_unavailable",
                "message": "rate limiting is temporarily unavailable"
            })),
        )
            .into_response();
    };
    let Some(token) = crate::auth::bearer_token(request.headers()) else {
        return next.run(request).await;
    };

    match limiter.check_token(&token).await {
        Ok(DistributedDecision {
            decision: Decision::Allow { .. } | Decision::Bypass { .. },
            ..
        }) => next.run(request).await,
        Ok(DistributedDecision {
            decision: Decision::Deny { retry_after_ms, .. },
            ..
        }) => {
            let retry_after_secs = retry_after_ms.saturating_add(999) / 1_000;
            tracing::warn!(retry_after_ms, "package-token rate limit exceeded");
            (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                [(
                    axum::http::header::RETRY_AFTER,
                    retry_after_secs.max(1).to_string(),
                )],
                axum::Json(serde_json::json!({
                    "error": "rate_limited",
                    "message": "too many requests for this package token"
                })),
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "canonical rate-limit backend unavailable");
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({
                    "error": "rate_limit_unavailable",
                    "message": "rate limiting is temporarily unavailable"
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_rate_limit_contract_matches_package_token_boundary() {
        let config = RateLimitConfigV1::from_toml_str(include_str!("../.ores-rl.toml"))
            .expect("checked-in rate-limit config must parse");
        let server = config.server_view().expect("server projection");
        assert_eq!(server.default_policy_id, "authenticated-default");
        assert_eq!(server.policies.len(), 1);
        let policy = &server.policies[0];
        assert_eq!(policy.identity_scope, RateLimitConfigIdentityScope::AuthenticatedSubject);
        assert_eq!(policy.policy_id, server.default_policy_id);
        assert!(server.env.iter().any(|entry| entry.key == "REDIS_URL" && entry.secret));
        assert!(server
            .env
            .iter()
            .any(|entry| entry.key == "ORES_RL_HMAC_KEY" && entry.secret));
    }

    #[test]
    fn principal_derivation_is_versioned_stable_and_never_plaintext() {
        let first = derive_principal(b"synthetic-test-key", "v1", "bearer-secret");
        let repeated = derive_principal(b"synthetic-test-key", "v1", "bearer-secret");
        let other_token = derive_principal(b"synthetic-test-key", "v1", "other-secret");
        let other_version = derive_principal(b"synthetic-test-key", "v2", "bearer-secret");
        assert_eq!(first, repeated);
        assert_ne!(first, other_token);
        assert_ne!(first, other_version);
        let debug = format!("{first:?}");
        assert!(!debug.contains("bearer-secret"));
        assert!(!debug.contains("synthetic-test-key"));
    }
}
