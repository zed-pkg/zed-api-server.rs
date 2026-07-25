//! Per-credential rate limiting.
//!
//! The global `ConcurrencyLimitLayer` bounds how many requests run *at once*,
//! but nothing bounded how fast a single caller could issue them: one token
//! could saturate the whole in-flight budget and starve every other client.
//!
//! **Why key on the token, not the IP.** In production this server sits behind
//! ingress-nginx, so every peer address is the ingress controller's — IP
//! keying there would either throttle the whole world as one bucket or do
//! nothing. Per-IP limiting belongs at the ingress (it sees the real client
//! address; see `k8s/ingress.yaml`), while the token is the identity only the
//! application knows. Unauthenticated reads are left to the ingress limit and
//! the concurrency cap.
//!
//! The algorithm is a token bucket per credential: `burst` requests may go out
//! back-to-back, refilling at `per_second`. That suits a package registry,
//! where a CI job legitimately fires a burst of installs and then goes quiet,
//! better than a fixed window would.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Buckets idle for longer than this are dropped by the sweep, so the map
/// cannot grow without bound as tokens come and go.
const IDLE_EVICTION: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Tokens available right now (fractional: refill is continuous).
    tokens: f64,
    last_seen: Instant,
}

/// A token-bucket rate limiter keyed by opaque credential identity.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    burst: f64,
    per_second: f64,
}

/// Outcome of a rate-limit check.
#[derive(Debug, PartialEq)]
pub enum Decision {
    Allow,
    /// Rejected; retry after roughly this many seconds (never 0, so a client
    /// honoring `Retry-After` always backs off).
    Deny {
        retry_after_secs: u64,
    },
}

impl RateLimiter {
    /// `burst` requests immediately available, refilling at `per_second`.
    pub fn new(burst: u32, per_second: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            burst: f64::from(burst.max(1)),
            per_second: if per_second > 0.0 { per_second } else { 1.0 },
        }
    }

    /// Build from the environment: `ZED_RATE_LIMIT_BURST` (default 60) and
    /// `ZED_RATE_LIMIT_PER_SECOND` (default 10). Generous by design — this is
    /// an abuse ceiling, not a quota.
    pub fn from_env() -> Self {
        let burst = std::env::var("ZED_RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let per_second = std::env::var("ZED_RATE_LIMIT_PER_SECOND")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10.0);
        Self::new(burst, per_second)
    }

    /// Charge one request against `key`. Uses an injected `now` so the policy
    /// is testable without sleeping.
    pub fn check_at(&self, key: &str, now: Instant) -> Decision {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: self.burst,
            last_seen: now,
        });
        // Continuous refill since the last charge, capped at the burst size.
        let elapsed = now
            .saturating_duration_since(bucket.last_seen)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.per_second).min(self.burst);
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            drop(buckets);
            return Decision::Allow;
        }
        // Round up: a sub-second wait still asks for at least 1s of backoff.
        let deficit = 1.0 - bucket.tokens;
        let retry_after_secs = (deficit / self.per_second).ceil().max(1.0) as u64;
        drop(buckets);
        Decision::Deny { retry_after_secs }
    }

    pub fn check(&self, key: &str) -> Decision {
        self.check_at(key, Instant::now())
    }

    /// Drop buckets untouched for [`IDLE_EVICTION`]. A full bucket carries no
    /// state worth keeping, so eviction can never punish a returning caller.
    pub fn sweep_at(&self, now: Instant) {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        buckets.retain(|_, b| now.saturating_duration_since(b.last_seen) < IDLE_EVICTION);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

/// Axum middleware charging one unit per request against the caller's bearer
/// token. Requests without a token pass through untouched — they cannot
/// mutate anything (every write path calls `require_token`), and the ingress
/// owns per-IP limiting for reads.
pub async fn layer(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::state::AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let Some(limiter) = state.rate_limiter.as_ref() else {
        return next.run(request).await;
    };
    let Some(token) = crate::auth::bearer_token(request.headers()) else {
        return next.run(request).await;
    };
    // Key on the token's hash, never the plaintext: the key lives in a map,
    // in log lines, and in error paths, and none of those should hold a
    // usable credential.
    let key = crate::auth::hash_token(&token);
    match limiter.check(&key) {
        Decision::Allow => next.run(request).await,
        Decision::Deny { retry_after_secs } => {
            tracing::warn!(retry_after_secs, "rate limit exceeded for a token");
            (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                [(
                    axum::http::header::RETRY_AFTER,
                    retry_after_secs.to_string(),
                )],
                axum::Json(serde_json::json!({
                    "error": "rate_limited",
                    "message": format!(
                        "too many requests for this token; retry in {retry_after_secs}s"
                    ),
                })),
            )
                .into_response()
        }
    }
}

/// Spawn the periodic sweep that keeps the bucket map bounded.
pub fn spawn_sweeper(limiter: std::sync::Arc<RateLimiter>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            limiter.sweep_at(Instant::now());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_is_allowed_then_the_bucket_empties() {
        let limiter = RateLimiter::new(3, 1.0);
        let now = Instant::now();
        for i in 0..3 {
            assert_eq!(limiter.check_at("tok", now), Decision::Allow, "burst {i}");
        }
        match limiter.check_at("tok", now) {
            Decision::Deny { retry_after_secs } => assert!(retry_after_secs >= 1),
            other => panic!("expected the 4th request to be denied, got {other:?}"),
        }
    }

    #[test]
    fn the_bucket_refills_over_time() {
        let limiter = RateLimiter::new(2, 10.0); // 10/s => 100ms per token
        let start = Instant::now();
        assert_eq!(limiter.check_at("tok", start), Decision::Allow);
        assert_eq!(limiter.check_at("tok", start), Decision::Allow);
        assert!(matches!(
            limiter.check_at("tok", start),
            Decision::Deny { .. }
        ));
        // 150ms later one token has accrued.
        let later = start + Duration::from_millis(150);
        assert_eq!(limiter.check_at("tok", later), Decision::Allow);
        assert!(matches!(
            limiter.check_at("tok", later),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn refill_never_exceeds_the_burst_ceiling() {
        let limiter = RateLimiter::new(5, 1_000.0);
        let start = Instant::now();
        // An hour of idling must not bank more than `burst` requests.
        let much_later = start + Duration::from_secs(3_600);
        for _ in 0..5 {
            assert_eq!(limiter.check_at("tok", much_later), Decision::Allow);
        }
        assert!(matches!(
            limiter.check_at("tok", much_later),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn callers_are_isolated_from_each_other() {
        let limiter = RateLimiter::new(1, 0.001);
        let now = Instant::now();
        assert_eq!(limiter.check_at("alice", now), Decision::Allow);
        assert!(matches!(
            limiter.check_at("alice", now),
            Decision::Deny { .. }
        ));
        // Alice exhausting her bucket must not affect Bob.
        assert_eq!(limiter.check_at("bob", now), Decision::Allow);
    }

    #[test]
    fn retry_after_reflects_the_refill_rate_and_is_never_zero() {
        // 0.5/s => a full token takes 2s.
        let limiter = RateLimiter::new(1, 0.5);
        let now = Instant::now();
        assert_eq!(limiter.check_at("tok", now), Decision::Allow);
        match limiter.check_at("tok", now) {
            Decision::Deny { retry_after_secs } => assert_eq!(retry_after_secs, 2),
            other => panic!("expected Deny, got {other:?}"),
        }
        // A fast refill still rounds up to a whole second.
        let fast = RateLimiter::new(1, 1_000.0);
        assert_eq!(fast.check_at("t", now), Decision::Allow);
        match fast.check_at("t", now) {
            Decision::Deny { retry_after_secs } => assert_eq!(retry_after_secs, 1),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn the_sweep_evicts_only_idle_buckets() {
        let limiter = RateLimiter::new(5, 1.0);
        let start = Instant::now();
        limiter.check_at("old", start);
        limiter.check_at("fresh", start + IDLE_EVICTION);
        assert_eq!(limiter.len(), 2);

        limiter.sweep_at(start + IDLE_EVICTION + Duration::from_secs(1));
        assert_eq!(limiter.len(), 1, "the idle bucket is dropped");
        // The surviving caller keeps its allowance.
        assert_eq!(
            limiter.check_at("fresh", start + IDLE_EVICTION + Duration::from_secs(1)),
            Decision::Allow
        );
    }

    #[test]
    fn degenerate_settings_fall_back_to_something_usable() {
        // A zero burst would deny everything forever; a zero rate would never
        // refill. Both are clamped rather than bricking the server.
        let limiter = RateLimiter::new(0, 0.0);
        let now = Instant::now();
        assert_eq!(limiter.check_at("tok", now), Decision::Allow);
    }
}
