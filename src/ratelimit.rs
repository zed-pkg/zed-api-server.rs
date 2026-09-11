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
//! Admission transitions are delegated to the exact reviewed
//! `ores-rl-lib-core` revision. This adapter owns only opaque-key storage,
//! monotonic time, environment compatibility, Axum response mapping, and idle
//! eviction. No floating-point state is used.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ores_rl_lib_core::{
    Decision as CoreDecision, LimitPolicy, LimitState, PolicyError, transition,
};

/// Buckets idle for longer than this are dropped when their state is safe to
/// forget. The hard capacity below bounds memory even when callers never go
/// idle long enough to regain a full bucket.
const IDLE_EVICTION: Duration = Duration::from_secs(600);
const MAX_BUCKETS: usize = 100_000;
const DEFAULT_BURST: &str = "60";
const DEFAULT_RATE_PER_SECOND: &str = "10.0";
const RATE_SETTING: &str = "ZED_RATE_LIMIT_PER_SECOND";
const BURST_SETTING: &str = "ZED_RATE_LIMIT_BURST";

#[derive(Debug, Clone, Copy)]
struct Bucket {
    state: LimitState,
    last_seen: Instant,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct RefillRate {
    tokens: u64,
    interval_ms: u64,
}

/// Configuration failure that prevents the server from starting with an
/// ambiguous or weakened abuse ceiling.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RateLimitConfigError {
    InvalidSetting {
        name: &'static str,
        requirement: &'static str,
    },
    InvalidPolicy(PolicyError),
}

impl fmt::Display for RateLimitConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSetting { name, requirement } => {
                write!(formatter, "invalid {name}: {requirement}")
            }
            Self::InvalidPolicy(error) => write!(formatter, "invalid rate-limit policy: {error}"),
        }
    }
}

impl std::error::Error for RateLimitConfigError {}

/// A token-bucket rate limiter keyed by an opaque, already-derived credential
/// identity. Raw tokens and other personal identifiers never enter this type.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    clock: Mutex<Instant>,
    policy: LimitPolicy,
    epoch: Instant,
}

/// Outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Decision {
    Allow,
    /// Rejected; retry after roughly this many seconds (never 0, so a client
    /// honoring `Retry-After` always backs off).
    Deny {
        retry_after_secs: u64,
    },
}

impl RateLimiter {
    /// Construct a validated integer token-bucket policy.
    pub fn new(
        capacity: u64,
        refill_tokens: u64,
        refill_interval_ms: u64,
    ) -> Result<Self, RateLimitConfigError> {
        let policy = LimitPolicy::token_bucket(capacity, refill_tokens, refill_interval_ms)
            .validate()
            .map_err(RateLimitConfigError::InvalidPolicy)?;
        let epoch = Instant::now();
        Ok(Self {
            buckets: Mutex::new(HashMap::new()),
            clock: Mutex::new(epoch),
            policy,
            epoch,
        })
    }

    /// Build from the audited flags-2-env snapshot. The legacy decimal
    /// `ZED_RATE_LIMIT_PER_SECOND` setting remains compatible, but is parsed
    /// exactly into a reduced integer refill ratio rather than an `f64`.
    pub fn from_env() -> Result<Self, RateLimitConfigError> {
        let capacity = parse_capacity(
            &crate::flags::var(BURST_SETTING).unwrap_or_else(|_| DEFAULT_BURST.to_owned()),
        )?;
        let refill = parse_refill_rate(
            &crate::flags::var(RATE_SETTING).unwrap_or_else(|_| DEFAULT_RATE_PER_SECOND.to_owned()),
        )?;
        Self::new(capacity, refill.tokens, refill.interval_ms)
    }

    #[must_use]
    pub const fn policy(&self) -> LimitPolicy {
        self.policy
    }

    /// Charge one request against `key`. Uses an injected `now` so the policy
    /// is testable without sleeping. Any impossible clock or state transition
    /// fails closed without replacing the last valid bucket state.
    pub fn check_at(&self, key: &str, now: Instant) -> Decision {
        let mut clock = self.clock.lock().unwrap_or_else(|error| error.into_inner());
        if now < *clock {
            tracing::error!("rate-limit monotonic clock moved backwards; denying");
            return Decision::Deny {
                retry_after_secs: 1,
            };
        }
        *clock = now;
        let Some(elapsed) = now.checked_duration_since(self.epoch) else {
            tracing::error!("rate-limit monotonic clock preceded the limiter epoch; denying");
            return Decision::Deny {
                retry_after_secs: 1,
            };
        };
        let Ok(now_ms) = u64::try_from(elapsed.as_millis()) else {
            tracing::error!("rate-limit monotonic clock exceeded the supported range; denying");
            return Decision::Deny {
                retry_after_secs: 1,
            };
        };

        let transition_result = {
            let mut buckets = self
                .buckets
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if !buckets.contains_key(key) && buckets.len() >= MAX_BUCKETS {
                tracing::error!("rate-limit bucket capacity reached; denying new identity");
                return Decision::Deny {
                    retry_after_secs: 1,
                };
            }
            let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
                state: LimitState::Empty,
                last_seen: now,
            });
            let result = transition(self.policy, bucket.state, now_ms, 1);
            if let Ok((next_state, _)) = result {
                bucket.state = next_state;
                bucket.last_seen = now;
            }
            result
        };

        match transition_result {
            Ok((_, decision)) => decision_from_core(decision),
            Err(error) => {
                tracing::error!(error = %error, "rate-limit transition failed closed");
                Decision::Deny {
                    retry_after_secs: 1,
                }
            }
        }
    }

    pub fn check(&self, key: &str) -> Decision {
        self.check_at(key, Instant::now())
    }

    /// Drop buckets untouched for [`IDLE_EVICTION`]. A full bucket carries no
    /// state worth keeping, so eviction can never punish a returning caller.
    pub fn sweep_at(&self, now: Instant) {
        let mut clock = self.clock.lock().unwrap_or_else(|error| error.into_inner());
        if now < *clock {
            tracing::error!("rate-limit sweep clock moved backwards; retaining buckets");
            return;
        }
        *clock = now;
        let Some(elapsed) = now.checked_duration_since(self.epoch) else {
            tracing::error!("rate-limit sweep preceded the limiter epoch; retaining buckets");
            return;
        };
        let Ok(now_ms) = u64::try_from(elapsed.as_millis()) else {
            tracing::error!("rate-limit sweep exceeded the supported range; retaining buckets");
            return;
        };
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        buckets.retain(|_, bucket| {
            now.saturating_duration_since(bucket.last_seen) < IDLE_EVICTION
                || !is_safe_to_evict(self.policy, bucket.state, now_ms)
        });
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

fn decision_from_core(decision: CoreDecision) -> Decision {
    match decision {
        CoreDecision::Allow { .. } => Decision::Allow,
        CoreDecision::Deny { retry_after_ms, .. } => Decision::Deny {
            retry_after_secs: retry_after_ms.div_ceil(1_000).max(1),
        },
        CoreDecision::Bypass { reason } => {
            tracing::error!(reason, "rate-limit core requested a bypass; denying");
            Decision::Deny {
                retry_after_secs: 1,
            }
        }
    }
}

fn is_safe_to_evict(policy: LimitPolicy, state: LimitState, now_ms: u64) -> bool {
    match (policy.algorithm, state) {
        (ores_rl_lib_core::Algorithm::TokenBucket, LimitState::TokenBucket(value)) => {
            let capacity_micros = u128::from(policy.capacity).saturating_mul(1_000_000);
            if now_ms < value.last_refill_ms {
                return false;
            }
            let refill = u128::from(now_ms - value.last_refill_ms)
                .saturating_mul(u128::from(policy.refill_tokens))
                .saturating_mul(1_000_000)
                / u128::from(policy.refill_interval_ms);
            u128::from(value.tokens_micros)
                .saturating_add(refill)
                .min(capacity_micros)
                >= capacity_micros
        }
        // Other algorithms retain a time-dependent watermark whose safe
        // eviction boundary is not represented by this adapter. Retaining
        // them is conservative if the shared core later exposes another
        // constructor.
        _ => false,
    }
}

fn parse_capacity(value: &str) -> Result<u64, RateLimitConfigError> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|capacity| *capacity > 0)
        .ok_or(RateLimitConfigError::InvalidSetting {
            name: BURST_SETTING,
            requirement: "expected a positive integer",
        })
}

fn parse_refill_rate(value: &str) -> Result<RefillRate, RateLimitConfigError> {
    let value = value.trim();
    let invalid = || RateLimitConfigError::InvalidSetting {
        name: RATE_SETTING,
        requirement: "expected a positive decimal with at most three fractional digits",
    };
    if value.is_empty() || value.starts_with(['+', '-']) {
        return Err(invalid());
    }

    let (whole, fractional) = match value.split_once('.') {
        Some((whole, fractional)) => {
            if fractional.is_empty() || fractional.contains('.') {
                return Err(invalid());
            }
            (whole, fractional)
        }
        None => (value, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }

    let scale = match fractional.len() {
        0 => 1,
        1 => 10,
        2 => 100,
        3 => 1_000,
        _ => return Err(invalid()),
    };
    let whole = whole.parse::<u64>().map_err(|_| invalid())?;
    let fractional = if fractional.is_empty() {
        0
    } else {
        fractional.parse::<u64>().map_err(|_| invalid())?
    };
    let numerator = whole
        .checked_mul(scale)
        .and_then(|scaled| scaled.checked_add(fractional))
        .filter(|value| *value > 0)
        .ok_or_else(invalid)?;
    let denominator_ms = 1_000_u64.checked_mul(scale).ok_or_else(invalid)?;
    let divisor = greatest_common_divisor(numerator, denominator_ms);
    Ok(RefillRate {
        tokens: numerator / divisor,
        interval_ms: denominator_ms / divisor,
    })
}

fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
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
    // Key on the token's hash, never the plaintext. The reusable core accepts
    // only opaque, already-derived principal keys.
    let key = crate::auth::hash_token(&token);
    match limiter.check(&key) {
        Decision::Allow => next.run(request).await,
        Decision::Deny { retry_after_secs } => {
            tracing::warn!(
                rate_limit_outcome = "deny",
                rate_limit_retry_after_secs = retry_after_secs,
                rate_limit_authority = "ores-rl-lib-core",
                "rate limit exceeded for an opaque token identity"
            );
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

    fn make_limiter(capacity: u64, refill_tokens: u64, refill_interval_ms: u64) -> RateLimiter {
        RateLimiter::new(capacity, refill_tokens, refill_interval_ms).expect("valid policy")
    }

    #[test]
    fn burst_is_allowed_then_the_bucket_empties() {
        let limiter = make_limiter(3, 1, 1_000);
        let now = Instant::now();
        for index in 0..3 {
            assert_eq!(
                limiter.check_at("tok", now),
                Decision::Allow,
                "burst {index}"
            );
        }
        match limiter.check_at("tok", now) {
            Decision::Deny { retry_after_secs } => assert!(retry_after_secs >= 1),
            other => panic!("expected the 4th request to be denied, got {other:?}"),
        }
    }

    #[test]
    fn the_bucket_refills_over_time() {
        let limiter = make_limiter(2, 10, 1_000);
        let start = Instant::now();
        assert_eq!(limiter.check_at("tok", start), Decision::Allow);
        assert_eq!(limiter.check_at("tok", start), Decision::Allow);
        assert!(matches!(
            limiter.check_at("tok", start),
            Decision::Deny { .. }
        ));
        let later = start + Duration::from_millis(150);
        assert_eq!(limiter.check_at("tok", later), Decision::Allow);
        assert!(matches!(
            limiter.check_at("tok", later),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn refill_never_exceeds_the_burst_ceiling() {
        let limiter = make_limiter(5, 1_000, 1_000);
        let start = Instant::now();
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
        let limiter = make_limiter(1, 1, 1_000_000);
        let now = Instant::now();
        assert_eq!(limiter.check_at("alice", now), Decision::Allow);
        assert!(matches!(
            limiter.check_at("alice", now),
            Decision::Deny { .. }
        ));
        assert_eq!(limiter.check_at("bob", now), Decision::Allow);
    }

    #[test]
    fn retry_after_reflects_the_refill_rate_and_is_never_zero() {
        let limiter = make_limiter(1, 1, 2_000);
        let now = Instant::now();
        assert_eq!(limiter.check_at("tok", now), Decision::Allow);
        assert_eq!(
            limiter.check_at("tok", now),
            Decision::Deny {
                retry_after_secs: 2
            }
        );

        let fast = make_limiter(1, 1_000, 1_000);
        let now = fast.epoch;
        assert_eq!(fast.check_at("tok", now), Decision::Allow);
        assert_eq!(
            fast.check_at("tok", now),
            Decision::Deny {
                retry_after_secs: 1
            }
        );
    }

    #[test]
    fn the_sweep_evicts_only_idle_buckets() {
        let limiter = make_limiter(5, 1, 1_000);
        let start = Instant::now();
        limiter.check_at("old", start);
        limiter.check_at("fresh", start + IDLE_EVICTION);
        assert_eq!(limiter.len(), 2);
        limiter.sweep_at(start + IDLE_EVICTION + Duration::from_secs(1));
        assert_eq!(limiter.len(), 1, "the idle bucket is dropped");
        assert_eq!(
            limiter.check_at("fresh", start + IDLE_EVICTION + Duration::from_secs(1)),
            Decision::Allow
        );
    }

    #[test]
    fn invalid_policy_values_fail_closed_instead_of_being_clamped() {
        assert!(RateLimiter::new(0, 1, 1_000).is_err());
        assert!(RateLimiter::new(1, 0, 1_000).is_err());
        assert!(RateLimiter::new(1, 1, 0).is_err());
    }

    #[test]
    fn a_core_bypass_is_not_an_allowance_at_the_enforcement_boundary() {
        assert_eq!(
            decision_from_core(CoreDecision::Bypass {
                reason: "policy-disabled"
            }),
            Decision::Deny {
                retry_after_secs: 1
            }
        );
    }

    #[test]
    fn legacy_decimal_rates_are_represented_exactly() {
        assert_eq!(
            parse_refill_rate("10.0").expect("rate"),
            RefillRate {
                tokens: 1,
                interval_ms: 100
            }
        );
        assert_eq!(
            parse_refill_rate("0.5").expect("rate"),
            RefillRate {
                tokens: 1,
                interval_ms: 2_000
            }
        );
        assert_eq!(
            parse_refill_rate("12.25").expect("rate"),
            RefillRate {
                tokens: 49,
                interval_ms: 4_000
            }
        );
        assert_eq!(
            parse_refill_rate("1.125").expect("rate"),
            RefillRate {
                tokens: 9,
                interval_ms: 8_000
            }
        );
    }

    #[test]
    fn invalid_decimal_rates_are_rejected_without_value_echo() {
        for value in ["", "0", "-1", "+1", ".5", "1.", "1.0001", "nan", "1.2.3"] {
            let error = parse_refill_rate(value).expect_err("invalid rate");
            let message = error.to_string();
            assert!(message.contains(RATE_SETTING));
            assert!(!message.contains(value) || value.is_empty());
        }
    }

    #[test]
    fn a_backwards_clock_transition_is_denied_without_replacing_state() {
        let limiter = make_limiter(2, 1, 1_000);
        let later = limiter.epoch + Duration::from_secs(1);
        assert_eq!(limiter.check_at("tok", later), Decision::Allow);
        assert!(matches!(
            limiter.check_at("tok", limiter.epoch),
            Decision::Deny { .. }
        ));
        assert_eq!(limiter.check_at("tok", later), Decision::Allow);
    }

    #[test]
    fn idle_eviction_never_restores_unearned_capacity() {
        let limiter = make_limiter(1, 1, 1_000_000);
        let start = limiter.epoch;
        assert_eq!(limiter.check_at("slow", start), Decision::Allow);
        limiter.sweep_at(start + IDLE_EVICTION);
        assert_eq!(limiter.len(), 1, "the idle bucket is not yet full");
        assert_eq!(
            limiter.check_at("slow", start + IDLE_EVICTION),
            Decision::Deny {
                retry_after_secs: 400
            }
        );
    }

    #[test]
    fn backwards_submillisecond_clock_preserves_capacity() {
        let limiter = make_limiter(2, 1, 1_000);
        let later = limiter.epoch + Duration::from_nanos(900);
        assert_eq!(limiter.check_at("tok", later), Decision::Allow);
        assert!(matches!(
            limiter.check_at("tok", limiter.epoch),
            Decision::Deny { .. }
        ));
        assert_eq!(limiter.check_at("tok", later), Decision::Allow);
    }

    #[test]
    fn eviction_does_not_erase_the_clock_watermark() {
        let limiter = make_limiter(1, 1, 1_000);
        let start = limiter.epoch;
        assert_eq!(limiter.check_at("tok", start), Decision::Allow);
        limiter.sweep_at(start + IDLE_EVICTION);
        assert_eq!(limiter.len(), 0);
        assert!(matches!(
            limiter.check_at("tok", start),
            Decision::Deny { .. }
        ));
        assert_eq!(limiter.len(), 0, "stale requests cannot allocate a bucket");
    }

    #[test]
    fn new_identities_are_rejected_at_the_memory_ceiling() {
        let limiter = make_limiter(1, 1, 1_000);
        let now = limiter.epoch;
        for index in 0..MAX_BUCKETS {
            assert_eq!(
                limiter.check_at(&format!("key-{index}"), now),
                Decision::Allow
            );
        }
        assert_eq!(limiter.len(), MAX_BUCKETS);
        assert_eq!(
            limiter.check_at("one-too-many", now),
            Decision::Deny {
                retry_after_secs: 1
            }
        );
        assert_eq!(limiter.len(), MAX_BUCKETS);
    }
}
