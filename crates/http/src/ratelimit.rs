//! Token-bucket (GCRA) rate limiter.
//!
//! `requests_per_window` requests may burst at once; the bucket then refills
//! continuously at `requests_per_window / window_duration`. The state per key
//! is one timestamp (the generic cell rate algorithm's theoretical arrival
//! time), so a check is O(1) and a refused check changes nothing — it only
//! reports how long until a permit is due, which lets the caller sleep exactly
//! that long (or give up against a deadline) instead of polling.
//!
//! This replaced a fixed 60 s window that reset only at its boundary: a
//! serial 1 rps client hit request 31 of a 30/60 s rule, slept ~30 s to the
//! boundary, and blew its call deadline. Here the same client is slowed to the
//! refill rate in steps of one emission interval (2 s for 30/60 s), never
//! stalled for half a window.
//!
//! Time comes from `tokio::time::Instant`, so tests drive it with a paused
//! clock.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// Configuration for a [`Limiter`].
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Burst size, and the number of requests refilled per `window_duration`.
    pub requests_per_window: usize,
    /// Time over which `requests_per_window` permits are refilled.
    pub window_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_window: 50,
            window_duration: Duration::from_secs(15 * 60),
        }
    }
}

/// Per-key state: the theoretical arrival time of the bucket, plus an
/// explicit block (e.g. an upstream 429 `Retry-After`).
#[derive(Default)]
struct KeyState {
    /// When the bucket would be empty again; `None` = never used.
    tat: Option<Instant>,
    blocked_until: Option<Instant>,
}

/// A token-bucket rate limiter keyed by arbitrary strings.
///
/// Thread-safe: all mutable state is behind a [`Mutex`].
pub struct Limiter {
    config: RateLimitConfig,
    keys: Mutex<HashMap<String, KeyState>>,
}

impl Limiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Shorthand: create a `Limiter` from window size and duration.
    pub fn with_window(requests: usize, duration: Duration) -> Self {
        Self::new(RateLimitConfig {
            requests_per_window: requests,
            window_duration: duration,
        })
    }

    /// Try to admit one request for `key`.
    ///
    /// `Ok(())` consumes a permit. `Err(wait)` consumes nothing: `wait` is the
    /// time until a permit is due (an explicit block counts, and wins when it
    /// is later).
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        let window = self.config.window_duration;
        let burst = self.config.requests_per_window;
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let state = keys.entry(key.to_string()).or_default();

        if let Some(until) = state.blocked_until {
            if now < until {
                return Err(until - now);
            }
            state.blocked_until = None;
        }

        // A zero-burst rule can never admit; report one full window.
        if burst == 0 {
            return Err(window);
        }
        let emission = window / u32::try_from(burst).unwrap_or(u32::MAX);
        let new_tat = state.tat.map_or(now, |t| t.max(now)) + emission;
        // The bucket holds `burst` emissions: the request is due once the
        // backlog it would create fits in one window.
        let backlog = new_tat - now;
        if backlog > window {
            return Err(backlog - window);
        }
        state.tat = Some(new_tat);
        Ok(())
    }

    /// Boolean form of [`Limiter::check`].
    pub fn allow(&self, key: &str) -> bool {
        self.check(key).is_ok()
    }

    /// Explicitly block `key` until the given instant (e.g. from a 429
    /// `Retry-After` header).
    pub fn mark_rate_limited(&self, key: &str, until: impl Into<Instant>) {
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        keys.entry(key.to_string()).or_default().blocked_until = Some(until.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_within_limit() {
        let limiter = Limiter::new(RateLimitConfig {
            requests_per_window: 3,
            window_duration: Duration::from_secs(60),
        });
        assert!(limiter.allow("a"));
        assert!(limiter.allow("a"));
        assert!(limiter.allow("a"));
    }

    #[test]
    fn block_after_limit() {
        let limiter = Limiter::new(RateLimitConfig {
            requests_per_window: 2,
            window_duration: Duration::from_secs(60),
        });
        assert!(limiter.allow("a"));
        assert!(limiter.allow("a"));
        assert!(!limiter.allow("a"));
    }

    #[test]
    fn blocked_until_respected() {
        let limiter = Limiter::new(RateLimitConfig::default());
        limiter.mark_rate_limited("a", Instant::now() + Duration::from_secs(60));
        assert!(!limiter.allow("a"));
    }

    #[test]
    fn blocked_until_expires() {
        let limiter = Limiter::new(RateLimitConfig::default());
        // Block until a time already in the past.
        limiter.mark_rate_limited(
            "a",
            Instant::now()
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        );
        assert!(limiter.allow("a"));
    }

    #[test]
    fn separate_keys_independent() {
        let limiter = Limiter::new(RateLimitConfig {
            requests_per_window: 1,
            window_duration: Duration::from_secs(60),
        });
        assert!(limiter.allow("a"));
        assert!(limiter.allow("b"));
        assert!(!limiter.allow("a"));
        assert!(!limiter.allow("b"));
    }

    #[test]
    fn zero_burst_never_admits() {
        let limiter = Limiter::with_window(0, Duration::from_secs(60));
        assert_eq!(limiter.check("k"), Err(Duration::from_secs(60)));
    }

    /// The incident: 30/60 s and a serial 1 rps client. The fixed window made
    /// request 31 sleep ~30 s to the boundary. The bucket admits it on the
    /// spot (it has refilled 15 permits by then) and later slows the client
    /// to the refill rate in single 2 s steps — never a half-window stall.
    #[tokio::test(start_paused = true)]
    async fn request_31_at_one_rps_does_not_stall() {
        let limiter = Limiter::with_window(30, Duration::from_secs(60));
        for i in 0..30 {
            assert_eq!(limiter.check("k"), Ok(()), "request {}", i + 1);
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert_eq!(limiter.check("k"), Ok(()), "request 31 stalled");

        // Keep going at 1 rps for 5 more minutes: the longest wait is one
        // emission interval, not a window.
        let mut max_wait = Duration::ZERO;
        for _ in 0..300 {
            tokio::time::advance(Duration::from_secs(1)).await;
            if let Err(wait) = limiter.check("k") {
                max_wait = max_wait.max(wait);
                tokio::time::advance(wait).await;
                assert_eq!(limiter.check("k"), Ok(()));
            }
        }
        assert!(
            max_wait <= Duration::from_secs(2),
            "longest wait {max_wait:?}"
        );
    }

    /// Below the refill rate a serial client is never refused, however long
    /// it runs.
    #[tokio::test(start_paused = true)]
    async fn rate_below_limit_never_waits() {
        let limiter = Limiter::with_window(120, Duration::from_secs(60));
        for i in 0..400 {
            assert_eq!(limiter.check("k"), Ok(()), "request {i} stalled");
            tokio::time::advance(Duration::from_secs(1)).await;
        }
    }

    /// A refused check must not consume a permit: 1000 polls while empty
    /// leave the next permit due exactly when it was due before.
    #[tokio::test(start_paused = true)]
    async fn denied_polls_do_not_consume_quota() {
        let limiter = Limiter::with_window(2, Duration::from_secs(60));
        assert!(limiter.allow("k"));
        assert!(limiter.allow("k"));
        let due = limiter.check("k").unwrap_err();
        assert_eq!(due, Duration::from_secs(30));
        for _ in 0..1000 {
            assert!(!limiter.allow("k"));
        }
        assert_eq!(limiter.check("k"), Err(due), "polling moved the due time");
        tokio::time::advance(due).await;
        assert!(limiter.allow("k"), "permit not granted on time");
        assert!(!limiter.allow("k"));
    }

    #[tokio::test(start_paused = true)]
    async fn check_reports_block_remaining() {
        let limiter = Limiter::with_window(10, Duration::from_secs(60));
        limiter.mark_rate_limited("k", Instant::now() + Duration::from_secs(7));
        assert_eq!(limiter.check("k"), Err(Duration::from_secs(7)));
        tokio::time::advance(Duration::from_secs(7)).await;
        assert_eq!(limiter.check("k"), Ok(()));
    }
}
