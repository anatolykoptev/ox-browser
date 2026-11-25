//! Keyed rate limiter: a [`governor`] GCRA token bucket per key, combined with
//! a minimum gap between admissions and an explicit block-until (an origin's
//! `Retry-After`).
//!
//! `requests_per_window` requests may burst at once; permits then return at
//! `requests_per_window / window_duration`. Every constraint is evaluated in
//! one critical section, and a refusal reports the **latest** time any of them
//! allows (gap, block, bucket) — never an optimistic figure from just the one
//! that happened to be checked first. A refusal consumes nothing, with one
//! bookkeeping exception: `governor` cannot peek, so the first check that
//! finds the bucket open while the gap or block still holds *reserves* that
//! permit (`prepaid`) and the next admission for the key spends the reserve
//! instead of a second one. Polling a closed gap 1000 times costs one permit,
//! the one the admission will cost anyway.
//!
//! This replaced a fixed 60 s window that reset only at its boundary: a
//! serial 1 rps client hit request 31 of a 30/60 s rule, slept ~30 s to the
//! boundary, and blew its call deadline. Here the same client is slowed to the
//! refill rate in steps of one emission interval (2 s for 30/60 s).
//!
//! Time comes from `tokio::time::Instant` (through [`TokioClock`]), so tests
//! drive it with a paused clock.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Mutex;
use std::time::Duration;

use governor::clock::Clock;
use governor::middleware::NoOpMiddleware;
use governor::nanos::Nanos;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use tokio::time::Instant;

/// `governor` time source backed by tokio's clock, so a paused test runtime
/// moves the bucket and every other timestamp here together.
#[derive(Debug, Clone, Copy)]
pub struct TokioClock {
    base: Instant,
}

impl TokioClock {
    fn new() -> Self {
        Self {
            base: Instant::now(),
        }
    }
}

impl Clock for TokioClock {
    type Instant = Nanos;

    fn now(&self) -> Nanos {
        Nanos::from(Instant::now().saturating_duration_since(self.base))
    }
}

type Bucket = RateLimiter<NotKeyed, InMemoryState, TokioClock, NoOpMiddleware<Nanos>>;

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

impl RateLimitConfig {
    /// The `governor` quota for this config. Degenerate values (zero burst,
    /// a window shorter than one nanosecond per permit) are clamped here
    /// rather than panicking; user-supplied configs are rejected up front by
    /// the config loader, so this is a backstop for programmatic use.
    fn quota(&self) -> Quota {
        let burst = u32::try_from(self.requests_per_window)
            .unwrap_or(u32::MAX)
            .max(1);
        let period = (self.window_duration / burst).max(Duration::from_nanos(1));
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        Quota::with_period(period)
            .unwrap_or_else(|| Quota::per_second(NonZeroU32::MIN))
            .allow_burst(burst)
    }
}

/// Per-key state.
struct KeyState {
    bucket: Bucket,
    /// An origin cooldown (e.g. `Retry-After` on a 429); never shortened.
    blocked_until: Option<Instant>,
    /// A bucket permit already taken for the next admission (see module docs).
    prepaid: bool,
    last_admit: Option<Instant>,
    last_used: Instant,
}

/// A keyed rate limiter. Thread-safe: all state is behind one [`Mutex`].
pub struct Limiter {
    config: RateLimitConfig,
    clock: TokioClock,
    keys: Mutex<HashMap<String, KeyState>>,
}

impl Limiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            clock: TokioClock::new(),
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

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, KeyState>> {
        self.keys.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn new_state(&self, now: Instant) -> KeyState {
        KeyState {
            bucket: RateLimiter::direct_with_clock(self.config.quota(), self.clock),
            blocked_until: None,
            prepaid: false,
            last_admit: None,
            last_used: now,
        }
    }

    /// Try to admit one request for `key`: [`Limiter::check_gap`] with no gap.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        self.check_gap(key, Duration::ZERO)
    }

    /// Try to admit one request for `key`, also requiring `gap` since the
    /// previous admission.
    ///
    /// `Ok(())` admits. `Err(wait)` admits nothing and `wait` is when the
    /// request would next be allowed: the maximum over the gap, the explicit
    /// block and the bucket.
    pub fn check_gap(&self, key: &str, gap: Duration) -> Result<(), Duration> {
        let mut keys = self.lock();
        // Sampled inside the critical section so the decision and the clock
        // reading cannot be separated by a preempted thread.
        let now = Instant::now();
        let state = keys
            .entry(key.to_string())
            .or_insert_with(|| self.new_state(now));
        state.last_used = now;

        let block = match state.blocked_until {
            Some(until) if until > now => until - now,
            Some(_) => {
                state.blocked_until = None;
                Duration::ZERO
            }
            None => Duration::ZERO,
        };
        let gap_wait = state.last_admit.map_or(Duration::ZERO, |prev| {
            prev.checked_add(gap)
                .map_or(Duration::MAX, |due| due.saturating_duration_since(now))
        });
        let bucket_wait = if state.prepaid {
            Duration::ZERO
        } else {
            match state.bucket.check() {
                Ok(()) => {
                    state.prepaid = true;
                    Duration::ZERO
                }
                Err(not_until) => not_until.wait_time_from(self.clock.now()),
            }
        };

        let wait = block.max(gap_wait).max(bucket_wait);
        if !wait.is_zero() {
            return Err(wait);
        }
        state.prepaid = false;
        state.last_admit = Some(now);
        Ok(())
    }

    /// Boolean form of [`Limiter::check`].
    pub fn allow(&self, key: &str) -> bool {
        self.check(key).is_ok()
    }

    /// Block `key` until the given instant (e.g. from a 429 `Retry-After`).
    /// A later block is never replaced by an earlier one.
    pub fn mark_rate_limited(&self, key: &str, until: impl Into<Instant>) {
        let until = until.into();
        let mut keys = self.lock();
        let now = Instant::now();
        let state = keys
            .entry(key.to_string())
            .or_insert_with(|| self.new_state(now));
        state.last_used = now;
        state.blocked_until = Some(state.blocked_until.map_or(until, |cur| cur.max(until)));
    }

    /// Drop keys idle for longer than `max_idle` that carry no active block.
    pub fn evict_idle(&self, max_idle: Duration) {
        let now = Instant::now();
        self.lock().retain(|_, s| {
            s.blocked_until.is_some_and(|u| u > now)
                || now.saturating_duration_since(s.last_used) <= max_idle
        });
    }

    /// Number of tracked keys.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// True if no key is tracked.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
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
    fn degenerate_config_is_clamped_not_a_panic() {
        // Zero burst behaves as one permit per window; zero window as the
        // finest period. Neither panics (the loader rejects both up front).
        assert!(Limiter::with_window(0, Duration::from_secs(60)).allow("k"));
        assert!(Limiter::with_window(5, Duration::ZERO).allow("k"));
    }

    /// The incident: 30/60 s and a serial 1 rps client. The fixed window made
    /// request 31 sleep ~30 s to the boundary. The bucket admits it on the
    /// spot (it has refilled 15 permits by then) and later slows the client
    /// to the refill rate in single 2 s steps, never a half-window stall.
    #[tokio::test(start_paused = true)]
    async fn request_31_at_one_rps_does_not_stall() {
        let limiter = Limiter::with_window(30, Duration::from_secs(60));
        for i in 0..30 {
            assert_eq!(limiter.check("k"), Ok(()), "request {}", i + 1);
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert_eq!(limiter.check("k"), Ok(()), "request 31 stalled");

        // Five more minutes at 1 rps: sustained admissions track the refill
        // rate (0.5/s) and the longest single wait is one emission interval.
        let start = Instant::now();
        let mut admitted = 0u32;
        let mut max_wait = Duration::ZERO;
        while start.elapsed() < Duration::from_secs(300) {
            tokio::time::advance(Duration::from_secs(1)).await;
            match limiter.check("k") {
                Ok(()) => admitted += 1,
                Err(wait) => {
                    max_wait = max_wait.max(wait);
                    tokio::time::advance(wait).await;
                    assert_eq!(limiter.check("k"), Ok(()));
                    admitted += 1;
                }
            }
        }
        assert!(
            max_wait <= Duration::from_secs(2),
            "longest wait {max_wait:?}"
        );
        // 300 s at 0.5/s refill plus the remaining bucket: far fewer than 1 rps
        // would give if the limit were not enforced, at least the refill rate.
        assert!((150..=225).contains(&admitted), "admitted {admitted}");
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

    /// Polling while only the gap denies costs at most the one permit the
    /// admission will cost anyway: burst 3, 1000 polls inside a 1 s gap, and
    /// still exactly 3 admissions before the bucket is empty.
    #[tokio::test(start_paused = true)]
    async fn polls_inside_the_gap_reserve_one_permit_not_many() {
        let limiter = Limiter::with_window(3, Duration::from_secs(60));
        let gap = Duration::from_secs(1);
        assert_eq!(limiter.check_gap("k", gap), Ok(()));
        for _ in 0..1000 {
            assert!(limiter.check_gap("k", gap).is_err());
        }
        tokio::time::advance(gap).await;
        assert_eq!(limiter.check_gap("k", gap), Ok(()));
        tokio::time::advance(gap).await;
        assert_eq!(limiter.check_gap("k", gap), Ok(()));
        tokio::time::advance(gap).await;
        assert!(limiter.check_gap("k", gap).is_err(), "4th must wait");
    }

    /// The advertised wait is the MAX over every constraint, not the first one
    /// that happened to deny: gap 1 s, block 7 s, bucket 30 s -> 30 s; with the
    /// bucket open the block (7 s) wins over the gap.
    #[tokio::test(start_paused = true)]
    async fn refusal_advertises_the_latest_constraint() {
        let limiter = Limiter::with_window(2, Duration::from_secs(60));
        let gap = Duration::from_secs(1);
        assert_eq!(limiter.check_gap("k", gap), Ok(()));
        tokio::time::advance(gap).await;
        assert_eq!(limiter.check_gap("k", gap), Ok(())); // bucket now empty
        limiter.mark_rate_limited("k", Instant::now() + Duration::from_secs(7));
        // gap due in 1 s, block in 7 s, bucket in 29 s (30 s emission - 1 s).
        assert_eq!(limiter.check_gap("k", gap), Err(Duration::from_secs(29)));

        let open = Limiter::with_window(100, Duration::from_secs(60));
        assert_eq!(open.check_gap("k", gap), Ok(()));
        open.mark_rate_limited("k", Instant::now() + Duration::from_secs(7));
        assert_eq!(open.check_gap("k", gap), Err(Duration::from_secs(7)));
    }

    #[tokio::test(start_paused = true)]
    async fn check_reports_block_remaining() {
        let limiter = Limiter::with_window(10, Duration::from_secs(60));
        limiter.mark_rate_limited("k", Instant::now() + Duration::from_secs(7));
        assert_eq!(limiter.check("k"), Err(Duration::from_secs(7)));
        tokio::time::advance(Duration::from_secs(7)).await;
        assert_eq!(limiter.check("k"), Ok(()));
    }

    /// A shorter cooldown never replaces a longer one.
    #[tokio::test(start_paused = true)]
    async fn shorter_block_does_not_shorten_a_longer_one() {
        let limiter = Limiter::with_window(10, Duration::from_secs(60));
        limiter.mark_rate_limited("k", Instant::now() + Duration::from_secs(60));
        limiter.mark_rate_limited("k", Instant::now() + Duration::from_secs(5));
        assert_eq!(limiter.check("k"), Err(Duration::from_secs(60)));
    }

    /// Eviction keeps a key with an active block however idle it is.
    #[tokio::test(start_paused = true)]
    async fn evict_idle_keeps_active_blocks() {
        let limiter = Limiter::with_window(10, Duration::from_secs(60));
        assert!(limiter.allow("idle"));
        limiter.mark_rate_limited("blocked", Instant::now() + Duration::from_secs(600));
        tokio::time::advance(Duration::from_secs(300)).await;
        limiter.evict_idle(Duration::from_secs(120));
        assert_eq!(limiter.len(), 1);
        assert!(limiter.check("blocked").is_err(), "block survived eviction");
    }
}
