//! Sliding-window rate limiter.
//!
//! Port of go-stealth's `ratelimit.Limiter`. Tracks request counts per key
//! within a sliding time window, with support for explicit block-until marking.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Configuration for a [`Limiter`].
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests allowed within one window.
    pub requests_per_window: usize,
    /// Duration of the sliding window.
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

/// Per-key sliding window state.
struct WindowState {
    count: usize,
    window_start: Instant,
    blocked_until: Option<Instant>,
}

/// A sliding-window rate limiter keyed by arbitrary strings.
///
/// Thread-safe: all mutable state is behind a [`Mutex`].
pub struct Limiter {
    config: RateLimitConfig,
    windows: Mutex<HashMap<String, WindowState>>,
}

impl Limiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Shorthand: create a `Limiter` from window size and duration.
    pub fn with_window(requests: usize, duration: Duration) -> Self {
        Self::new(RateLimitConfig {
            requests_per_window: requests,
            window_duration: duration,
        })
    }

    /// Check whether a request for `key` is allowed under the rate limit.
    ///
    /// If allowed, the window counter is incremented. If the window has
    /// expired, it is reset before checking.
    pub fn allow(&self, key: &str) -> bool {
        let mut windows = self.windows.lock().unwrap();
        let now = Instant::now();

        let state = windows.entry(key.to_string()).or_insert(WindowState {
            count: 0,
            window_start: now,
            blocked_until: None,
        });

        // Check explicit block.
        if let Some(until) = state.blocked_until {
            if now < until {
                return false;
            }
            state.blocked_until = None;
        }

        // Reset window if expired.
        if now.duration_since(state.window_start) >= self.config.window_duration {
            state.count = 0;
            state.window_start = now;
        }

        state.count += 1;
        state.count <= self.config.requests_per_window
    }

    /// Explicitly block `key` until the given instant (e.g. from a 429
    /// `Retry-After` header).
    pub fn mark_rate_limited(&self, key: &str, until: Instant) {
        let mut windows = self.windows.lock().unwrap();
        let now = Instant::now();
        let state = windows.entry(key.to_string()).or_insert(WindowState {
            count: 0,
            window_start: now,
            blocked_until: None,
        });
        state.blocked_until = Some(until);
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
}
