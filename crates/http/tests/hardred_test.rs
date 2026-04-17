//! Hard red tests: each exposes a real bug in the current code.
//!
//! These tests FAIL on the pre-fix code, proving the bug exists.
//! After fixes, they go green.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ox_http::{
    HttpClient, HttpConfig, ProxyHealth, ProxyPool, RetryConfig, StaticPool, backoff_duration,
    parse_retry_after,
};

// ── Bug 1: backoff_duration i32 overflow ─────────────────────────────
//
// `attempt as i32` wraps for large usize values. `2.0.powi(-1)` = 0.5,
// so backoff becomes SMALLER than initial_wait instead of being capped
// at max_wait.

#[test]
fn backoff_huge_attempt_capped_at_max() {
    let cfg = RetryConfig {
        jitter_pct: 0.0,
        ..Default::default()
    };
    let d = backoff_duration(&cfg, usize::MAX);
    assert_eq!(
        d, cfg.max_wait,
        "huge attempt should be capped at max_wait, got {d:?}"
    );
}

// ── Bug 2: parse_retry_after accepts invalid dates ───────────────────
//
// days_from_civil only checks 1..=31 range but doesn't validate per-month
// limits. Feb 30, Apr 31, etc. produce wrong timestamps silently.

#[test]
fn parse_retry_after_feb_30_rejected() {
    let result = parse_retry_after("Wed, 30 Feb 2027 00:00:00 GMT");
    assert!(result.is_none(), "Feb 30 is invalid, should return None");
}

#[test]
fn parse_retry_after_apr_31_rejected() {
    let result = parse_retry_after("Thu, 31 Apr 2027 00:00:00 GMT");
    assert!(result.is_none(), "Apr 31 is invalid, should return None");
}

// ── Bug 2b: year 0 causes arithmetic overflow / panic ────────────────
//
// year.wrapping_sub(1) for year=0 produces u64::MAX. Subsequent
// multiplication overflows and panics in debug mode.

#[test]
fn parse_retry_after_year_zero_no_panic() {
    let result = parse_retry_after("Mon, 01 Jan 0000 00:00:00 GMT");
    assert!(result.is_none(), "year 0 should return None, not panic");
}

// ── Bug 3: avg_latency u32 truncation ────────────────────────────────
//
// `self.total_latency / total as u32` silently truncates total when it
// exceeds u32::MAX (~4 billion), producing wrong average.

#[test]
fn avg_latency_large_count_no_truncation() {
    let h = ProxyHealth {
        successes: 5_000_000_000,
        failures: 0,
        total_latency: Duration::from_secs(5_000_000_000),
        last_used: Instant::now(),
        deactivated_at: None,
    };
    let avg = h.avg_latency();
    assert_eq!(avg, Duration::from_secs(1), "avg should be 1s, got {avg:?}");
}

// ── Bug 4: proxy pool sampled once during construction ───────────────
//
// build_wreq_client calls pool.next() once and configures the wreq
// Client with a single static proxy. All requests go through the SAME
// proxy — the pool's round-robin rotation is completely useless.

struct TrackingPool {
    inner: StaticPool,
    call_count: AtomicUsize,
}

impl TrackingPool {
    fn new(proxies: Vec<String>) -> Self {
        Self {
            inner: StaticPool::new(proxies),
            call_count: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

impl ProxyPool for TrackingPool {
    fn next(&self) -> Option<String> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.inner.next()
    }
    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[test]
fn proxy_pool_not_consumed_during_construction() {
    let pool = Arc::new(TrackingPool::new(vec![
        "http://p1:8080".into(),
        "http://p2:8080".into(),
    ]));
    let pool_dyn: Arc<dyn ProxyPool> = pool.clone();
    let config = HttpConfig {
        proxy_pool: Some(pool_dyn),
        ..HttpConfig::default()
    };
    let _client = HttpClient::new(config).unwrap();
    assert_eq!(
        pool.calls(),
        0,
        "proxy pool should not be sampled during client construction"
    );
}

// ── Edge case tests (should pass, increase coverage) ─────────────────

#[test]
fn backoff_infinity_capped_at_max() {
    let cfg = RetryConfig {
        multiplier: 10.0,
        jitter_pct: 0.0,
        ..Default::default()
    };
    // 10^1000 = infinity, but should be capped at max_wait
    let d = backoff_duration(&cfg, 1000);
    assert_eq!(d, cfg.max_wait);
}

#[test]
fn parse_retry_after_zero_seconds() {
    let result = parse_retry_after("0");
    assert_eq!(result, Some(Duration::ZERO));
}

#[test]
fn parse_retry_after_large_seconds() {
    let result = parse_retry_after("86400");
    assert_eq!(result, Some(Duration::from_secs(86400)));
}

#[test]
fn parse_retry_after_negative_rejected() {
    let result = parse_retry_after("-5");
    assert!(result.is_none());
}

#[test]
fn parse_retry_after_empty_rejected() {
    let result = parse_retry_after("");
    assert!(result.is_none());
}

#[test]
fn parse_retry_after_whitespace_only() {
    let result = parse_retry_after("   ");
    assert!(result.is_none());
}

#[test]
fn parse_retry_after_feb_29_leap_year_accepted() {
    // 2028 is a leap year — Feb 29 is valid
    let result = parse_retry_after("Tue, 29 Feb 2028 00:00:00 GMT");
    assert!(result.is_some(), "Feb 29 in leap year should be accepted");
}

#[test]
fn parse_retry_after_feb_29_non_leap_rejected() {
    // 2027 is NOT a leap year — Feb 29 is invalid
    let result = parse_retry_after("Mon, 29 Feb 2027 00:00:00 GMT");
    assert!(
        result.is_none(),
        "Feb 29 in non-leap year should be rejected"
    );
}
