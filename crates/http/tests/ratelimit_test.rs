use std::time::{Duration, Instant};

use ox_http::{DomainConfig, DomainLimiter, Limiter, RateLimitConfig};

#[test]
fn limiter_allows_initially() {
    let limiter = Limiter::new(RateLimitConfig::default());
    assert!(limiter.allow("test"), "first request should be allowed");
}

#[test]
fn limiter_blocks_after_exceeding_limit() {
    let limiter = Limiter::new(RateLimitConfig {
        requests_per_window: 2,
        window_duration: Duration::from_secs(60),
    });
    assert!(limiter.allow("k"));
    assert!(limiter.allow("k"));
    assert!(!limiter.allow("k"), "third request should be blocked");
}

#[test]
fn limiter_separate_keys_are_independent() {
    let limiter = Limiter::new(RateLimitConfig {
        requests_per_window: 1,
        window_duration: Duration::from_secs(60),
    });
    assert!(limiter.allow("a"));
    assert!(limiter.allow("b"));
    assert!(!limiter.allow("a"), "a should be blocked");
    assert!(!limiter.allow("b"), "b should be blocked");
}

#[test]
fn domain_limiter_allows_known_domains() {
    let dl = DomainLimiter::new(vec![DomainConfig {
        domain: "example.com".into(),
        requests_per_window: 100,
        window_duration: Duration::from_secs(60),
        min_delay: Duration::ZERO,
        random_delay: Duration::ZERO,
    }]);
    assert!(dl.allow("https://example.com/page1"));
    assert!(dl.allow("https://example.com/page2"));
}

#[test]
fn domain_limiter_wildcard_catches_subdomains() {
    let dl = DomainLimiter::new(vec![DomainConfig {
        domain: String::new(), // catch-all
        requests_per_window: 100,
        window_duration: Duration::from_secs(60),
        min_delay: Duration::ZERO,
        random_delay: Duration::ZERO,
    }]);
    assert!(dl.allow("https://a.example.com/x"));
    assert!(dl.allow("https://b.other.org/y"));
}

#[test]
fn domain_limiter_mark_rate_limited_blocks() {
    let dl = DomainLimiter::new(vec![DomainConfig {
        domain: "example.com".into(),
        requests_per_window: 100,
        window_duration: Duration::from_secs(60),
        min_delay: Duration::ZERO,
        random_delay: Duration::ZERO,
    }]);
    // First request to create the limiter entry.
    assert!(dl.allow("https://example.com/a"));
    // Mark as rate-limited for 60 seconds.
    dl.mark_rate_limited(
        "https://example.com/b",
        Instant::now() + Duration::from_secs(60),
    );
    assert!(
        !dl.allow("https://example.com/c"),
        "should be blocked after mark_rate_limited"
    );
}
