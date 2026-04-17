use std::time::Duration;

use ox_http::{RetryConfig, backoff_duration, is_retryable_status, parse_retry_after};

#[test]
fn backoff_increases_with_attempt() {
    let cfg = RetryConfig {
        jitter_pct: 0.0,
        ..Default::default()
    };
    let d0 = backoff_duration(&cfg, 0);
    let d1 = backoff_duration(&cfg, 1);
    let d2 = backoff_duration(&cfg, 2);
    assert!(d1 > d0, "attempt 1 should be longer than attempt 0");
    assert!(d2 > d1, "attempt 2 should be longer than attempt 1");
}

#[test]
fn backoff_capped_at_max_wait() {
    let cfg = RetryConfig {
        jitter_pct: 0.0,
        ..Default::default()
    };
    let d = backoff_duration(&cfg, 20);
    assert_eq!(d, cfg.max_wait, "should be capped at max_wait");
}

#[test]
fn retryable_status_true_for_server_errors() {
    for code in [429, 500, 502, 503, 504] {
        assert!(is_retryable_status(code), "{code} should be retryable");
    }
}

#[test]
fn retryable_status_false_for_client_responses() {
    for code in [200, 301, 400, 403, 404] {
        assert!(!is_retryable_status(code), "{code} should not be retryable");
    }
}

#[test]
fn parse_retry_after_integer_seconds() {
    assert_eq!(parse_retry_after("5"), Some(Duration::from_secs(5)));
    assert_eq!(parse_retry_after("120"), Some(Duration::from_secs(120)));
    assert_eq!(parse_retry_after(" 10 "), Some(Duration::from_secs(10)));
}

#[test]
fn parse_retry_after_garbage_returns_none() {
    assert_eq!(parse_retry_after("abc"), None);
    assert_eq!(parse_retry_after(""), None);
    assert_eq!(parse_retry_after("not-a-date-either"), None);
}
