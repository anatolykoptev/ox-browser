//! Retry with exponential backoff.
//!
//! Port of go-stealth's `retry.go`: [`RetryConfig`], [`backoff_duration`],
//! [`retry_do`], and [`is_retryable_status`].

use std::future::Future;
use std::time::Duration;

use rand::Rng;

use crate::error::HttpError;
use crate::Result;

/// Configuration for retry with exponential backoff.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: usize,
    pub initial_wait: Duration,
    pub max_wait: Duration,
    pub multiplier: f64,
    pub jitter_pct: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_wait: Duration::from_millis(500),
            max_wait: Duration::from_secs(10),
            multiplier: 2.0,
            jitter_pct: 0.3,
        }
    }
}

/// Compute backoff duration for the given attempt (0-indexed).
///
/// `wait = initial_wait * multiplier^attempt`, capped at `max_wait`.
/// Jitter adds `[-jitter_pct, +jitter_pct]` randomness.
pub fn backoff_duration(config: &RetryConfig, attempt: usize) -> Duration {
    let base =
        config.initial_wait.as_secs_f64() * config.multiplier.powi(attempt as i32);
    let capped = base.min(config.max_wait.as_secs_f64());

    let wait = if config.jitter_pct > 0.0 {
        let jitter_range = capped * config.jitter_pct;
        let jitter = rand::thread_rng().gen_range(-jitter_range..=jitter_range);
        (capped + jitter).max(0.0)
    } else {
        capped
    };

    Duration::from_secs_f64(wait)
}

/// Execute `f` with retries on retryable errors.
///
/// Calls `f` up to `config.max_retries + 1` times. Between attempts,
/// sleeps for [`backoff_duration`]. Non-retryable errors short-circuit.
pub async fn retry_do<T, F, Fut>(config: &RetryConfig, f: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut last_err: Option<HttpError> = None;

    for attempt in 0..=config.max_retries {
        match f().await {
            Ok(val) => return Ok(val),
            Err(err) => {
                if !err.is_retryable() {
                    return Err(err);
                }
                if attempt < config.max_retries {
                    let wait = backoff_duration(config, attempt);
                    tracing::debug!(
                        attempt = attempt + 1,
                        wait_ms = wait.as_millis() as u64,
                        error = %err,
                        "retrying"
                    );
                    last_err = Some(err);
                    tokio::time::sleep(wait).await;
                } else {
                    last_err = Some(err);
                }
            }
        }
    }

    Err(last_err.expect("at least one attempt must have run"))
}

/// Returns `true` for HTTP status codes that warrant a retry.
pub fn is_retryable_status(code: u16) -> bool {
    matches!(code, 429 | 500 | 502 | 503 | 504)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_exponential() {
        let cfg = RetryConfig { jitter_pct: 0.0, ..Default::default() };
        let d0 = backoff_duration(&cfg, 0);
        let d1 = backoff_duration(&cfg, 1);
        let d2 = backoff_duration(&cfg, 2);
        assert_eq!(d0, Duration::from_millis(500));
        assert_eq!(d1, Duration::from_millis(1000));
        assert_eq!(d2, Duration::from_millis(2000));
    }

    #[test]
    fn backoff_capped_at_max_wait() {
        let cfg = RetryConfig { jitter_pct: 0.0, ..Default::default() };
        let d10 = backoff_duration(&cfg, 10);
        assert_eq!(d10, cfg.max_wait);
    }

    #[test]
    fn retryable_status_codes() {
        assert!(is_retryable_status(429));
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(502));
        assert!(is_retryable_status(503));
        assert!(is_retryable_status(504));
        assert!(!is_retryable_status(200));
        assert!(!is_retryable_status(301));
        assert!(!is_retryable_status(404));
    }

    #[tokio::test]
    async fn retry_do_eventual_success() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);
        let cfg = RetryConfig {
            max_retries: 3,
            initial_wait: Duration::from_millis(1),
            max_wait: Duration::from_millis(10),
            jitter_pct: 0.0,
            ..Default::default()
        };

        let result = retry_do(&cfg, || {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(HttpError::RetryableStatus(503))
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_do_all_failures() {
        let cfg = RetryConfig {
            max_retries: 2,
            initial_wait: Duration::from_millis(1),
            max_wait: Duration::from_millis(10),
            jitter_pct: 0.0,
            ..Default::default()
        };

        let result: Result<i32> =
            retry_do(&cfg, || async { Err(HttpError::RetryableStatus(500)) }).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn retry_do_non_retryable_short_circuits() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);
        let cfg = RetryConfig {
            max_retries: 3,
            initial_wait: Duration::from_millis(1),
            max_wait: Duration::from_millis(10),
            jitter_pct: 0.0,
            ..Default::default()
        };

        let result: Result<i32> = retry_do(&cfg, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err(HttpError::InvalidUrl("bad".into())) }
        })
        .await;

        assert!(result.is_err());
        // Should have stopped after first attempt (non-retryable).
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
}
