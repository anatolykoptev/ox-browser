//! Retry with exponential backoff configuration.

use std::time::Duration;

use ox_http::RetryConfig;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct RetrySection {
    pub max_retries: usize,
    pub initial_wait_ms: u64,
    pub max_wait_ms: u64,
    pub multiplier: f64,
    pub jitter_pct: f64,
}

impl Default for RetrySection {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_wait_ms: 500,
            max_wait_ms: 10_000,
            multiplier: 2.0,
            jitter_pct: 0.3,
        }
    }
}

impl RetrySection {
    /// Convert to ox-http RetryConfig.
    pub fn to_retry_config(&self) -> RetryConfig {
        RetryConfig {
            max_retries: self.max_retries,
            initial_wait: Duration::from_millis(self.initial_wait_ms),
            max_wait: Duration::from_millis(self.max_wait_ms),
            multiplier: self.multiplier,
            jitter_pct: self.jitter_pct,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion() {
        let s = RetrySection::default();
        let r = s.to_retry_config();
        assert_eq!(r.max_retries, 3);
        assert_eq!(r.initial_wait, Duration::from_millis(500));
        assert_eq!(r.max_wait, Duration::from_secs(10));
        assert_eq!(r.multiplier, 2.0);
    }
}
