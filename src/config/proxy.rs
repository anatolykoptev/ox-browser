//! Proxy pool and health tracking configuration.

use std::time::Duration;

use ox_http::HealthConfig;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ProxySection {
    pub url: Option<String>,
    pub webshare_timeout_secs: u64,
    pub health: ProxyHealthSection,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ProxyHealthSection {
    /// Failure rate (0.0-1.0) above which a proxy is deactivated.
    pub failure_threshold: f64,
    /// Minimum requests before the failure threshold is evaluated.
    pub min_requests: u64,
    /// How long a deactivated proxy stays offline (seconds).
    pub cooldown_secs: u64,
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            url: None,
            webshare_timeout_secs: 10,
            health: ProxyHealthSection::default(),
        }
    }
}

impl Default for ProxyHealthSection {
    fn default() -> Self {
        Self {
            failure_threshold: 0.5,
            min_requests: 3,
            cooldown_secs: 300,
        }
    }
}

impl ProxyHealthSection {
    /// Convert to ox-http HealthConfig.
    #[allow(dead_code)]
    pub fn to_health_config(&self) -> HealthConfig {
        HealthConfig {
            failure_threshold: self.failure_threshold,
            min_requests: self.min_requests,
            cooldown: Duration::from_secs(self.cooldown_secs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_config_conversion() {
        let s = ProxyHealthSection::default();
        let h = s.to_health_config();
        assert_eq!(h.failure_threshold, 0.5);
        assert_eq!(h.min_requests, 3);
        assert_eq!(h.cooldown, Duration::from_secs(300));
    }
}
