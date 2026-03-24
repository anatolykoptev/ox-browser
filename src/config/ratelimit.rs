//! Per-domain rate limit configuration.

use std::time::Duration;

use ox_http::DomainConfig;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct RatelimitSection {
    pub rules: Vec<RatelimitRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RatelimitRule {
    /// Domain pattern: exact "api.x.com", wildcard "*.x.com", or "" (catch-all).
    pub domain: String,
    pub requests_per_window: usize,
    pub window_secs: u64,
    #[serde(default)]
    pub min_delay_ms: u64,
    #[serde(default)]
    pub random_delay_ms: u64,
}

impl Default for RatelimitSection {
    fn default() -> Self {
        Self {
            rules: vec![
                RatelimitRule {
                    domain: "*.reddit.com".into(),
                    requests_per_window: 10,
                    window_secs: 60,
                    min_delay_ms: 2000,
                    random_delay_ms: 1000,
                },
                RatelimitRule {
                    domain: "*.x.com".into(),
                    requests_per_window: 40,
                    window_secs: 900,
                    min_delay_ms: 1000,
                    random_delay_ms: 500,
                },
                RatelimitRule {
                    domain: String::new(), // catch-all
                    requests_per_window: 30,
                    window_secs: 60,
                    min_delay_ms: 200,
                    random_delay_ms: 100,
                },
            ],
        }
    }
}

impl RatelimitSection {
    pub fn to_domain_configs(&self) -> Vec<DomainConfig> {
        self.rules
            .iter()
            .map(|r| DomainConfig {
                domain: r.domain.clone(),
                requests_per_window: r.requests_per_window,
                window_duration: Duration::from_secs(r.window_secs),
                min_delay: Duration::from_millis(r.min_delay_ms),
                random_delay: Duration::from_millis(r.random_delay_ms),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_catch_all() {
        let s = RatelimitSection::default();
        assert!(s.rules.iter().any(|r| r.domain.is_empty()));
    }

    #[test]
    fn converts_to_domain_configs() {
        let s = RatelimitSection::default();
        let configs = s.to_domain_configs();
        assert_eq!(configs.len(), s.rules.len());
        assert_eq!(configs[0].domain, "*.reddit.com");
    }
}
