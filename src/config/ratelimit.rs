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
                    // JSON finance APIs (chart/quote/search) answer in
                    // milliseconds and are called in tight serial loops by
                    // market-data consumers: a burst of 120, then 2 req/s,
                    // no inter-request gap, a few ms of jitter. Must precede
                    // the catch-all or its 30/60 s + 200 ms gap applies.
                    domain: "*.finance.yahoo.com".into(),
                    requests_per_window: 120,
                    window_secs: 60,
                    min_delay_ms: 0,
                    random_delay_ms: 50,
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

    /// The Yahoo rule must win over the catch-all for the hosts copytrade
    /// calls. Moving it below the catch-all (first match wins) puts
    /// `query1.finance.yahoo.com` back on 30/60 s and this goes RED.
    #[test]
    fn yahoo_finance_rule_matches_before_catch_all() {
        let limiter = ox_http::DomainLimiter::new(RatelimitSection::default().to_domain_configs());
        for host in ["query1.finance.yahoo.com", "query2.finance.yahoo.com"] {
            assert_eq!(
                limiter.rule_name(&format!("https://{host}/v8/finance/chart/AAPL")),
                Some("*.finance.yahoo.com"),
                "{host}"
            );
        }
        // The bare apex and other Yahoo properties are not JSON finance APIs.
        assert_eq!(
            limiter.rule_name("https://finance.yahoo.com/quote/AAPL"),
            Some("catch_all")
        );
        assert_eq!(limiter.rule_name("https://example.com/"), Some("catch_all"));
    }

    #[test]
    fn yahoo_finance_rule_has_no_min_gap_and_a_120_burst() {
        let s = RatelimitSection::default();
        let r = s
            .rules
            .iter()
            .find(|r| r.domain == "*.finance.yahoo.com")
            .expect("yahoo rule");
        assert_eq!((r.requests_per_window, r.window_secs), (120, 60));
        assert_eq!(r.min_delay_ms, 0);
    }

    /// A `[[ratelimit.rules]]` list in config.toml replaces the defaults
    /// wholesale; the documented override path for the Yahoo rule.
    #[test]
    fn config_toml_overrides_the_default_rules() {
        #[derive(Deserialize)]
        struct Doc {
            ratelimit: RatelimitSection,
        }
        let doc: Doc = toml::from_str(
            r#"
            [[ratelimit.rules]]
            domain = "*.finance.yahoo.com"
            requests_per_window = 600
            window_secs = 60

            [[ratelimit.rules]]
            domain = ""
            requests_per_window = 30
            window_secs = 60
            min_delay_ms = 200
            "#,
        )
        .expect("valid toml");
        let configs = doc.ratelimit.to_domain_configs();
        assert_eq!(configs[0].requests_per_window, 600);
        assert_eq!(configs[0].min_delay, Duration::ZERO);
    }

    #[test]
    fn converts_to_domain_configs() {
        let s = RatelimitSection::default();
        let configs = s.to_domain_configs();
        assert_eq!(configs.len(), s.rules.len());
        assert_eq!(configs[0].domain, "*.reddit.com");
    }
}
