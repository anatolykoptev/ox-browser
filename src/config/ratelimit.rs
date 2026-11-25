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
#[serde(deny_unknown_fields)]
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

/// Largest accepted burst (`requests_per_window`).
pub const MAX_BURST: usize = 100_000;
/// Largest accepted `window_secs` (one day).
pub const MAX_WINDOW_SECS: u64 = 86_400;
/// Largest accepted `min_delay_ms` / `random_delay_ms` (one hour).
pub const MAX_DELAY_MS: u64 = 3_600_000;

impl RatelimitRule {
    fn validate(&self) -> Result<(), String> {
        if !valid_domain_pattern(&self.domain) {
            return Err(format!(
                "domain must be \"\" (catch-all), \"host\" or \"*.host\" using [a-z0-9.-], got {:?}",
                self.domain
            ));
        }
        if !(1..=MAX_BURST).contains(&self.requests_per_window) {
            return Err(format!(
                "requests_per_window must be between 1 and {MAX_BURST}, got {}",
                self.requests_per_window
            ));
        }
        if !(1..=MAX_WINDOW_SECS).contains(&self.window_secs) {
            return Err(format!(
                "window_secs must be between 1 and {MAX_WINDOW_SECS}, got {}",
                self.window_secs
            ));
        }
        for (name, v) in [
            ("min_delay_ms", self.min_delay_ms),
            ("random_delay_ms", self.random_delay_ms),
        ] {
            if v > MAX_DELAY_MS {
                return Err(format!("{name} must be at most {MAX_DELAY_MS}, got {v}"));
            }
        }
        Ok(())
    }
}

/// `""`, `host.tld` or `*.host.tld`: lowercase ASCII labels of `[a-z0-9-]`.
/// The restricted alphabet also keeps a rule from colliding with the
/// reserved metric label of the catch-all rule.
fn valid_domain_pattern(p: &str) -> bool {
    if p.is_empty() {
        return true;
    }
    let host = p.strip_prefix("*.").unwrap_or(p);
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl RatelimitSection {
    /// Reject a configuration that would silently disable or distort the
    /// limiter (zero window or burst, absurd bounds, malformed patterns). The
    /// error names the offending rule and key.
    pub fn validate(&self) -> Result<(), String> {
        for (i, r) in self.rules.iter().enumerate() {
            r.validate()
                .map_err(|e| format!("[ratelimit] rule #{} (domain {:?}): {e}", i + 1, r.domain))?;
        }
        Ok(())
    }

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
        doc.ratelimit.validate().expect("valid override");
        // The COMPLETE resulting list: the override replaces the defaults
        // wholesale (no reddit/x.com rule survives).
        let got: Vec<_> = doc
            .ratelimit
            .to_domain_configs()
            .into_iter()
            .map(|c| {
                (
                    c.domain,
                    c.requests_per_window,
                    c.window_duration,
                    c.min_delay,
                    c.random_delay,
                )
            })
            .collect();
        let expected = vec![
            (
                "*.finance.yahoo.com".to_string(),
                600,
                Duration::from_secs(60),
                Duration::ZERO,
                Duration::ZERO,
            ),
            (
                String::new(),
                30,
                Duration::from_secs(60),
                Duration::from_millis(200),
                Duration::ZERO,
            ),
        ];
        assert_eq!(got, expected);
    }

    fn rule_with(f: impl FnOnce(&mut RatelimitRule)) -> RatelimitSection {
        let mut rule = RatelimitRule {
            domain: "*.x.com".into(),
            requests_per_window: 10,
            window_secs: 60,
            min_delay_ms: 0,
            random_delay_ms: 0,
        };
        f(&mut rule);
        RatelimitSection { rules: vec![rule] }
    }

    #[test]
    fn shipped_defaults_are_valid() {
        RatelimitSection::default().validate().expect("defaults");
    }

    /// Bad overrides are rejected loudly, naming the rule and the key, rather
    /// than silently disabling (burst 0) or clamping (window 0) the limiter.
    #[test]
    fn invalid_overrides_are_rejected_with_a_clear_error() {
        let cases: [(RatelimitSection, &str); 8] = [
            (rule_with(|r| r.window_secs = 0), "window_secs"),
            (
                rule_with(|r| r.requests_per_window = 0),
                "requests_per_window",
            ),
            (
                rule_with(|r| r.requests_per_window = MAX_BURST + 1),
                "requests_per_window",
            ),
            (
                rule_with(|r| r.window_secs = MAX_WINDOW_SECS + 1),
                "window_secs",
            ),
            (rule_with(|r| r.min_delay_ms = u64::MAX), "min_delay_ms"),
            (
                rule_with(|r| r.random_delay_ms = MAX_DELAY_MS + 1),
                "random_delay_ms",
            ),
            (rule_with(|r| r.domain = "catch_all".into()), "domain"),
            (rule_with(|r| r.domain = "*.".into()), "domain"),
        ];
        for (section, key) in cases {
            let err = section.validate().expect_err(key);
            assert!(err.contains(key) && err.contains("rule #1"), "{err}");
        }
        // Boundaries are accepted.
        rule_with(|r| {
            r.requests_per_window = MAX_BURST;
            r.window_secs = MAX_WINDOW_SECS;
            r.min_delay_ms = MAX_DELAY_MS;
        })
        .validate()
        .expect("upper bounds are valid");
    }

    /// `ServerConfig::load` refuses a bad `[ratelimit]` instead of starting
    /// with a distorted limiter.
    #[test]
    fn server_config_load_rejects_an_invalid_ratelimit_override() {
        let dir = std::env::temp_dir().join(format!("ox-rl-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[[ratelimit.rules]]\ndomain = \"\"\nrequests_per_window = 30\nwindow_secs = 0\n",
        )
        .expect("write");
        let err = crate::config::ServerConfig::load(&path).expect_err("window_secs = 0");
        assert!(err.to_string().contains("window_secs"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_rule_keys_are_rejected() {
        #[derive(Deserialize)]
        struct Doc {
            #[allow(dead_code)]
            ratelimit: RatelimitSection,
        }
        let r: Result<Doc, _> = toml::from_str(
            "[[ratelimit.rules]]\ndomain = \"\"\nrequests_per_window = 1\nwindow_secs = 1\nmin_delay_msec = 5\n",
        );
        assert!(r.is_err(), "a typo'd key must not be silently ignored");
    }

    /// Caller compatibility of the token bucket vs the old fixed window: with
    /// the SHIPPED rules, a serial 1 rps client of the JSON finance APIs never
    /// waits, however long it runs; under the catch-all it never waits for the
    /// first 50 requests and is afterwards slowed in steps of at most one
    /// emission interval (2 s) plus the rule's gap, never a half-window stall.
    /// (reddit and x.com carry a deliberate multi-second min gap and are not
    /// 1 rps hosts.)
    #[tokio::test(start_paused = true)]
    async fn shipped_defaults_never_stall_a_one_rps_serial_client() {
        let limiter = ox_http::DomainLimiter::new(RatelimitSection::default().to_domain_configs());
        let far = || Some(tokio::time::Instant::now() + Duration::from_secs(120));

        for i in 0..400 {
            let waited = limiter
                .acquire(
                    "https://query1.finance.yahoo.com/v8/finance/chart/AAPL",
                    far(),
                )
                .await
                .unwrap_or_else(|e| panic!("yahoo request {i}: {e}"));
            assert_eq!(waited, Duration::ZERO, "yahoo request {i} waited");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        let mut max_wait = Duration::ZERO;
        for i in 0..200 {
            let waited = limiter
                .acquire("https://api.example.com/data", far())
                .await
                .unwrap_or_else(|e| panic!("catch-all request {i}: {e}"));
            if i < 50 {
                assert_eq!(waited, Duration::ZERO, "catch-all request {i} waited");
            }
            max_wait = max_wait.max(waited);
            tokio::time::sleep(Duration::from_secs(1).saturating_sub(waited)).await;
        }
        assert!(max_wait <= Duration::from_millis(2_300), "{max_wait:?}");
    }

    #[test]
    fn converts_to_domain_configs() {
        let s = RatelimitSection::default();
        let configs = s.to_domain_configs();
        assert_eq!(configs.len(), s.rules.len());
        assert_eq!(configs[0].domain, "*.reddit.com");
    }
}
