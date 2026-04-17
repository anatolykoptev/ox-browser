//! Per-domain rate limiter with wildcard matching and inter-request delays.
//! Port of go-stealth's `ratelimit.DomainLimiter`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::Rng;
use url::Url;

use crate::ratelimit::Limiter;

/// Rule binding a domain pattern to rate-limit parameters.
#[derive(Debug, Clone)]
pub struct DomainConfig {
    /// Exact `"api.example.com"`, wildcard `"*.example.com"`, or `""` (catch-all).
    pub domain: String,
    pub requests_per_window: usize,
    pub window_duration: Duration,
    pub min_delay: Duration,
    pub random_delay: Duration,
}

/// Per-domain rate limiter that matches URLs against ordered rules.
pub struct DomainLimiter {
    rules: Vec<DomainConfig>,
    limiters: Mutex<HashMap<String, Limiter>>,
    last_req: Mutex<HashMap<String, Instant>>,
}

impl DomainLimiter {
    /// Create a new limiter. Rules are evaluated in order; first match wins.
    pub fn new(rules: Vec<DomainConfig>) -> Self {
        Self {
            rules,
            limiters: Mutex::new(HashMap::new()),
            last_req: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the request is allowed (no matching rule, or within limits).
    pub fn allow(&self, raw_url: &str) -> bool {
        let domain = match extract_domain(raw_url) {
            Some(d) => d,
            None => return true,
        };
        let rule = match self.match_rule(&domain) {
            Some(r) => r,
            None => return true,
        };

        let now = Instant::now();

        // Enforce min_delay + random jitter.
        if !rule.min_delay.is_zero() || !rule.random_delay.is_zero() {
            let last = self.last_req.lock().unwrap();
            if let Some(&prev) = last.get(&domain) {
                let jitter = if rule.random_delay.is_zero() {
                    Duration::ZERO
                } else {
                    let ms = rand::thread_rng().gen_range(0..rule.random_delay.as_millis() as u64);
                    Duration::from_millis(ms)
                };
                let required = rule.min_delay + jitter;
                if now.duration_since(prev) < required {
                    return false;
                }
            }
        }

        let allowed = {
            let mut lims = self.limiters.lock().unwrap();
            let lim = lims.entry(domain.clone()).or_insert_with(|| {
                Limiter::with_window(rule.requests_per_window, rule.window_duration)
            });
            lim.allow(&domain)
        };
        if allowed {
            self.last_req.lock().unwrap().insert(domain, now);
        }
        allowed
    }

    /// Wait (async, polling every 50 ms) until the request is allowed.
    pub async fn wait(&self, raw_url: &str) {
        loop {
            if self.allow(raw_url) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Mark a domain as rate-limited until `until` (e.g. after a 429).
    pub fn mark_rate_limited(&self, raw_url: &str, until: Instant) {
        let domain = match extract_domain(raw_url) {
            Some(d) => d,
            None => return,
        };
        let rule = match self.match_rule(&domain) {
            Some(r) => r,
            None => return,
        };
        let mut lims = self.limiters.lock().unwrap();
        let lim = lims.entry(domain.clone()).or_insert_with(|| {
            Limiter::with_window(rule.requests_per_window, rule.window_duration)
        });
        lim.mark_rate_limited(&domain, until);
    }

    fn match_rule(&self, domain: &str) -> Option<&DomainConfig> {
        self.rules
            .iter()
            .find(|r| domain_matches(&r.domain, domain))
    }
}

/// Extract the host (without port) from a URL string.
fn extract_domain(raw_url: &str) -> Option<String> {
    Url::parse(raw_url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
}

/// Match: `""` = catch-all, `"*.x.com"` = wildcard, `"x.com"` = exact.
fn domain_matches(pattern: &str, domain: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        domain.ends_with(suffix)
            && domain.len() > suffix.len()
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
    } else {
        pattern == domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_domain_match() {
        assert!(domain_matches("api.example.com", "api.example.com"));
        assert!(!domain_matches("api.example.com", "other.example.com"));
    }

    #[test]
    fn wildcard_domain_match() {
        assert!(domain_matches("*.example.com", "api.example.com"));
        assert!(domain_matches("*.example.com", "sub.api.example.com"));
        assert!(!domain_matches("*.example.com", "example.com"));
    }

    #[test]
    fn catch_all_matches_everything() {
        assert!(domain_matches("", "anything.com"));
    }

    #[test]
    fn no_rule_allows_request() {
        let limiter = DomainLimiter::new(vec![]);
        assert!(limiter.allow("https://example.com/path"));
    }

    #[test]
    fn blocks_after_window_limit() {
        let limiter = DomainLimiter::new(vec![DomainConfig {
            domain: "example.com".into(),
            requests_per_window: 2,
            window_duration: Duration::from_secs(60),
            min_delay: Duration::ZERO,
            random_delay: Duration::ZERO,
        }]);
        assert!(limiter.allow("https://example.com/a"));
        assert!(limiter.allow("https://example.com/b"));
        assert!(!limiter.allow("https://example.com/c"));
    }

    #[test]
    fn min_delay_blocks_rapid_requests() {
        let limiter = DomainLimiter::new(vec![DomainConfig {
            domain: "example.com".into(),
            requests_per_window: 100,
            window_duration: Duration::from_secs(60),
            min_delay: Duration::from_secs(10),
            random_delay: Duration::ZERO,
        }]);
        assert!(limiter.allow("https://example.com/a"));
        // Second request immediately — should be blocked by min_delay.
        assert!(!limiter.allow("https://example.com/b"));
    }

    #[test]
    fn extract_domain_works() {
        assert_eq!(
            extract_domain("https://api.example.com/p"),
            Some("api.example.com".into())
        );
        assert_eq!(extract_domain("bad"), None);
    }
}
