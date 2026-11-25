//! Per-domain rate limiter with wildcard matching and inter-request delays.
//! Port of go-stealth's `ratelimit.DomainLimiter`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::time::Instant;

use rand::Rng;

use crate::deadline::{self, MAX_CALL_TIMEOUT_SECS};
use crate::error::HttpError;
use crate::metrics;
use crate::metrics_ratelimit;
use crate::ratelimit::Limiter;
use crate::url_util::extract_domain;

/// Lock a Mutex, recovering from poisoning by taking the inner value.
///
/// A poisoned mutex means a thread panicked while holding the lock. The data
/// may be in an inconsistent state, but for these caches (HashMaps of
/// domain→state) the worst case is a stale or missing entry — which the
/// caller treats as a cache miss anyway. Crashing the server is worse than
/// serving a possibly-stale entry.
fn lock_or_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

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

    /// Try to admit one request for `raw_url`, drawing a fresh jitter.
    /// Returns `true` if allowed (no matching rule, or within limits).
    pub fn allow(&self, raw_url: &str) -> bool {
        self.check(raw_url, self.draw_jitter(raw_url)).is_ok()
    }

    /// Admit one request for `raw_url` or report how long until it could be.
    ///
    /// `Ok(())` consumes a permit (and stamps the min-delay clock). `Err(wait)`
    /// consumes nothing. Both limits are checked under one lock, so concurrent
    /// callers cannot both pass the same min-delay gap.
    pub fn check(&self, raw_url: &str, jitter: Duration) -> Result<(), Duration> {
        let Some(domain) = extract_domain(raw_url) else {
            return Ok(());
        };
        let Some(rule) = self.match_rule(&domain) else {
            return Ok(());
        };

        let now = Instant::now();
        let mut last = lock_or_recover(&self.last_req);

        // Min-delay + jitter gap since the previous admitted request.
        if let Some(&prev) = last.get(&domain) {
            let required = rule.min_delay + jitter;
            let since = now.duration_since(prev);
            if since < required {
                return Err(required - since);
            }
        }

        {
            let mut lims = lock_or_recover(&self.limiters);
            let lim = lims.entry(domain.clone()).or_insert_with(|| {
                Limiter::with_window(rule.requests_per_window, rule.window_duration)
            });
            lim.check(&domain)?;
        }

        last.insert(domain, now);
        metrics::set_gauge(&metrics::RATELIMIT_DOMAINS, last.len() as u64);
        Ok(())
    }

    /// Name of the rule matching `raw_url` (its domain pattern; `catch_all`
    /// for the empty pattern), or `None` when no rule applies.
    pub fn rule_name(&self, raw_url: &str) -> Option<&str> {
        let domain = extract_domain(raw_url)?;
        self.match_rule(&domain)
            .map(|r| metrics_ratelimit::rule_label(&r.domain))
    }

    /// Wait until a permit is available, sleeping exactly as long as the
    /// limiter says (no polling), but never past `deadline`.
    ///
    /// If the next permit would arrive after `deadline` (or, with no deadline
    /// known, after the global call ceiling), nothing is slept and
    /// [`HttpError::RateLimited`] carries the expected wait so the caller can
    /// answer 429 + `Retry-After` instead of burning its whole budget and
    /// timing out. Returns the time spent waiting on success.
    pub async fn acquire(
        &self,
        raw_url: &str,
        deadline: Option<Instant>,
    ) -> Result<Duration, HttpError> {
        let start = Instant::now();
        let deadline = deadline.unwrap_or(start + Duration::from_secs(MAX_CALL_TIMEOUT_SECS));
        // One jitter draw per call: re-drawing after each sleep could demand
        // a further wait for the difference.
        let jitter = self.draw_jitter(raw_url);
        loop {
            let wait = match self.check(raw_url, jitter) {
                Ok(()) => {
                    deadline::set_in_limiter(false);
                    let waited = start.elapsed();
                    if let Some(rule) = self.rule_name(raw_url) {
                        metrics_ratelimit::record_wait(rule, waited);
                    }
                    return Ok(waited);
                }
                Err(wait) => wait,
            };
            if Instant::now() + wait > deadline {
                let rule = self.rule_name(raw_url).unwrap_or_default().to_string();
                metrics_ratelimit::record_deadline_refusal(&rule);
                return Err(HttpError::RateLimited {
                    retry_after: wait,
                    rule,
                });
            }
            deadline::set_in_limiter(true);
            tokio::time::sleep(wait).await;
        }
    }

    /// Random extra gap for this URL's rule, `0..random_delay`.
    fn draw_jitter(&self, raw_url: &str) -> Duration {
        let Some(rule) = extract_domain(raw_url).and_then(|d| self.match_rule(&d)) else {
            return Duration::ZERO;
        };
        let ms = rule.random_delay.as_millis() as u64;
        if ms == 0 {
            return Duration::ZERO;
        }
        Duration::from_millis(rand::thread_rng().gen_range(0..ms))
    }

    /// Mark a domain as rate-limited until `until` (e.g. after a 429).
    pub fn mark_rate_limited(&self, raw_url: &str, until: impl Into<Instant>) {
        let domain = match extract_domain(raw_url) {
            Some(d) => d,
            None => return,
        };
        let rule = match self.match_rule(&domain) {
            Some(r) => r,
            None => return,
        };
        let mut lims = lock_or_recover(&self.limiters);
        let lim = lims.entry(domain.clone()).or_insert_with(|| {
            Limiter::with_window(rule.requests_per_window, rule.window_duration)
        });
        lim.mark_rate_limited(&domain, until);
        drop(lims);
        self.publish_gauge();
    }

    /// Remove entries whose last request is older than `2 × window_duration`
    /// for their matched rule — i.e. domains that haven't been requested in
    /// twice the window. Called periodically by [`spawn_eviction_task`].
    /// Mirrors [`crate::solver_negcache::SolverNegCache::evict_expired`].
    pub fn evict_expired(&self) {
        let now = Instant::now();
        let mut last_req = lock_or_recover(&self.last_req);
        last_req.retain(|domain, prev| {
            let Some(rule) = self.match_rule(domain) else {
                return false;
            };
            now.duration_since(*prev) <= rule.window_duration * 2
        });
        // Keep limiters in sync: drop any domain no longer present in last_req.
        let mut lims = lock_or_recover(&self.limiters);
        lims.retain(|domain, _| last_req.contains_key(domain));
        drop(lims);
        drop(last_req);
        self.publish_gauge();
    }

    /// Number of tracked domains (test/observability helper).
    pub fn len(&self) -> usize {
        lock_or_recover(&self.last_req).len()
    }

    /// True if no domains are tracked.
    pub fn is_empty(&self) -> bool {
        lock_or_recover(&self.last_req).is_empty()
    }

    /// Publish the current domain count to the `oxbrowser_ratelimit_domains`
    /// gauge so operators can see bounded-growth health in Prometheus.
    fn publish_gauge(&self) {
        let n = lock_or_recover(&self.last_req).len() as u64;
        metrics::set_gauge(&metrics::RATELIMIT_DOMAINS, n);
    }

    fn match_rule(&self, domain: &str) -> Option<&DomainConfig> {
        self.rules
            .iter()
            .find(|r| domain_matches(&r.domain, domain))
    }
}

/// Spawn a background task that periodically evicts stale per-domain entries
/// so a long-running server doesn't accumulate them forever (issue #20).
///
/// Mirrors [`crate::solver_negcache::spawn_eviction_task`]. Call once at
/// server startup, passing the same `Arc<DomainLimiter>` wired into
/// `HttpConfig.rate_limiter`.
pub fn spawn_eviction_task(limiter: Arc<DomainLimiter>, interval: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            limiter.evict_expired();
        }
    });
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

    #[test]
    fn evict_expired_removes_stale_domains() {
        // Window of 50ms → entries older than 100ms (2× window) are stale.
        let limiter = DomainLimiter::new(vec![DomainConfig {
            domain: "*.example.com".into(),
            requests_per_window: 100,
            window_duration: Duration::from_millis(50),
            min_delay: Duration::ZERO,
            random_delay: Duration::ZERO,
        }]);

        // Insert several domains.
        limiter.allow("https://a.example.com/1");
        limiter.allow("https://b.example.com/1");
        limiter.allow("https://c.example.com/1");
        assert_eq!(limiter.len(), 3);

        // Wait past 2× window so all entries become stale.
        std::thread::sleep(Duration::from_millis(120));

        limiter.evict_expired();
        assert_eq!(limiter.len(), 0, "stale entries should have been evicted");
        assert!(limiter.is_empty());
    }

    #[test]
    fn evict_expired_retains_recent_domains() {
        let limiter = DomainLimiter::new(vec![DomainConfig {
            domain: "*.example.com".into(),
            requests_per_window: 100,
            window_duration: Duration::from_secs(60),
            min_delay: Duration::ZERO,
            random_delay: Duration::ZERO,
        }]);

        limiter.allow("https://a.example.com/1");
        limiter.allow("https://b.example.com/1");
        assert_eq!(limiter.len(), 2);

        // No wait — entries are well within 2× window (120s).
        limiter.evict_expired();
        assert_eq!(limiter.len(), 2, "recent entries should be retained");
    }

    #[test]
    fn evict_expired_retains_some_drops_stale() {
        // Mixed: a fresh entry and a stale entry coexist.
        let limiter = DomainLimiter::new(vec![DomainConfig {
            domain: "*.example.com".into(),
            requests_per_window: 100,
            window_duration: Duration::from_millis(50),
            min_delay: Duration::ZERO,
            random_delay: Duration::ZERO,
        }]);

        limiter.allow("https://stale.example.com/1");
        // Wait past 2× window for the first entry.
        std::thread::sleep(Duration::from_millis(120));
        // Now insert a fresh entry.
        limiter.allow("https://fresh.example.com/1");
        assert_eq!(limiter.len(), 2);

        limiter.evict_expired();
        assert_eq!(limiter.len(), 1, "only the fresh entry should remain");
    }

    fn rule(domain: &str, n: usize, window_secs: u64, min_delay_ms: u64) -> DomainConfig {
        DomainConfig {
            domain: domain.into(),
            requests_per_window: n,
            window_duration: Duration::from_secs(window_secs),
            min_delay: Duration::from_millis(min_delay_ms),
            random_delay: Duration::ZERO,
        }
    }

    /// The incident replayed on the real limiter: catch-all 30/60 s with a
    /// 200 ms min gap, one serial 1 rps client for 80 requests. The old fixed
    /// window stalled request 31 for ~30 s; here no request ever waits.
    #[tokio::test(start_paused = true)]
    async fn serial_one_rps_client_is_never_stalled_a_half_window_on_30_per_60() {
        let limiter = DomainLimiter::new(vec![rule("", 30, 60, 200)]);
        let url = "https://query1.finance.yahoo.com/v8/chart/AAPL";
        let mut max_wait = Duration::ZERO;
        for i in 0..80 {
            // Bursts through the first 30, then the bucket slows the client
            // to its refill rate one emission interval at a time.
            let before = Instant::now();
            let res = limiter
                .acquire(url, Some(before + Duration::from_secs(120)))
                .await;
            let waited = res.unwrap_or_else(|e| panic!("request {i}: {e}"));
            max_wait = max_wait.max(waited);
            tokio::time::sleep(Duration::from_secs(1) - waited.min(Duration::from_secs(1))).await;
        }
        // 80 requests at 1 rps against 30/60 s: the limiter must throttle to
        // 0.5 rps once drained, never stall for half a window.
        assert!(
            max_wait <= Duration::from_secs(2),
            "a single wait was {max_wait:?}"
        );
    }

    /// `acquire` sleeps once for the computed wait, not in 50 ms polls, and
    /// does not spend quota while waiting.
    #[tokio::test(start_paused = true)]
    async fn acquire_sleeps_computed_wait_and_denied_checks_cost_nothing() {
        let limiter = DomainLimiter::new(vec![rule("example.com", 1, 10, 0)]);
        let url = "https://example.com/a";
        assert!(limiter.allow(url));
        for _ in 0..500 {
            assert!(limiter.check(url, Duration::ZERO).is_err());
        }
        let start = Instant::now();
        let waited = limiter
            .acquire(url, Some(start + Duration::from_secs(60)))
            .await
            .unwrap();
        assert_eq!(waited, Duration::from_secs(10));
        assert_eq!(start.elapsed(), Duration::from_secs(10));
    }

    /// No wait may run past the deadline: the permit is 10 s away, the budget
    /// 3 s, so the call is refused with the expected wait and zero sleeping.
    #[tokio::test(start_paused = true)]
    async fn acquire_refuses_when_wait_exceeds_budget() {
        let limiter = DomainLimiter::new(vec![rule("example.com", 1, 10, 0)]);
        let url = "https://example.com/a";
        assert!(limiter.allow(url));
        let start = Instant::now();
        let err = limiter
            .acquire(url, Some(start + Duration::from_secs(3)))
            .await
            .unwrap_err();
        assert_eq!(start.elapsed(), Duration::ZERO);
        match err {
            HttpError::RateLimited { retry_after, rule } => {
                assert_eq!(retry_after, Duration::from_secs(10));
                assert_eq!(rule, "example.com");
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn min_delay_wait_is_computed_not_polled() {
        let limiter = DomainLimiter::new(vec![rule("example.com", 100, 60, 400)]);
        let url = "https://example.com/a";
        assert!(limiter.allow(url));
        let start = Instant::now();
        limiter.acquire(url, None).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(400));
    }

    #[test]
    fn rule_name_labels_by_pattern_not_host() {
        let limiter = DomainLimiter::new(vec![rule("*.x.com", 1, 60, 0), rule("", 1, 60, 0)]);
        assert_eq!(limiter.rule_name("https://a.x.com/p"), Some("*.x.com"));
        assert_eq!(limiter.rule_name("https://b.x.com/p"), Some("*.x.com"));
        assert_eq!(limiter.rule_name("https://other.org/p"), Some("catch_all"));
    }
}
