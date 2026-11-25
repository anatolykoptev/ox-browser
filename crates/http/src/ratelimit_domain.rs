//! Per-domain rate limiter with wildcard matching and inter-request delays.
//! Port of go-stealth's `ratelimit.DomainLimiter`, on a [`governor`] token
//! bucket per host (see [`crate::ratelimit::Limiter`]).

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::time::Instant;

use crate::deadline::{self, MAX_CALL_TIMEOUT_SECS};
use crate::error::HttpError;
use crate::metrics;
use crate::metrics_ratelimit;
use crate::ratelimit::{Limiter, RateLimitConfig};
use crate::url_util::extract_domain;

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

/// A rule plus the limiter that holds its per-host state.
struct Rule {
    cfg: DomainConfig,
    label: String,
    limiter: Limiter,
}

/// Per-domain rate limiter that matches URLs against ordered rules.
pub struct DomainLimiter {
    rules: Vec<Rule>,
}

impl DomainLimiter {
    /// Create a new limiter. Rules are evaluated in order; first match wins.
    pub fn new(rules: Vec<DomainConfig>) -> Self {
        Self {
            rules: rules
                .into_iter()
                .map(|cfg| Rule {
                    label: metrics_ratelimit::rule_label(&cfg.domain).to_string(),
                    limiter: Limiter::new(RateLimitConfig {
                        requests_per_window: cfg.requests_per_window,
                        window_duration: cfg.window_duration,
                    }),
                    cfg,
                })
                .collect(),
        }
    }

    /// The host and matching rule for `raw_url`, if any rule applies.
    fn resolve(&self, raw_url: &str) -> Option<(String, &Rule)> {
        let domain = extract_domain(raw_url)?;
        let rule = self
            .rules
            .iter()
            .find(|r| domain_matches(&r.cfg.domain, &domain))?;
        Some((domain, rule))
    }

    /// Try to admit one request for `raw_url`, drawing a fresh jitter.
    /// Returns `true` if allowed (no matching rule, or within limits).
    pub fn allow(&self, raw_url: &str) -> bool {
        self.check(raw_url, None).is_ok()
    }

    /// Admit one request for `raw_url` or report when it could next be
    /// admitted: the latest of the min-delay gap, the origin cooldown and the
    /// token bucket, evaluated together. `gap_jitter` pins the random part of
    /// the gap (`None` draws a fresh one).
    pub fn check(&self, raw_url: &str, gap_jitter: Option<Duration>) -> Result<(), Duration> {
        let Some((domain, rule)) = self.resolve(raw_url) else {
            return Ok(());
        };
        let jitter = gap_jitter.unwrap_or_else(|| draw_jitter(&rule.cfg));
        let gap = rule.cfg.min_delay.saturating_add(jitter);
        rule.limiter.check_gap(&domain, gap)?;
        self.publish_gauge();
        Ok(())
    }

    /// Name of the rule matching `raw_url` (its domain pattern; `catch_all`
    /// for the empty pattern), or `None` when no rule applies.
    pub fn rule_name(&self, raw_url: &str) -> Option<&str> {
        self.resolve(raw_url).map(|(_, r)| r.label.as_str())
    }

    /// Wait until a permit is available, sleeping exactly as long as the
    /// limiter says (no polling), but never past `deadline`.
    ///
    /// If the next permit is due at or after `deadline` (or, with no deadline
    /// known, the global call ceiling), nothing is slept and
    /// [`HttpError::RateLimited`] carries the true next-permit wait so the
    /// caller can answer 429 + `Retry-After` instead of burning its whole
    /// budget and timing out. The deadline is re-checked before every attempt
    /// to consume a permit, so a late wake-up never spends one after the call
    /// is already dead. Returns the time spent waiting on success.
    pub async fn acquire(
        &self,
        raw_url: &str,
        deadline: Option<Instant>,
    ) -> Result<Duration, HttpError> {
        let Some((domain, rule)) = self.resolve(raw_url) else {
            return Ok(Duration::ZERO);
        };
        let start = Instant::now();
        let deadline = deadline.unwrap_or_else(|| {
            start
                .checked_add(Duration::from_secs(MAX_CALL_TIMEOUT_SECS))
                .unwrap_or(start)
        });
        // One jitter draw per call: re-drawing after each sleep could demand
        // a further wait for the difference.
        let gap = rule.cfg.min_delay.saturating_add(draw_jitter(&rule.cfg));
        let refuse = |wait: Duration| {
            metrics_ratelimit::record_deadline_refusal(&rule.label);
            HttpError::RateLimited {
                retry_after: wait,
                rule: rule.label.clone(),
            }
        };

        let mut last_wait = Duration::ZERO;
        loop {
            let now = Instant::now();
            if now >= deadline {
                // Woke up (or arrived) with no budget left: do not spend a
                // permit on a call that is already dead.
                return Err(refuse(last_wait.max(Duration::from_millis(1))));
            }
            match rule.limiter.check_gap(&domain, gap) {
                Ok(()) => {
                    deadline::set_in_limiter(false);
                    self.publish_gauge();
                    let waited = start.elapsed();
                    metrics_ratelimit::record_wait(&rule.label, waited);
                    return Ok(waited);
                }
                Err(wait) => {
                    if wait >= deadline.saturating_duration_since(now) {
                        return Err(refuse(wait));
                    }
                    last_wait = wait;
                    deadline::set_in_limiter(true);
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    /// Mark a domain as rate-limited until `until` (e.g. after a 429). A
    /// later cooldown is never shortened by an earlier one.
    pub fn mark_rate_limited(&self, raw_url: &str, until: impl Into<Instant>) {
        if let Some((domain, rule)) = self.resolve(raw_url) {
            rule.limiter.mark_rate_limited(&domain, until);
            self.publish_gauge();
        }
    }

    /// Remove hosts idle for more than `2 × window_duration` of their rule and
    /// carrying no active cooldown. Called periodically by
    /// [`spawn_eviction_task`]. Mirrors
    /// [`crate::solver_negcache::SolverNegCache::evict_expired`].
    pub fn evict_expired(&self) {
        for r in &self.rules {
            r.limiter.evict_idle(r.cfg.window_duration * 2);
        }
        self.publish_gauge();
    }

    /// Number of tracked domains (test/observability helper).
    pub fn len(&self) -> usize {
        self.rules.iter().map(|r| r.limiter.len()).sum()
    }

    /// True if no domains are tracked.
    pub fn is_empty(&self) -> bool {
        self.rules.iter().all(|r| r.limiter.is_empty())
    }

    /// Publish the current domain count to the `oxbrowser_ratelimit_domains`
    /// gauge so operators can see bounded-growth health in Prometheus.
    fn publish_gauge(&self) {
        metrics::set_gauge(&metrics::RATELIMIT_DOMAINS, self.len() as u64);
    }
}

/// Random extra gap for a rule, `0..random_delay`.
fn draw_jitter(cfg: &DomainConfig) -> Duration {
    let ms = u64::try_from(cfg.random_delay.as_millis()).unwrap_or(u64::MAX);
    if ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(rand::thread_rng().gen_range(0..ms))
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

    fn rule(domain: &str, n: usize, window_secs: u64, min_delay_ms: u64) -> DomainConfig {
        DomainConfig {
            domain: domain.into(),
            requests_per_window: n,
            window_duration: Duration::from_secs(window_secs),
            min_delay: Duration::from_millis(min_delay_ms),
            random_delay: Duration::ZERO,
        }
    }

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
        let limiter = DomainLimiter::new(vec![rule("example.com", 2, 60, 0)]);
        assert!(limiter.allow("https://example.com/a"));
        assert!(limiter.allow("https://example.com/b"));
        assert!(!limiter.allow("https://example.com/c"));
    }

    #[test]
    fn min_delay_blocks_rapid_requests() {
        let limiter = DomainLimiter::new(vec![rule("example.com", 100, 60, 10_000)]);
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
        // Window of 50ms → entries idle for more than 100ms (2× window) are stale.
        let mut cfg = rule("*.example.com", 100, 60, 0);
        cfg.window_duration = Duration::from_millis(50);
        let limiter = DomainLimiter::new(vec![cfg]);

        limiter.allow("https://a.example.com/1");
        limiter.allow("https://b.example.com/1");
        limiter.allow("https://c.example.com/1");
        assert_eq!(limiter.len(), 3);

        std::thread::sleep(Duration::from_millis(120));

        limiter.evict_expired();
        assert_eq!(limiter.len(), 0, "stale entries should have been evicted");
        assert!(limiter.is_empty());
    }

    #[test]
    fn evict_expired_retains_recent_domains() {
        let limiter = DomainLimiter::new(vec![rule("*.example.com", 100, 60, 0)]);
        limiter.allow("https://a.example.com/1");
        limiter.allow("https://b.example.com/1");
        assert_eq!(limiter.len(), 2);

        limiter.evict_expired();
        assert_eq!(limiter.len(), 2, "recent entries should be retained");
    }

    #[test]
    fn evict_expired_retains_some_drops_stale() {
        let mut cfg = rule("*.example.com", 100, 60, 0);
        cfg.window_duration = Duration::from_millis(50);
        let limiter = DomainLimiter::new(vec![cfg]);

        limiter.allow("https://stale.example.com/1");
        std::thread::sleep(Duration::from_millis(120));
        limiter.allow("https://fresh.example.com/1");
        assert_eq!(limiter.len(), 2);

        limiter.evict_expired();
        assert_eq!(limiter.len(), 1, "only the fresh entry should remain");
    }

    /// Eviction must not drop a host that is still in an origin cooldown.
    #[tokio::test(start_paused = true)]
    async fn evict_expired_keeps_hosts_in_cooldown() {
        let limiter = DomainLimiter::new(vec![rule("example.com", 10, 10, 0)]);
        let url = "https://example.com/a";
        limiter.mark_rate_limited(url, Instant::now() + Duration::from_secs(600));
        tokio::time::advance(Duration::from_secs(120)).await; // > 2x window idle
        limiter.evict_expired();
        assert!(!limiter.allow(url), "cooldown lost to eviction");
    }

    /// The incident replayed on the real limiter: catch-all 30/60 s with a
    /// 200 ms min gap, one serial 1 rps client for 80 requests. The old fixed
    /// window stalled request 31 for ~30 s; here the client bursts through the
    /// first 30 and is then slowed to the refill rate, one emission interval
    /// (2 s) at a time. Sustained admissions are bounded by burst + refill.
    #[tokio::test(start_paused = true)]
    async fn serial_one_rps_client_is_never_stalled_a_half_window_on_30_per_60() {
        let limiter = DomainLimiter::new(vec![rule("", 30, 60, 200)]);
        let url = "https://query1.finance.yahoo.com/v8/chart/AAPL";
        let begin = Instant::now();
        let mut max_wait = Duration::ZERO;
        for i in 0..80 {
            let waited = limiter
                .acquire(url, Some(Instant::now() + Duration::from_secs(120)))
                .await
                .unwrap_or_else(|e| panic!("request {i}: {e}"));
            max_wait = max_wait.max(waited);
            tokio::time::sleep(Duration::from_secs(1).saturating_sub(waited)).await;
        }
        assert!(
            max_wait <= Duration::from_secs(2),
            "a single wait was {max_wait:?}"
        );
        // 30 burst + 0.5/s refill: 80 requests need >= ~(80-30)/0.5 = 100 s
        // minus what the 1 rps pacing already supplies (~79 s). They cannot
        // finish faster than the bucket allows, nor much slower.
        let took = begin.elapsed();
        assert!(
            (Duration::from_secs(95)..=Duration::from_secs(125)).contains(&took),
            "80 requests took {took:?}"
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
            assert!(limiter.check(url, Some(Duration::ZERO)).is_err());
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

    /// The boundary: a permit due exactly when the budget ends leaves no time
    /// to send the request, so it is refused (`>=`), not slept into a 504.
    #[tokio::test(start_paused = true)]
    async fn acquire_refuses_when_wait_equals_remaining_budget() {
        let limiter = DomainLimiter::new(vec![rule("example.com", 1, 10, 0)]);
        let url = "https://example.com/a";
        assert!(limiter.allow(url));
        let start = Instant::now();
        let res = limiter
            .acquire(url, Some(start + Duration::from_secs(10)))
            .await;
        assert!(matches!(res, Err(HttpError::RateLimited { .. })), "{res:?}");
        assert_eq!(start.elapsed(), Duration::ZERO);
        // One nanosecond more budget and the same wait is slept.
        let res = limiter
            .acquire(
                url,
                Some(start + Duration::from_secs(10) + Duration::from_nanos(1)),
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
    }

    /// A refusal advertises the latest constraint: the bucket is open but an
    /// origin cooldown has 40 s left while the gap has 1 s.
    #[tokio::test(start_paused = true)]
    async fn refusal_reports_the_cooldown_when_it_is_the_latest_constraint() {
        let limiter = DomainLimiter::new(vec![rule("example.com", 100, 60, 1000)]);
        let url = "https://example.com/a";
        assert!(limiter.allow(url));
        limiter.mark_rate_limited(url, Instant::now() + Duration::from_secs(40));
        let err = limiter
            .acquire(url, Some(Instant::now() + Duration::from_secs(5)))
            .await
            .unwrap_err();
        match err {
            HttpError::RateLimited { retry_after, .. } => {
                assert_eq!(retry_after, Duration::from_secs(40));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    /// A deadline that is already spent never consumes a permit.
    #[tokio::test(start_paused = true)]
    async fn acquire_with_spent_deadline_does_not_consume_a_permit() {
        let limiter = DomainLimiter::new(vec![rule("example.com", 1, 60, 0)]);
        let url = "https://example.com/a";
        let res = limiter.acquire(url, Some(Instant::now())).await;
        assert!(matches!(res, Err(HttpError::RateLimited { .. })));
        assert!(
            limiter.allow(url),
            "the refused call burned the only permit"
        );
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
