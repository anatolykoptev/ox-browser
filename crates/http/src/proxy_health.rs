use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::proxy_pool::ProxyPool;

/// Configuration for health-based proxy filtering.
pub struct HealthConfig {
    /// Failure rate (0.0-1.0) above which a proxy is deactivated.
    pub failure_threshold: f64,
    /// Minimum requests before the failure threshold is evaluated.
    pub min_requests: u64,
    /// How long a deactivated proxy stays offline before reactivation.
    pub cooldown: Duration,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 0.5,
            min_requests: 3,
            cooldown: Duration::from_secs(300),
        }
    }
}

/// Health statistics for a single proxy.
#[derive(Debug, Clone)]
pub struct ProxyHealth {
    pub successes: u64,
    pub failures: u64,
    pub last_used: Instant,
    pub deactivated_at: Option<Instant>,
}

impl ProxyHealth {
    fn new() -> Self {
        Self {
            successes: 0,
            failures: 0,
            last_used: Instant::now(),
            deactivated_at: None,
        }
    }

    fn total(&self) -> u64 {
        self.successes + self.failures
    }

    fn failure_rate(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        self.failures as f64 / total as f64
    }

    fn is_active(&self) -> bool {
        self.deactivated_at.is_none()
    }
}

/// A health-tracking wrapper around any `ProxyPool`.
///
/// Skips deactivated proxies in `next()`, reactivates them after the
/// cooldown period expires. Falls back to raw rotation if all proxies
/// are unhealthy.
pub struct HealthyPool {
    inner: Arc<dyn ProxyPool>,
    config: HealthConfig,
    health: Mutex<HashMap<String, ProxyHealth>>,
}

impl HealthyPool {
    pub fn new(inner: Arc<dyn ProxyPool>, config: HealthConfig) -> Self {
        Self {
            inner,
            config,
            health: Mutex::new(HashMap::new()),
        }
    }

    /// Records a successful request through the given proxy.
    pub fn record_success(&self, proxy: &str) {
        let mut health = self.health.lock().unwrap();
        let entry = health.entry(proxy.to_string()).or_insert_with(ProxyHealth::new);
        entry.successes += 1;
        entry.last_used = Instant::now();
    }

    /// Records a failed request. Deactivates the proxy if the failure
    /// rate exceeds the threshold after `min_requests`.
    pub fn record_failure(&self, proxy: &str) {
        let mut health = self.health.lock().unwrap();
        let entry = health.entry(proxy.to_string()).or_insert_with(ProxyHealth::new);
        entry.failures += 1;
        entry.last_used = Instant::now();

        if entry.total() >= self.config.min_requests
            && entry.failure_rate() > self.config.failure_threshold
        {
            entry.deactivated_at = Some(Instant::now());
        }
    }

    /// Returns a snapshot of health stats for all tracked proxies.
    pub fn stats(&self) -> HashMap<String, ProxyHealth> {
        self.health.lock().unwrap().clone()
    }

    /// Returns the number of currently active (non-deactivated) proxies.
    pub fn active_count(&self) -> usize {
        let health = self.health.lock().unwrap();
        let total = self.inner.len();
        let deactivated = health.values().filter(|h| !h.is_active()).count();
        total.saturating_sub(deactivated)
    }

    /// Checks if a proxy should be reactivated (cooldown expired) and
    /// resets its counters if so. Returns `true` if the proxy is active.
    fn try_reactivate(&self, health: &mut HashMap<String, ProxyHealth>, proxy: &str) -> bool {
        let Some(entry) = health.get_mut(proxy) else {
            return true; // No health data yet means it is active.
        };

        if let Some(deactivated_at) = entry.deactivated_at {
            if deactivated_at.elapsed() >= self.config.cooldown {
                entry.successes = 0;
                entry.failures = 0;
                entry.deactivated_at = None;
                return true;
            }
            return false;
        }

        true
    }
}

impl ProxyPool for HealthyPool {
    fn next(&self) -> Option<String> {
        let pool_len = self.inner.len();
        if pool_len == 0 {
            return None;
        }

        let mut health = self.health.lock().unwrap();

        // Try each proxy once, skipping deactivated ones.
        for _ in 0..pool_len {
            let proxy = self.inner.next()?;
            if self.try_reactivate(&mut health, &proxy) {
                return Some(proxy);
            }
        }

        // Fallback: all proxies are unhealthy. Return next anyway.
        drop(health);
        self.inner.next()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_pool::StaticPool;

    fn test_pool() -> Arc<StaticPool> {
        Arc::new(StaticPool::new(vec![
            "http://p1:8080".into(),
            "http://p2:8080".into(),
            "http://p3:8080".into(),
        ]))
    }

    #[test]
    fn healthy_pool_passes_through() {
        let pool = HealthyPool::new(test_pool(), HealthConfig::default());
        assert_eq!(pool.len(), 3);
        assert!(pool.next().is_some());
        assert_eq!(pool.active_count(), 3);
    }

    #[test]
    fn record_success_tracks_stats() {
        let pool = HealthyPool::new(test_pool(), HealthConfig::default());
        pool.record_success("http://p1:8080");
        pool.record_success("http://p1:8080");

        let stats = pool.stats();
        let h = &stats["http://p1:8080"];
        assert_eq!(h.successes, 2);
        assert_eq!(h.failures, 0);
        assert!(h.is_active());
    }

    #[test]
    fn deactivation_after_threshold() {
        let config = HealthConfig {
            failure_threshold: 0.5,
            min_requests: 3,
            cooldown: Duration::from_secs(300),
        };
        let pool = HealthyPool::new(test_pool(), config);

        // 3 failures out of 3 requests = 100% failure rate.
        pool.record_failure("http://p1:8080");
        pool.record_failure("http://p1:8080");
        pool.record_failure("http://p1:8080");

        let stats = pool.stats();
        assert!(stats["http://p1:8080"].deactivated_at.is_some());
        assert_eq!(pool.active_count(), 2);
    }

    #[test]
    fn no_deactivation_below_min_requests() {
        let config = HealthConfig {
            failure_threshold: 0.5,
            min_requests: 5,
            cooldown: Duration::from_secs(300),
        };
        let pool = HealthyPool::new(test_pool(), config);

        pool.record_failure("http://p1:8080");
        pool.record_failure("http://p1:8080");
        pool.record_failure("http://p1:8080");

        let stats = pool.stats();
        assert!(stats["http://p1:8080"].deactivated_at.is_none());
        assert_eq!(pool.active_count(), 3);
    }

    #[test]
    fn cooldown_reactivation() {
        let config = HealthConfig {
            failure_threshold: 0.5,
            min_requests: 1,
            cooldown: Duration::from_millis(0), // Instant reactivation.
        };
        let inner = Arc::new(StaticPool::new(vec!["http://p1:8080".into()]));
        let pool = HealthyPool::new(inner, config);

        pool.record_failure("http://p1:8080");
        // Proxy is deactivated but cooldown is 0ms, so next() reactivates it.
        let result = pool.next();
        assert_eq!(result.unwrap(), "http://p1:8080");

        // Counters should be reset after reactivation.
        let stats = pool.stats();
        assert_eq!(stats["http://p1:8080"].successes, 0);
        assert_eq!(stats["http://p1:8080"].failures, 0);
    }

    #[test]
    fn all_unhealthy_fallback() {
        let config = HealthConfig {
            failure_threshold: 0.5,
            min_requests: 1,
            cooldown: Duration::from_secs(9999),
        };
        let inner = Arc::new(StaticPool::new(vec!["http://p1:8080".into()]));
        let pool = HealthyPool::new(inner, config);

        pool.record_failure("http://p1:8080");
        // All deactivated with long cooldown, should still return something.
        let result = pool.next();
        assert!(result.is_some());
    }
}
