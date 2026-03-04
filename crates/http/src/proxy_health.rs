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
    pub total_latency: Duration,
    pub last_used: Instant,
    pub deactivated_at: Option<Instant>,
}

impl ProxyHealth {
    fn new() -> Self {
        Self {
            successes: 0,
            failures: 0,
            total_latency: Duration::ZERO,
            last_used: Instant::now(),
            deactivated_at: None,
        }
    }

    /// Average request latency.
    pub fn avg_latency(&self) -> Duration {
        let total = self.total();
        if total == 0 {
            return Duration::ZERO;
        }
        self.total_latency / total as u32
    }

    /// Total number of requests recorded.
    pub fn total(&self) -> u64 {
        self.successes + self.failures
    }

    /// Failure rate as a fraction (0.0-1.0).
    pub fn failure_rate(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        self.failures as f64 / total as f64
    }

    /// Returns `true` if this proxy has not been deactivated.
    pub fn is_active(&self) -> bool {
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
    pub fn record_success(&self, proxy: &str, latency: Duration) {
        let mut health = self.health.lock().unwrap();
        let entry = health.entry(proxy.to_string()).or_insert_with(ProxyHealth::new);
        entry.successes += 1;
        entry.total_latency += latency;
        entry.last_used = Instant::now();
    }

    /// Records a failed request. Deactivates the proxy if the failure
    /// rate exceeds the threshold after `min_requests`.
    pub fn record_failure(&self, proxy: &str, latency: Duration) {
        let mut health = self.health.lock().unwrap();
        let entry = health.entry(proxy.to_string()).or_insert_with(ProxyHealth::new);
        entry.failures += 1;
        entry.total_latency += latency;
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
            return true;
        };
        if let Some(deactivated_at) = entry.deactivated_at {
            if deactivated_at.elapsed() >= self.config.cooldown {
                entry.successes = 0;
                entry.failures = 0;
                entry.total_latency = Duration::ZERO;
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
#[path = "proxy_health_test.rs"]
mod tests;
