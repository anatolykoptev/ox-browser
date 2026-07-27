use std::sync::Arc;
use std::time::Duration;

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
    pool.record_success("http://p1:8080", Duration::from_millis(100));
    pool.record_success("http://p1:8080", Duration::from_millis(100));

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

    pool.record_failure("http://p1:8080", Duration::from_millis(50));
    pool.record_failure("http://p1:8080", Duration::from_millis(50));
    pool.record_failure("http://p1:8080", Duration::from_millis(50));

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

    pool.record_failure("http://p1:8080", Duration::from_millis(50));
    pool.record_failure("http://p1:8080", Duration::from_millis(50));
    pool.record_failure("http://p1:8080", Duration::from_millis(50));

    let stats = pool.stats();
    assert!(stats["http://p1:8080"].deactivated_at.is_none());
    assert_eq!(pool.active_count(), 3);
}

#[test]
fn cooldown_reactivation() {
    let config = HealthConfig {
        failure_threshold: 0.5,
        min_requests: 1,
        cooldown: Duration::from_millis(0),
    };
    let inner = Arc::new(StaticPool::new(vec!["http://p1:8080".into()]));
    let pool = HealthyPool::new(inner, config);

    pool.record_failure("http://p1:8080", Duration::from_millis(50));
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

    pool.record_failure("http://p1:8080", Duration::from_millis(50));
    let result = pool.next();
    assert!(result.is_some());
}

#[test]
fn evict_stale_drops_old_deactivated_keeps_active() {
    // Issue #21: a deactivated, long-unused proxy (e.g. a rotated-out Webshare
    // proxy) must be evicted by evict_stale(), while active proxies — even old
    // ones — are never evicted.
    let config = HealthConfig {
        failure_threshold: 0.5,
        min_requests: 1,
        cooldown: Duration::from_millis(10),
    };
    let pool = HealthyPool::new(test_pool(), config);

    // Simulate a proxy that was deactivated long ago and never used since.
    // `Instant::now() - Duration` yields a past instant (std::ops::Sub).
    let ancient = Instant::now() - Duration::from_secs(9999);
    {
        let mut health = pool.health.lock().unwrap();
        let stale = health
            .entry("http://p1:8080".to_string())
            .or_insert_with(ProxyHealth::new);
        stale.deactivated_at = Some(ancient);
        stale.last_used = ancient;

        // An active proxy that is also ancient — must survive eviction.
        let active = health
            .entry("http://p2:8080".to_string())
            .or_insert_with(ProxyHealth::new);
        active.last_used = ancient;
    }

    pool.evict_stale();

    let stats = pool.stats();
    assert!(
        !stats.contains_key("http://p1:8080"),
        "stale deactivated proxy should be evicted, stats: {stats:?}"
    );
    assert!(
        stats.contains_key("http://p2:8080"),
        "active proxy must never be evicted, stats: {stats:?}"
    );
}

#[test]
fn evict_stale_keeps_recently_used_deactivated() {
    // A deactivated proxy that was used recently (within cooldown * 4) must
    // survive eviction — it may still be reactivated on the next cooldown check.
    let config = HealthConfig {
        failure_threshold: 0.5,
        min_requests: 1,
        cooldown: Duration::from_secs(300),
    };
    let pool = HealthyPool::new(test_pool(), config);

    pool.record_failure("http://p1:8080", Duration::from_millis(50));
    // Deactivated just now → last_used is recent → must survive.
    assert!(pool.stats()["http://p1:8080"].deactivated_at.is_some());

    pool.evict_stale();
    assert!(
        pool.stats().contains_key("http://p1:8080"),
        "recently-used deactivated proxy should survive eviction"
    );
}
