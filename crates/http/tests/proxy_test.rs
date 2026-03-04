use std::sync::Arc;
use std::time::Duration;

use ox_http::{HealthConfig, HealthyPool, ProxyPool, StaticPool};

#[test]
fn static_pool_round_robin_rotation() {
    let pool = StaticPool::new(vec![
        "http://p1:8080".into(),
        "http://p2:8080".into(),
        "http://p3:8080".into(),
    ]);
    assert_eq!(pool.next().unwrap(), "http://p1:8080");
    assert_eq!(pool.next().unwrap(), "http://p2:8080");
    assert_eq!(pool.next().unwrap(), "http://p3:8080");
    // Wraps around.
    assert_eq!(pool.next().unwrap(), "http://p1:8080");
}

#[test]
fn static_pool_empty_returns_none() {
    let pool = StaticPool::new(vec![]);
    assert!(pool.is_empty());
    assert!(pool.next().is_none());
}

#[test]
fn healthy_pool_passes_through() {
    let inner = Arc::new(StaticPool::new(vec![
        "http://p1:8080".into(),
        "http://p2:8080".into(),
    ]));
    let pool = HealthyPool::new(inner, HealthConfig::default());
    assert_eq!(pool.len(), 2);
    assert!(pool.next().is_some());
    assert_eq!(pool.active_count(), 2);
}

#[test]
fn healthy_pool_deactivates_after_failures() {
    let inner = Arc::new(StaticPool::new(vec![
        "http://p1:8080".into(),
        "http://p2:8080".into(),
        "http://p3:8080".into(),
    ]));
    let config = HealthConfig {
        failure_threshold: 0.5,
        min_requests: 3,
        cooldown: Duration::from_secs(300),
    };
    let pool = HealthyPool::new(inner, config);

    // Record 3 failures for p1 — exceeds threshold.
    pool.record_failure("http://p1:8080", Duration::from_millis(50));
    pool.record_failure("http://p1:8080", Duration::from_millis(50));
    pool.record_failure("http://p1:8080", Duration::from_millis(50));

    assert_eq!(pool.active_count(), 2, "p1 should be deactivated");
}

#[test]
fn healthy_pool_active_count_tracks_deactivations() {
    let inner = Arc::new(StaticPool::new(vec![
        "http://p1:8080".into(),
        "http://p2:8080".into(),
    ]));
    let config = HealthConfig {
        failure_threshold: 0.5,
        min_requests: 1,
        cooldown: Duration::from_secs(9999),
    };
    let pool = HealthyPool::new(inner, config);

    assert_eq!(pool.active_count(), 2);
    pool.record_failure("http://p1:8080", Duration::from_millis(10));
    assert_eq!(pool.active_count(), 1);
    pool.record_failure("http://p2:8080", Duration::from_millis(10));
    assert_eq!(pool.active_count(), 0);
}
