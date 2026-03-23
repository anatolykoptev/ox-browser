use super::*;

#[test]
fn chromium_config_defaults() {
    let cfg = ChromiumConfig::default();
    assert_eq!(cfg.timeout, Duration::from_secs(30));
    assert_eq!(cfg.max_concurrent, 3);
    assert!(cfg.proxy_url.is_none());
    assert!(cfg.chrome_path.is_none());
}

#[test]
fn chromium_config_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ChromiumConfig>();
}

#[test]
fn semaphore_matches_config() {
    let solver = ChromiumSolver::new(ChromiumConfig {
        max_concurrent: 5,
        ..Default::default()
    });
    assert_eq!(solver.semaphore.available_permits(), 5);
}

#[test]
fn chromium_solver_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ChromiumSolver>();
}

#[test]
fn chromium_config_custom_values() {
    let cfg = ChromiumConfig {
        timeout: Duration::from_secs(60),
        max_concurrent: 1,
        proxy_url: Some("http://proxy:8080".into()),
        chrome_path: Some("/usr/bin/chromium".into()),
    };
    assert_eq!(cfg.timeout, Duration::from_secs(60));
    assert_eq!(cfg.max_concurrent, 1);
    assert_eq!(cfg.proxy_url.as_deref(), Some("http://proxy:8080"));
    assert_eq!(cfg.chrome_path.as_deref(), Some("/usr/bin/chromium"));
}
