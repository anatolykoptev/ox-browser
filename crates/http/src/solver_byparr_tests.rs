use std::time::Duration;

use super::*;

#[test]
fn default_config() {
    let cfg = ByparrConfig::default();
    assert_eq!(cfg.base_url, "http://127.0.0.1:8191");
    assert_eq!(cfg.timeout, Duration::from_secs(60));
    assert_eq!(cfg.memory_budget_mb, 768);
}

#[test]
fn max_concurrent_from_memory() {
    // 768 MB → (768 - 150) / 100 = 6
    let cfg = ByparrConfig {
        memory_budget_mb: 768,
        ..Default::default()
    };
    assert_eq!(cfg.max_concurrent(), 6);

    // 512 MB → (512 - 150) / 100 = 3
    let cfg = ByparrConfig {
        memory_budget_mb: 512,
        ..Default::default()
    };
    assert_eq!(cfg.max_concurrent(), 3);

    // 1024 MB → (1024 - 150) / 100 = 8
    let cfg = ByparrConfig {
        memory_budget_mb: 1024,
        ..Default::default()
    };
    assert_eq!(cfg.max_concurrent(), 8);

    // 200 MB → (200 - 150) / 100 = 0 → clamped to 1
    let cfg = ByparrConfig {
        memory_budget_mb: 200,
        ..Default::default()
    };
    assert_eq!(cfg.max_concurrent(), 1);

    // 100 MB (less than overhead) → saturating_sub = 0, clamped to 1
    let cfg = ByparrConfig {
        memory_budget_mb: 100,
        ..Default::default()
    };
    assert_eq!(cfg.max_concurrent(), 1);
}

#[test]
fn solver_request_serializes() {
    let req = SolverRequest {
        cmd: "request.get".into(),
        url: "https://example.com".into(),
        max_timeout: 60000,
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["cmd"], "request.get");
    assert_eq!(json["url"], "https://example.com");
    assert_eq!(json["maxTimeout"], 60000);
    assert!(!json.as_object().unwrap().contains_key("max_timeout"));
}

#[test]
fn solver_response_deserializes_ok() {
    let json = r#"{
        "status": "ok",
        "solution": {
            "url": "https://example.com",
            "cookies": [
                {"name": "cf_clearance", "value": "abc123"},
                {"name": "__cflb", "value": "xyz"}
            ],
            "userAgent": "Mozilla/5.0 Test"
        },
        "message": null
    }"#;
    let resp: SolverResponse = serde_json::from_str(json).unwrap();
    assert_eq!(resp.status, "ok");
    let sol = resp.solution.unwrap();
    assert_eq!(sol.cookies.len(), 2);
    assert_eq!(sol.cookies[0].name, "cf_clearance");
    assert_eq!(sol.cookies[0].value, "abc123");
    assert_eq!(sol.user_agent, "Mozilla/5.0 Test");
}

#[test]
fn solver_response_deserializes_error() {
    let json = r#"{
        "status": "error",
        "solution": null,
        "message": "Challenge not detected!"
    }"#;
    let resp: SolverResponse = serde_json::from_str(json).unwrap();
    assert_eq!(resp.status, "error");
    assert!(resp.solution.is_none());
    assert_eq!(resp.message.unwrap(), "Challenge not detected!");
}

#[test]
fn solver_response_with_body() {
    let json = r#"{
        "status": "ok",
        "solution": {
            "url": "https://example.com",
            "cookies": [{"name": "cf_clearance", "value": "abc123"}],
            "userAgent": "Mozilla/5.0 Test",
            "response": "<html><body>Solved page content</body></html>"
        },
        "message": null
    }"#;
    let resp: SolverResponse = serde_json::from_str(json).unwrap();
    let sol = resp.solution.unwrap();
    assert_eq!(
        sol.response.as_deref(),
        Some("<html><body>Solved page content</body></html>")
    );
}

#[test]
fn solver_response_without_body() {
    let json = r#"{
        "status": "ok",
        "solution": {
            "url": "https://example.com",
            "cookies": [{"name": "cf_clearance", "value": "abc123"}],
            "userAgent": "Mozilla/5.0 Test"
        },
        "message": null
    }"#;
    let resp: SolverResponse = serde_json::from_str(json).unwrap();
    let sol = resp.solution.unwrap();
    assert!(sol.response.is_none());
}

#[test]
fn byparr_solver_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ByparrSolver>();
}

#[tokio::test]
async fn semaphore_matches_memory_budget() {
    let solver = ByparrSolver::new(ByparrConfig {
        memory_budget_mb: 768,
        ..Default::default()
    });
    // 768 → 6 concurrent
    assert_eq!(solver.semaphore.available_permits(), 6);

    let solver = ByparrSolver::new(ByparrConfig {
        memory_budget_mb: 512,
        ..Default::default()
    });
    assert_eq!(solver.semaphore.available_permits(), 3);
}
