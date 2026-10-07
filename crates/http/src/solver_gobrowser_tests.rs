use super::*;

#[test]
fn solve_resp_parses_new_fields() {
    // go-browser v0.20.8 /solve response — FlareSolverr shape.
    let raw = r#"{
        "status": "ok",
        "cookies": {"cf_clearance": "tok"},
        "user_agent": "Mozilla/5.0 Chrome/131",
        "body": "<html>cleared</html>",
        "final_url": "https://example.com/landing"
    }"#;
    let resp: SolveResp = serde_json::from_str(raw).unwrap();
    let ch = resp.into_challenge();
    assert_eq!(ch.cookies["cf_clearance"], "tok");
    assert_eq!(ch.user_agent, "Mozilla/5.0 Chrome/131");
    assert_eq!(ch.body.as_deref(), Some("<html>cleared</html>"));
}

#[test]
fn solve_resp_old_server_compat() {
    // Pre-v0.20.8 go-wowa omits user_agent/body — decodes as None, caller
    // falls back to cookie replay (same behaviour as before the bump).
    let raw = r#"{"status": "ok", "cookies": {"cf_clearance": "tok"}}"#;
    let resp: SolveResp = serde_json::from_str(raw).unwrap();
    let ch = resp.into_challenge();
    assert_eq!(ch.cookies["cf_clearance"], "tok");
    assert!(ch.user_agent.is_empty());
    assert!(ch.body.is_none());
}

#[test]
fn solve_resp_empty_body_means_still_challenged() {
    // Silent-failure surface: go-browser returns body:"" when the page never
    // settled past the interstitial. Dropping the `filter` (mutation:
    // `body: self.body`) maps it to Some("") — the middleware would serve an
    // empty page as solved content instead of falling back to the resend.
    let raw = r#"{"status": "ok", "cookies": {}, "user_agent": "UA", "body": ""}"#;
    let resp: SolveResp = serde_json::from_str(raw).unwrap();
    let ch = resp.into_challenge();
    assert!(ch.body.is_none(), "empty body must not become Some(\"\")");
}

/// go-wowa rejects requests without a credential: the `/solve` call must
/// carry `X-Internal-Secret`.
///
/// Falsification: drop the `.default_headers(...)` line in
/// `GoBrowserSolver::new` and the captured request has no secret → RED.
#[tokio::test]
async fn solve_sends_internal_secret() {
    let (url, req) =
        crate::wowa_auth::capture_one(r#"{"status":"ok","cookies":{"cf_clearance":"t"}}"#).await;
    let solver = GoBrowserSolver::new(GoBrowserConfig {
        base_url: url,
        timeout: Duration::from_secs(5),
        internal_secret: "s3cret".into(),
    });
    solver
        .solve("https://example.com", ChallengeType::JsChallenge)
        .await
        .expect("solve");
    let head = req.await.expect("capture");
    assert!(head.starts_with("post /solve "), "{head}");
    assert!(head.contains("x-internal-secret: s3cret"), "{head}");
}
