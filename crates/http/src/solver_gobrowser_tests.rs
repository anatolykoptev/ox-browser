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

/// ox-browser#177 / SEC-CR-016: a `/solve` call made for an UNAUTHENTICATED
/// inbound caller (anonymous soft-mode request, or a bearer-only one that
/// never earned the `ok_secret` marker) must carry NO `X-Internal-Secret` —
/// the go-wowa secret is a fleet credential, not a caller pass-through.
///
/// Falsification: attach the secret unconditionally (the pre-#177 code did,
/// via `.default_headers`) and the captured head carries it → RED.
#[tokio::test]
async fn solve_sends_no_secret_for_anonymous_caller() {
    let (url, req) =
        crate::wowa_auth::capture_one(r#"{"status":"ok","cookies":{"cf_clearance":"t"}}"#).await;
    let solver = GoBrowserSolver::new(GoBrowserConfig {
        base_url: url,
        timeout: Duration::from_secs(5),
        internal_secret: "s3cret".into(),
    });
    solver
        .solve("https://example.com", ChallengeType::JsChallenge, false)
        .await
        .expect("solve");
    let head = req.await.expect("capture");
    assert!(
        !head.contains("x-internal-secret"),
        "anonymous solve relayed the fleet secret: {head}"
    );
}

/// The same /solve call made for an AUTHENTICATED inbound caller (the gate's
/// `ok_secret` marker) carries `X-Internal-Secret` — go-wowa rejects
/// credentialed routes without it.
///
/// Falsification: drop the `if authenticated` header attach in
/// `GoBrowserSolver::solve` and the captured request has no secret → RED.
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
        .solve("https://example.com", ChallengeType::JsChallenge, true)
        .await
        .expect("solve");
    let head = req.await.expect("capture");
    assert!(head.starts_with("post /solve "), "{head}");
    assert!(head.contains("x-internal-secret: s3cret"), "{head}");
}

/// A redirect from go-wowa is not followed with the credential (SEC-CR-010).
///
/// Falsification: remove `.redirect(Policy::none())` in
/// `GoBrowserSolver::new` and the 302 is followed → RED.
#[tokio::test]
async fn solve_does_not_follow_redirects() {
    let (target, hit) = crate::wowa_auth::capture_one(r#"{"status":"ok","cookies":{}}"#).await;
    let redirector = crate::wowa_auth::redirect_once(target).await;
    let solver = GoBrowserSolver::new(GoBrowserConfig {
        base_url: redirector,
        timeout: Duration::from_secs(5),
        internal_secret: "s3cret".into(),
    });
    let _ = solver
        .solve("https://example.com", ChallengeType::JsChallenge, true)
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), hit)
            .await
            .is_err(),
        "redirect was followed"
    );
}
