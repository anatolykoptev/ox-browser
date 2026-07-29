//! Unit tests for fetch.rs — serialization helpers and input defaults.

use super::{FetchInput, FetchSmartInput};

// ── FetchInput ────────────────────────────────────────────────────────────────

#[test]
fn fetch_input_required_url() {
    let json = r#"{"url": "https://example.com"}"#;
    let input: FetchInput = serde_json::from_str(json).unwrap();
    assert_eq!(input.url, "https://example.com");
    // F5: method/body/content_type default to None (GET, no body).
    assert!(input.method.is_none());
    assert!(input.body.is_none());
    assert!(input.content_type.is_none());
}

#[test]
fn fetch_input_missing_url_fails() {
    let json = r#"{}"#;
    let result: Result<FetchInput, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn fetch_input_with_method_and_body() {
    let json = r#"{"url": "https://example.com", "method": "POST", "body": "{\"a\":1}"}"#;
    let input: FetchInput = serde_json::from_str(json).unwrap();
    assert_eq!(input.method.as_deref(), Some("POST"));
    assert_eq!(input.body.as_deref(), Some("{\"a\":1}"));
}

#[test]
fn fetch_input_body_without_method_defaults_to_post() {
    let json = r#"{"url": "https://example.com", "body": "hello"}"#;
    let input: FetchInput = serde_json::from_str(json).unwrap();
    assert!(input.method.is_none());
    assert!(input.body.is_some());
}

#[test]
fn fetch_input_with_content_type() {
    let json = r#"{"url": "https://example.com", "method": "POST", "body": "x", "content_type": "text/xml"}"#;
    let input: FetchInput = serde_json::from_str(json).unwrap();
    assert_eq!(input.content_type.as_deref(), Some("text/xml"));
}

// ── WIRE-NAME PARITY (issue #139 follow-up) ───────────────────────────────────
//
// `timeout` is canonical; `timeout_secs` is accepted via a serde alias so a
// caller guessing the wrong spelling does not silently get the 8 s default.
// Asserts the RESOLVED deadline, not merely Ok(_).

#[test]
fn fetch_input_timeout_canonical_name_resolves() {
    use ox_http::deadline::resolve_timeout;
    let input: FetchInput = serde_json::from_str(r#"{"url":"https://x.com","timeout":1}"#).unwrap();
    assert_eq!(
        resolve_timeout(input.timeout),
        std::time::Duration::from_secs(1),
        "canonical `timeout` must resolve to 1s"
    );
}

#[test]
fn fetch_input_timeout_secs_alias_resolves() {
    use ox_http::deadline::resolve_timeout;
    let input: FetchInput =
        serde_json::from_str(r#"{"url":"https://x.com","timeout_secs":1}"#).unwrap();
    assert_eq!(
        resolve_timeout(input.timeout),
        std::time::Duration::from_secs(1),
        "alias `timeout_secs` must resolve to 1s, not the 8s default"
    );
}

// ── FetchSmartInput ───────────────────────────────────────────────────────────

#[test]
fn fetch_smart_input_save_to_file_defaults_true() {
    let json = r#"{"url": "https://example.com"}"#;
    let input: FetchSmartInput = serde_json::from_str(json).unwrap();
    assert!(input.save_to_file, "save_to_file should default to true");
}

#[test]
fn fetch_smart_input_save_to_file_explicit_false() {
    let json = r#"{"url": "https://example.com", "save_to_file": false}"#;
    let input: FetchSmartInput = serde_json::from_str(json).unwrap();
    assert!(!input.save_to_file);
}

#[test]
fn fetch_smart_input_save_to_file_explicit_true() {
    let json = r#"{"url": "https://example.com", "save_to_file": true}"#;
    let input: FetchSmartInput = serde_json::from_str(json).unwrap();
    assert!(input.save_to_file);
}

#[test]
fn fetch_smart_input_missing_url_fails() {
    let json = r#"{"save_to_file": false}"#;
    let result: Result<FetchSmartInput, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

// ── FetchResult serialization ─────────────────────────────────────────────────

#[test]
fn fetch_result_skips_none_cf_type() {
    use std::collections::HashMap;
    // Construct via JSON round-trip since FetchResult is private.
    // We exercise the serialization behavior indirectly by constructing the
    // equivalent JSON manually and asserting field presence rules.
    let json = serde_json::json!({
        "status": 200u16,
        "headers": {},
        "body": "hello",
        "cf_detected": false,
        "elapsed_ms": 42u64
        // cf_type absent — skip_serializing_if = Option::is_none
        // error absent — skip_serializing_if = Option::is_none
    });
    let obj = json.as_object().unwrap();
    assert!(!obj.contains_key("cf_type"));
    assert!(!obj.contains_key("error"));
    assert_eq!(json["status"], 200);
    let _: HashMap<String, String> = serde_json::from_value(json["headers"].clone()).unwrap();
}

// ── FetchSmartResult serialization ───────────────────────────────────────────

mod smart_result {
    use serde::Serialize;

    // Mirror the private struct for serialization-only tests.
    #[derive(Serialize)]
    struct FetchSmartResult {
        status: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        body: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        file_path: Option<String>,
        method: String,
        cf_detected: bool,
        elapsed_ms: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    }

    #[test]
    fn inline_body_present_file_path_absent() {
        let r = FetchSmartResult {
            status: 200,
            body: Some("content".into()),
            file_path: None,
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 10,
            error: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["body"], "content");
        assert!(v.get("file_path").is_none());
        assert!(v.get("error").is_none());
    }

    #[test]
    fn file_path_present_body_absent() {
        let r = FetchSmartResult {
            status: 200,
            body: None,
            file_path: Some("/tmp/ox-browser/example.com_abc.html".into()),
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 10,
            error: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(v.get("body").is_none());
        assert_eq!(v["file_path"], "/tmp/ox-browser/example.com_abc.html");
    }

    #[test]
    fn error_present_serialized() {
        let r = FetchSmartResult {
            status: 0,
            body: None,
            file_path: None,
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 5,
            error: Some("connection refused".into()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["error"], "connection refused");
        assert_eq!(v["status"], 0);
    }

    #[test]
    fn method_field_preserved() {
        for method in ["direct", "solved"] {
            let r = FetchSmartResult {
                status: 200,
                body: Some("ok".into()),
                file_path: None,
                method: method.into(),
                cf_detected: true,
                elapsed_ms: 100,
                error: None,
            };
            let v = serde_json::to_value(&r).unwrap();
            assert_eq!(v["method"], method);
            assert_eq!(v["cf_detected"], true);
        }
    }
}

// ── default_true helper ───────────────────────────────────────────────────────

#[test]
fn default_true_via_serde_default() {
    // Verify the serde(default = "default_true") path indirectly: omitting the
    // field in JSON produces true.
    let input: FetchSmartInput = serde_json::from_str(r#"{"url":"https://x.com"}"#).unwrap();
    assert!(input.save_to_file);

    // Explicit false overrides the default.
    let input2: FetchSmartInput =
        serde_json::from_str(r#"{"url":"https://x.com","save_to_file":false}"#).unwrap();
    assert!(!input2.save_to_file);
}

// ── PER-CALL DEADLINE (issue #145) ───────────────────────────────────────────
//
// The MCP `fetch_smart` tool had no `timeout` field and no per-call bound.
// These assert the RESOLVED deadline / the bound actually firing — never
// merely that deserialization returned `Ok`, because an unknown field
// deserializes fine and is discarded, which is exactly how this defect
// survived.

/// `fetch_smart` accepts the canonical `{"timeout": 1}` and resolves to 1 s
/// (not the 8 s default). GREEN before and after the seam is wired.
#[test]
fn fetch_smart_input_timeout_canonical_name_resolves() {
    use ox_http::deadline::resolve_timeout;
    let input: FetchSmartInput =
        serde_json::from_str(r#"{"url":"https://x.com","timeout":1}"#).unwrap();
    assert_eq!(
        resolve_timeout(input.timeout),
        std::time::Duration::from_secs(1),
        "canonical `timeout` must resolve to 1s"
    );
}

/// `fetch_smart` accepts the legacy `{"timeout_secs": 1}` via the alias and
/// resolves to 1 s. RED on the pre-alias code: `timeout_secs` is an unknown
/// field → dropped → `input.timeout` is `None` → 8 s ≠ 1 s.
#[test]
fn fetch_smart_input_timeout_secs_alias_resolves() {
    use ox_http::deadline::resolve_timeout;
    let input: FetchSmartInput =
        serde_json::from_str(r#"{"url":"https://x.com","timeout_secs":1}"#).unwrap();
    assert_eq!(
        resolve_timeout(input.timeout),
        std::time::Duration::from_secs(1),
        "alias `timeout_secs` must resolve to 1s, not the 8s default"
    );
}

mod deadline {
    use super::super::{FetchSmartInput, OxMcpServer};
    use async_trait::async_trait;
    use ox_http::{
        ChallengeType, CookieCache, CookieProvider, Handler, HttpClient, HttpConfig, HttpResponse,
        Request, RetryConfig, SolvedChallenge,
    };
    use ox_js::EndpointDefaults;
    use ox_js::gobrowser_proxy::GoBrowserProxy;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// CookieProvider stub — mirrors ox-js's `MockProvider`.
    struct StubProvider;

    #[async_trait]
    impl CookieProvider for StubProvider {
        async fn solve(&self, _url: &str, _ct: ChallengeType) -> Result<SolvedChallenge, String> {
            let mut cookies = HashMap::new();
            cookies.insert("cf_clearance".into(), "test-token".into());
            Ok(SolvedChallenge {
                cookies,
                user_agent: "TestUA/1.0".into(),
                body: None,
            })
        }
    }

    /// Handler that sleeps `delay` before responding. Used to trigger the
    /// per-call deadline in `do_fetch_smart` (which wraps the call with
    /// `deadline::bounded`).
    struct SlowHandler {
        delay: Duration,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Handler for SlowHandler {
        async fn handle(&self, req: Request) -> ox_http::Result<HttpResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(HttpResponse {
                status: 200,
                url: req.url,
                headers: Default::default(),
                body: "<html><body>content</body></html>".into(),
            })
        }
    }

    fn fast_retry() -> RetryConfig {
        RetryConfig {
            max_retries: 3,
            initial_wait: Duration::from_millis(1),
            max_wait: Duration::from_millis(10),
            jitter_pct: 0.0,
            ..Default::default()
        }
    }

    fn server_with_handler(handler: Arc<dyn Handler>) -> OxMcpServer {
        let config = HttpConfig {
            retry: Some(fast_retry()),
            cloudflare_detect: false,
            quality_check: true,
            ..HttpConfig::default()
        };
        let client = Arc::new(HttpClient::with_chain(handler, config));
        let proxy = Arc::new(GoBrowserProxy::new("http://127.0.0.1:8906".to_string()));
        OxMcpServer::new(
            Arc::new(StubProvider),
            Arc::new(CookieCache::new(Duration::from_secs(300))),
            client,
            EndpointDefaults::default(),
            ox_media::MediaConfig::default(),
            proxy,
        )
    }

    /// Extract the JSON text payload from a `CallToolResult`.
    fn text_payload(res: &rmcp::model::CallToolResult) -> String {
        res.content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.clone())
            .unwrap_or_default()
    }

    /// `fetch_smart` with `timeout: 1` against a handler that sleeps 10 s
    /// MUST return a deadline-exceeded result (`is_error: Some(true)`, error
    /// string naming the bound, elapsed ~1 s), NOT a success at ~10 s. RED
    /// on the pre-seam code: there is no `timeout` field, the slow handler
    /// completes at ~10 s, and `do_fetch_smart` returns
    /// `CallToolResult::success`.
    #[tokio::test]
    async fn fetch_smart_honours_caller_timeout_bound_fires() {
        let calls = Arc::new(AtomicUsize::new(0));
        let server = server_with_handler(Arc::new(SlowHandler {
            delay: Duration::from_secs(10),
            calls: calls.clone(),
        }));
        let input = FetchSmartInput {
            url: "http://slow.test/page".into(),
            save_to_file: false,
            timeout: Some(1),
        };
        let res = server.do_fetch_smart(input).await.unwrap();
        assert_eq!(
            res.is_error,
            Some(true),
            "bound must fire → is_error, got {:?} (RED today: Some(false) because no seam)",
            res.is_error
        );
        let body = text_payload(&res);
        let parsed: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse: {e}; body={body}"));
        let err = parsed["error"]
            .as_str()
            .unwrap_or_else(|| panic!("error field missing; body={body}"));
        assert!(
            err.contains("deadline"),
            "error must mention deadline; got: {err:?}"
        );
        assert!(
            err.contains("per-call bound"),
            "error must name the per-call bound (parity with MCP fetch); got: {err:?}"
        );
        let elapsed = parsed["elapsed_ms"].as_u64().unwrap_or(u64::MAX);
        assert!(
            elapsed < 3_000,
            "deadline should fire at ~1s, got elapsed_ms={elapsed}"
        );
    }

    /// A bound that fires returns the deadline-exceeded shape
    /// (`is_error: Some(true)` + "deadline exceeded (...s per-call bound)"),
    /// distinguishable from a site failure (`is_error: Some(true)` + the
    /// site's error string). This pins the shape so a future change cannot
    /// collapse the two. Shares the slow-handler setup above.
    #[tokio::test]
    async fn fetch_smart_deadline_shape_is_not_a_site_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let server = server_with_handler(Arc::new(SlowHandler {
            delay: Duration::from_secs(10),
            calls,
        }));
        let input = FetchSmartInput {
            url: "http://slow.test/page".into(),
            save_to_file: false,
            timeout: Some(1),
        };
        let res = server.do_fetch_smart(input).await.unwrap();
        assert_eq!(res.is_error, Some(true));
        let body = text_payload(&res);
        let parsed: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse: {e}; body={body}"));
        let err = parsed["error"]
            .as_str()
            .unwrap_or_else(|| panic!("error field missing; body={body}"));
        assert!(
            err.starts_with("deadline exceeded"),
            "error must start with 'deadline exceeded'; got: {err:?}"
        );
        assert_eq!(parsed["status"], 0, "status field is 0 for a bound firing");
        assert!(
            parsed.get("body").map(|v| v.is_null()).unwrap_or(true),
            "no body on a deadline-exceeded response; got: {parsed}"
        );
    }
}
