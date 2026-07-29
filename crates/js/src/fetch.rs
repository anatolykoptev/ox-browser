//! POST /fetch — fast wreq+BoringSSL fetch without headless browser.

use std::collections::HashMap;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use ox_http::deadline::{CallOutcome, bounded, resolve_timeout};
use ox_http::detect_cloudflare;
use ox_http::metrics::{classify_fetch_outcome, record_fetch_outcome};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Request body for `POST /fetch`.
///
/// `method` defaults to GET when absent and no `body` is supplied (byte-
/// identical to pre-#114 callers). When a `body` is supplied with no
/// `method`, the method defaults to POST (curl `--data` convention).
///
/// A `body` supplied with `method: "GET"` (explicit) is rejected with 400 —
/// a body on a GET is a caller mistake, and silently dropping or sending it
/// is surprising.
///
/// `content_type` defaults to `application/json` when a body is present and
/// neither `content_type` nor a `Content-Type` header is supplied. Override
/// by setting either `content_type` or a `Content-Type` entry in `headers`.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct FetchRequest {
    pub url: String,
    /// HTTP method. Defaults to GET (or POST when a body is supplied).
    /// Supported: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE.
    pub method: Option<String>,
    /// Request body (raw bytes). Implies POST when `method` is unset.
    /// Rejected with 400 when `method` is explicitly GET.
    pub body: Option<String>,
    /// Content-Type for the body. Defaults to `application/json` when a
    /// body is present and no Content-Type is set via this field or
    /// `headers`. Ignored when no body is present.
    pub content_type: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Per-call deadline in seconds. `None` → the seam default
    /// (`deadline::DEFAULT_CALL_TIMEOUT_SECS`); `Some(s)` → clamped to
    /// `[1, deadline::MAX_CALL_TIMEOUT_SECS]`. Bounds the WHOLE call
    /// (retry loop + solver escalation + rate-limit wait), not one
    /// attempt — issue #139. Same field/name/units/ceiling as `/read`'s
    /// `timeout_secs`, the MCP `fetch`/`read` tools, and the CLI
    /// `--timeout` flag.
    pub timeout: Option<u64>,
}

#[derive(Serialize)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub cf_detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_type: Option<String>,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn fetch(
    State(state): State<AppState>,
    Json(req): Json<FetchRequest>,
) -> (StatusCode, Json<FetchResponse>) {
    let start = Instant::now();

    // Resolve method: default to POST when a body is supplied (curl --data
    // convention), GET otherwise. Existing callers with no method and no
    // body are byte-identical.
    let body_bytes = req.body.as_deref().map(|b| b.as_bytes().to_vec());
    let method = req
        .method
        .as_deref()
        .map(|m| m.to_string())
        .unwrap_or_else(|| {
            if body_bytes.is_some() {
                "POST".into()
            } else {
                "GET".into()
            }
        });

    // Reject body with explicit GET — a body on a GET is a caller mistake.
    if body_bytes.is_some() && method.eq_ignore_ascii_case("GET") {
        return (
            StatusCode::BAD_REQUEST,
            Json(FetchResponse {
                status: 0,
                headers: HashMap::new(),
                body: String::new(),
                cf_detected: false,
                cf_type: None,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some("body is not allowed with method GET".into()),
            }),
        );
    }

    // Determine content type: explicit content_type field > Content-Type
    // header > default application/json (when body present). Strip any
    // Content-Type from the caller's headers to avoid a duplicate.
    let mut content_type = req.content_type.clone();
    let mut extra_headers: Vec<(String, String)> = Vec::with_capacity(req.headers.len());
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("content-type") {
            if content_type.is_none() {
                content_type = Some(v.clone());
            }
        } else {
            extra_headers.push((k.clone(), v.clone()));
        }
    }
    if content_type.is_none() && body_bytes.is_some() {
        content_type = Some("application/json".to_string());
    }

    let extra_refs: Vec<(&str, &str)> = extra_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // Bound the WHOLE call (retry loop + solver escalation + rate-limit
    // wait), not one attempt — issue #139. The deadline is caller-supplied
    // and therefore attacker-influenced, so resolve_timeout clamps it to
    // the ceiling. On elapsed the inner future is dropped, cancelling the
    // in-flight request; the in-flight gauge (managed by `bounded`)
    // decrements with it.
    let deadline = resolve_timeout(req.timeout);
    let outcome = bounded(
        deadline,
        state.http_client.request(
            &method,
            &req.url,
            body_bytes,
            content_type.as_deref(),
            &extra_refs,
        ),
    )
    .await;

    // /fetch outcome counter (issue #128) — incremented in the handler,
    // NOT in the read pipeline. The classifier is the single source of
    // truth for which label fires on which branch.
    record_fetch_outcome(classify_fetch_outcome(&outcome));

    match outcome {
        CallOutcome::Ok(Ok(resp)) => {
            let cf = detect_cloudflare(&resp);
            let cf_detected = cf.is_some();
            let cf_type = cf.map(|c| c.challenge_type.to_string());

            let headers: HashMap<String, String> = resp
                .headers
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_owned())))
                .collect();

            (
                StatusCode::OK,
                Json(FetchResponse {
                    status: resp.status,
                    headers,
                    body: resp.body,
                    cf_detected,
                    cf_type,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: None,
                }),
            )
        }
        CallOutcome::Ok(Err(e)) => (
            StatusCode::BAD_GATEWAY,
            Json(FetchResponse {
                status: 0,
                headers: HashMap::new(),
                body: String::new(),
                cf_detected: false,
                cf_type: None,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some(e.to_string()),
            }),
        ),
        // The per-call bound fired — distinct from an upstream failure
        // (502): 504 Gateway Timeout, with an error string naming the
        // bound so a caller can tell "I bounded this" from "the site
        // failed" (issue #139).
        CallOutcome::DeadlineExceeded { secs } => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(FetchResponse {
                status: 0,
                headers: HashMap::new(),
                body: String::new(),
                cf_detected: false,
                cf_type: None,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some(format!("deadline exceeded ({secs}s per-call bound)")),
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gobrowser_proxy::GoBrowserProxy;
    use crate::{AppState, EndpointDefaults};
    use async_trait::async_trait;
    use ox_http::{
        CookieCache, Handler, HttpClient, HttpConfig, HttpResponse, Request, RetryConfig,
    };
    use std::sync::Arc;
    use std::time::Duration;

    /// Mock terminal handler that always returns a 500 with a body.
    /// Used by the /fetch wrapper-contract tests below.
    struct ServerErrorMock;

    #[async_trait]
    impl Handler for ServerErrorMock {
        async fn handle(&self, req: Request) -> ox_http::Result<HttpResponse> {
            Ok(HttpResponse {
                status: 500,
                url: req.url,
                headers: Default::default(),
                body: r#"{"error":"internal","trace":"abc-123"}"#.into(),
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

    /// Build an AppState whose http_client uses a mock base handler that
    /// always returns 500, wired through the real config→middleware chain
    /// (retry + quality_check, no cloudflare_detect — the default pair).
    fn state_with_500_handler() -> AppState {
        let config = HttpConfig {
            retry: Some(fast_retry()),
            cloudflare_detect: false,
            quality_check: true,
            ..HttpConfig::default()
        };
        let client = HttpClient::with_chain(Arc::new(ServerErrorMock), config);
        let proxy = Arc::new(GoBrowserProxy::new("http://127.0.0.1:8906".to_string()));
        AppState::new(
            Arc::new(crate::tests::MockProvider),
            Arc::new(CookieCache::new(Duration::from_secs(300))),
            Arc::new(client),
            EndpointDefaults::default(),
            ox_media::MediaConfig::default(),
            proxy,
        )
    }

    // ── F-B: /fetch wrapper contract for 500 responses ───────────────────
    //
    // The retry middleware's idempotency gate creates a deliberate asymmetry
    // (see `is_idempotent` in middleware_retry.rs): a non-idempotent method
    // (POST) returns its response after a single attempt, while an idempotent
    // method (GET) exhausts retries and surfaces `Err(RetryableStatus)`. The
    // /fetch wrapper maps `Ok(resp)` → HTTP 200 with the real status/body,
    // and `Err(e)` → HTTP 502 with `status: 0` and `error` set. These two
    // tests pin both shapes at the handler level so a future change to the
    // wrapper or the retry gate cannot silently move the contract.

    /// POST on 500 → HTTP 200, `status: 500`, `error: None`, body present.
    /// POST is non-idempotent: retry returns the response as-is (no retry
    /// to trigger), so the wrapper answers 200 with the origin's status and
    /// body intact.
    #[tokio::test]
    async fn fetch_post_on_500_returns_200_with_body() {
        let state = state_with_500_handler();
        let req = FetchRequest {
            url: "http://1.1.1.1".into(),
            method: Some("POST".into()),
            body: Some(r#"{"x":1}"#.into()),
            content_type: None,
            headers: std::collections::HashMap::new(),
            timeout: None,
        };
        let (status, json) = fetch(State(state), Json(req)).await;
        assert_eq!(status, StatusCode::OK, "POST on 500 → HTTP 200");
        assert_eq!(json.status, 500, "status field carries the origin 500");
        assert!(json.error.is_none(), "error must be None for POST on 500");
        assert!(
            json.body.contains("trace"),
            "body must be preserved, got: {}",
            json.body
        );
    }

    /// GET on 500 → HTTP 502, `status: 0`, `error` set, empty body.
    /// GET is idempotent: retry exhausts its attempts, each returning 500,
    /// and surfaces `Err(RetryableStatus(500))`. The wrapper maps that to
    /// 502 with `status: 0` and the error string.
    #[tokio::test]
    async fn fetch_get_on_500_returns_502_with_error() {
        let state = state_with_500_handler();
        let req = FetchRequest {
            url: "http://1.1.1.1".into(),
            method: Some("GET".into()),
            body: None,
            content_type: None,
            headers: std::collections::HashMap::new(),
            timeout: None,
        };
        let (status, json) = fetch(State(state), Json(req)).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "GET on 500 → HTTP 502");
        assert_eq!(json.status, 0, "status field is 0 for an error");
        assert!(json.error.is_some(), "error must be set for GET on 500");
        assert!(json.body.is_empty(), "body must be empty for an error");
    }

    #[test]
    fn fetch_request_defaults() {
        let json = r#"{"url": "https://example.com"}"#;
        let req: FetchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.url, "https://example.com");
        assert!(req.timeout.is_none());
        assert!(req.headers.is_empty());
        assert!(req.method.is_none());
        assert!(req.body.is_none());
        assert!(req.content_type.is_none());
    }

    #[test]
    fn fetch_request_with_method_and_body() {
        let json = r#"{"url": "https://example.com", "method": "POST", "body": "{\"a\":1}"}"#;
        let req: FetchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method.as_deref(), Some("POST"));
        assert_eq!(req.body.as_deref(), Some("{\"a\":1}"));
    }

    #[test]
    fn fetch_request_body_without_method_defaults_to_post() {
        // curl --data convention: body with no method implies POST.
        let json = r#"{"url": "https://example.com", "body": "hello"}"#;
        let req: FetchRequest = serde_json::from_str(json).unwrap();
        assert!(req.method.is_none());
        assert!(req.body.is_some());
        // The handler resolves the default; here we just confirm the field
        // is absent (the handler tests cover the resolution).
    }

    #[test]
    fn fetch_response_serializes() {
        let resp = FetchResponse {
            status: 200,
            headers: HashMap::new(),
            body: "<html>ok</html>".into(),
            cf_detected: false,
            cf_type: None,
            elapsed_ms: 150,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], 200);
        assert_eq!(json["cf_detected"], false);
        assert!(!json.as_object().unwrap().contains_key("cf_type"));
        assert!(!json.as_object().unwrap().contains_key("error"));
    }

    #[test]
    fn fetch_response_with_cf() {
        let resp = FetchResponse {
            status: 200,
            headers: HashMap::new(),
            body: String::new(),
            cf_detected: true,
            cf_type: Some("managed_challenge_200".into()),
            elapsed_ms: 300,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["cf_detected"], true);
        assert_eq!(json["cf_type"], "managed_challenge_200");
    }
}
