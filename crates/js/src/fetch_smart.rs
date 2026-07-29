//! POST /fetch-smart — DEPRECATED: Use POST /read instead.
//!
//! Kept for backward compatibility. Middleware chain handles CF automatically.

use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use ox_http::deadline::{CallOutcome, bounded, resolve_timeout};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Request body for `POST /fetch-smart` (DEPRECATED: use `/read`).
///
/// `timeout` is the per-call deadline in seconds (issue #145). The legacy
/// `timeout_secs` spelling is accepted via a serde alias but is not the
/// canonical name. Same field/name/units/ceiling as `/fetch`, `/read`,
/// the MCP `fetch`/`read`/`fetch_smart` tools, and the CLI `--timeout` flag.
#[derive(Deserialize)]
pub struct FetchSmartRequest {
    pub url: String,
    /// Per-call deadline in seconds. `None` → seam default
    /// (`deadline::DEFAULT_CALL_TIMEOUT_SECS`); `Some(s)` → clamped to
    /// `[1, deadline::MAX_CALL_TIMEOUT_SECS]`. Bounds the WHOLE call
    /// (retry loop + solver escalation + rate-limit wait), not one
    /// attempt — issue #145.
    #[serde(default, alias = "timeout_secs")]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub save_to_file: Option<bool>,
}

#[derive(Serialize)]
pub struct FetchSmartResponse {
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    pub method: String,
    pub cf_detected: bool,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn fetch_smart(
    State(state): State<AppState>,
    Json(req): Json<FetchSmartRequest>,
) -> (StatusCode, Json<FetchSmartResponse>) {
    let start = Instant::now();
    let save = req.save_to_file.unwrap_or(false);
    let url = req.url.clone();

    // Bound the WHOLE call (retry loop + solver escalation + rate-limit
    // wait), not one attempt — issue #145. The deadline is caller-supplied
    // and therefore attacker-influenced, so resolve_timeout clamps it to
    // the ceiling. On elapsed the inner future is dropped, cancelling the
    // in-flight request; the in-flight gauge (managed by `bounded`)
    // decrements with it. Same seam placement as `/fetch`
    // (`crates/js/src/fetch.rs`) and `read_pipeline::read_page` — outside
    // any retry, wrapping the top-level future.
    let deadline = resolve_timeout(req.timeout);
    let outcome = bounded(deadline, state.http_client.get(&req.url)).await;

    match outcome {
        CallOutcome::Ok(Ok(resp)) => (
            StatusCode::OK,
            Json(make_response(
                resp.status,
                resp.body,
                "auto",
                false,
                start,
                save,
                &url,
                None,
            )),
        ),
        CallOutcome::Ok(Err(e)) => (
            StatusCode::BAD_GATEWAY,
            Json(make_response(
                0,
                String::new(),
                "auto",
                false,
                start,
                save,
                &url,
                Some(e.to_string()),
            )),
        ),
        // The per-call bound fired — distinct from an upstream failure
        // (502): 504 Gateway Timeout, with an error string naming the
        // bound so a caller can tell "I bounded this" from "the site
        // failed" (issue #145). Same shape as `/fetch`.
        CallOutcome::DeadlineExceeded { secs } => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(make_response(
                0,
                String::new(),
                "auto",
                false,
                start,
                save,
                &url,
                Some(format!("deadline exceeded ({secs}s per-call bound)")),
            )),
        ),
    }
}

#[allow(clippy::too_many_arguments)] // assembles a response from independent fields
fn make_response(
    status: u16,
    body: String,
    method: &str,
    cf: bool,
    start: Instant,
    save: bool,
    url: &str,
    error: Option<String>,
) -> FetchSmartResponse {
    let (body_field, file_path) = if save && !body.is_empty() {
        match ox_core::save::save_response(url, &body) {
            Ok(path) => (None, Some(path.display().to_string())),
            Err(e) => {
                tracing::warn!(error = %e, "failed to save, returning inline");
                (Some(body), None)
            }
        }
    } else {
        (if body.is_empty() { None } else { Some(body) }, None)
    };

    FetchSmartResponse {
        status,
        body: body_field,
        file_path,
        method: method.into(),
        cf_detected: cf,
        elapsed_ms: start.elapsed().as_millis() as u64,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gobrowser_proxy::GoBrowserProxy;
    use crate::{AppState, EndpointDefaults};
    use async_trait::async_trait;
    use ox_http::deadline::resolve_timeout;
    use ox_http::{
        CookieCache, Handler, HttpClient, HttpConfig, HttpResponse, Request, RetryConfig,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn fetch_smart_request_defaults() {
        let json = r#"{"url": "https://example.com"}"#;
        let req: FetchSmartRequest = serde_json::from_str(json).unwrap();
        assert!(req.timeout.is_none());
    }

    // ── PER-CALL DEADLINE (issue #145) ────────────────────────────────────
    //
    // `/fetch-smart` declared `timeout` and ignored it (the struct carried
    // `#[allow(dead_code)]`, which silenced the unread-field warning). These
    // assert the RESOLVED deadline / the bound actually firing — never merely
    // that deserialization returned `Ok`, because an unknown or unread field
    // deserializes fine and is discarded, which is exactly how this defect
    // survived.

    /// `/fetch-smart` accepts the canonical `{"timeout": 1}` and resolves to
    /// 1 s (not the 8 s default). GREEN before and after the seam is wired.
    #[test]
    fn fetch_smart_request_timeout_canonical_name_resolves() {
        let req: FetchSmartRequest =
            serde_json::from_str(r#"{"url":"https://x.com","timeout":1}"#).unwrap();
        assert_eq!(
            resolve_timeout(req.timeout),
            Duration::from_secs(1),
            "canonical `timeout` must resolve to 1s"
        );
    }

    /// `/fetch-smart` accepts the legacy `{"timeout_secs": 1}` via the alias
    /// and resolves to 1 s. RED on the pre-alias code: `timeout_secs` is an
    /// unknown field → dropped → `req.timeout` is `None` → 8 s ≠ 1 s.
    #[test]
    fn fetch_smart_request_timeout_secs_alias_resolves() {
        let req: FetchSmartRequest =
            serde_json::from_str(r#"{"url":"https://x.com","timeout_secs":1}"#).unwrap();
        assert_eq!(
            resolve_timeout(req.timeout),
            Duration::from_secs(1),
            "alias `timeout_secs` must resolve to 1s, not the 8s default"
        );
    }

    /// Handler that sleeps `delay` before responding. Used to trigger the
    /// per-call deadline in `fetch_smart` (which wraps the call with
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

    /// Build an AppState whose http_client uses `handler` as the base,
    /// wired through the real config→middleware chain (retry +
    /// quality_check, no cloudflare_detect — the default pair).
    fn state_with_handler(handler: Arc<dyn Handler>) -> AppState {
        let config = HttpConfig {
            retry: Some(fast_retry()),
            cloudflare_detect: false,
            quality_check: true,
            ..HttpConfig::default()
        };
        let client = HttpClient::with_chain(handler, config);
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

    /// `/fetch-smart` with `timeout: 1` against a handler that sleeps 10 s
    /// MUST return a deadline-exceeded response (504, error naming the bound,
    /// elapsed ~1 s), NOT a 200 success at ~10 s. RED on the pre-seam code:
    /// the field is ignored, the slow handler completes at ~10 s, so the
    /// handler returns `StatusCode::OK` with `error: None`.
    #[tokio::test]
    async fn fetch_smart_honours_caller_timeout_bound_fires() {
        let calls = Arc::new(AtomicUsize::new(0));
        let state = state_with_handler(Arc::new(SlowHandler {
            delay: Duration::from_secs(10),
            calls: calls.clone(),
        }));
        let req = FetchSmartRequest {
            url: "http://slow.test/page".into(),
            timeout: Some(1),
            save_to_file: Some(false),
        };
        let (status, json) = fetch_smart(State(state), Json(req)).await;
        assert_eq!(
            status,
            StatusCode::GATEWAY_TIMEOUT,
            "bound must fire → 504, got {status} (RED today: 200 OK because timeout ignored)"
        );
        let err = json
            .error
            .as_deref()
            .expect("deadline-exceeded response must carry an error string");
        assert!(
            err.contains("deadline"),
            "error must mention deadline; got: {err:?}"
        );
        assert!(
            err.contains("per-call bound"),
            "error must name the per-call bound (parity with /fetch); got: {err:?}"
        );
        assert!(
            json.elapsed_ms < 3_000,
            "deadline should fire at ~1s, got elapsed_ms={}",
            json.elapsed_ms
        );
    }

    /// A bound that fires returns the deadline-exceeded shape (504 +
    /// "deadline exceeded (...s per-call bound)"), distinguishable from a
    /// site failure (502 + the site's error string). This pins the shape so
    /// a future change cannot collapse the two. Shares the slow-handler
    /// setup with the bound-fires test above.
    #[tokio::test]
    async fn fetch_smart_deadline_shape_is_not_a_site_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let state = state_with_handler(Arc::new(SlowHandler {
            delay: Duration::from_secs(10),
            calls,
        }));
        let req = FetchSmartRequest {
            url: "http://slow.test/page".into(),
            timeout: Some(1),
            save_to_file: Some(false),
        };
        let (status, json) = fetch_smart(State(state), Json(req)).await;
        assert_ne!(
            status,
            StatusCode::BAD_GATEWAY,
            "deadline-exceeded must NOT map to 502 (site-error); got 502"
        );
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(json.status, 0, "status field is 0 for a bound firing");
        assert!(
            json.body.is_none(),
            "no body on a deadline-exceeded response"
        );
        let err = json.error.as_deref().unwrap();
        assert!(
            err.starts_with("deadline exceeded"),
            "error must start with 'deadline exceeded'; got: {err:?}"
        );
    }

    #[test]
    fn fetch_smart_response_serializes_inline() {
        let resp = FetchSmartResponse {
            status: 200,
            body: Some("ok".into()),
            file_path: None,
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 100,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["method"], "direct");
        assert_eq!(json["body"], "ok");
        assert!(!json.as_object().unwrap().contains_key("error"));
    }

    #[test]
    fn fetch_smart_response_serializes_file() {
        let resp = FetchSmartResponse {
            status: 200,
            body: None,
            file_path: Some("/tmp/ox-browser/example.com_abc.html".into()),
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 100,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("body").is_none());
        assert_eq!(json["file_path"], "/tmp/ox-browser/example.com_abc.html");
    }
}
