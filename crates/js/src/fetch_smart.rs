//! POST /fetch-smart — DEPRECATED: Use POST /read instead.
//!
//! Kept for backward compatibility. Middleware chain handles CF automatically.

use std::time::Instant;

use axum::http::StatusCode;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use ox_http::deadline::{CallOutcome, bounded, resolve_timeout};

use crate::AppState;
use crate::inbound_auth::InboundAuth;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct FetchSmartRequest {
    pub url: String,
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
    auth: InboundAuth,
    Json(req): Json<FetchSmartRequest>,
) -> (StatusCode, Json<FetchSmartResponse>) {
    let start = Instant::now();
    let save = req.save_to_file.unwrap_or(false);
    let url = req.url.clone();

    // `None` → the configured endpoint default (`fetch.smart_timeout_secs`
    // → `EndpointDefaults::smart_timeout_secs`); a caller-supplied
    // `timeout` wins (issue #156). The outer deadline layer bounds the same
    // call — this is the first route that is BOTH layer-guarded and
    // internally bounded: for an explicit `timeout` the layer arms first
    // with the identical clamped duration, so the outer bound wins that
    // race and answers the generic 504 shape; the inner typed arm below is
    // reachable on the no-timeout path (inner 30s < outer 130s), which is
    // exactly the case this bound exists for. `OUTBOUND_INFLIGHT` counts
    // both bounds while the inner future runs — cosmetic.
    let deadline = resolve_timeout(req.timeout.or(Some(state.defaults.smart_timeout_secs)));
    // Middleware chain handles CF detect + solve + retry automatically.
    // ox-browser#177 / SEC-CR-018: `client_for` is the one stamp site — it
    // carries the gate's `ok_secret` decision (see `fetch`).
    let http = state.client_for(auth);
    match bounded(deadline, http.get(&req.url)).await {
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
    use ox_http::{CookieCache, HttpClient, HttpConfig};
    use std::sync::Arc;
    use std::time::Duration;

    /// Minimal AppState for handler-level tests (mirrors fetch.rs tests).
    fn test_state() -> AppState {
        AppState::new(
            Arc::new(crate::tests::MockProvider),
            Arc::new(CookieCache::new(Duration::from_secs(300))),
            Arc::new(HttpClient::new(HttpConfig::default()).unwrap()),
            EndpointDefaults::default(),
            ox_media::MediaConfig::default(),
            Arc::new(GoBrowserProxy::new("http://127.0.0.1:8906".to_string(), "")),
        )
    }

    /// #156: `fetch.smart_timeout_secs` is the real /fetch-smart default —
    /// a hanging upstream must trip at the configured bound (1 s), not
    /// sail to the outer layer's 130 s bound. Deleting the
    /// `.or(Some(state.defaults.smart_timeout_secs))` arm makes the
    /// error report `(8s` — or never fire — and this test fails.
    #[tokio::test]
    async fn fetch_smart_uses_configured_default_timeout() {
        struct HangingHandler;
        #[async_trait]
        impl ox_http::Handler for HangingHandler {
            async fn handle(
                &self,
                req: ox_http::Request,
            ) -> ox_http::Result<ox_http::HttpResponse> {
                let _ = req;
                std::future::pending::<()>().await;
                unreachable!()
            }
        }

        let mut state = test_state();
        state.http_client = Arc::new(HttpClient::with_chain(
            Arc::new(HangingHandler),
            HttpConfig::default(),
        ));
        state.defaults.smart_timeout_secs = 1;
        let req = FetchSmartRequest {
            url: "http://1.1.1.1".into(),
            timeout: None,
            save_to_file: None,
        };
        let (status, json) =
            fetch_smart(State(state), InboundAuth::from_marker(None), Json(req)).await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            json.error.as_deref(),
            Some("deadline exceeded (1s per-call bound)"),
            "configured default bound, not the 8s seam default"
        );
    }

    #[test]
    fn fetch_smart_request_defaults() {
        let json = r#"{"url": "https://example.com"}"#;
        let req: FetchSmartRequest = serde_json::from_str(json).unwrap();
        assert!(req.timeout.is_none());
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
