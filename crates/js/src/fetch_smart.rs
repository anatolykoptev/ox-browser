//! POST /fetch-smart — DEPRECATED: Use POST /read instead.
//!
//! Kept for backward compatibility. Middleware chain handles CF automatically.

use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::AppState;

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
    Json(req): Json<FetchSmartRequest>,
) -> (StatusCode, Json<FetchSmartResponse>) {
    let start = Instant::now();
    let save = req.save_to_file.unwrap_or(false);
    let url = req.url.clone();

    // Middleware chain handles CF detect + solve + retry automatically
    match state.http_client.get(&req.url).await {
        Ok(resp) => (
            StatusCode::OK,
            Json(make_response(resp.status, resp.body, "auto", false, start, save, &url, None)),
        ),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(make_response(0, String::new(), "auto", false, start, save, &url, Some(e.to_string()))),
        ),
    }
}

fn make_response(
    status: u16, body: String, method: &str, cf: bool,
    start: Instant, save: bool, url: &str, error: Option<String>,
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
        status, body: body_field, file_path, method: method.into(),
        cf_detected: cf, elapsed_ms: start.elapsed().as_millis() as u64, error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_smart_request_defaults() {
        let json = r#"{"url": "https://example.com"}"#;
        let req: FetchSmartRequest = serde_json::from_str(json).unwrap();
        assert!(req.timeout.is_none());
    }

    #[test]
    fn fetch_smart_response_serializes_inline() {
        let resp = FetchSmartResponse {
            status: 200, body: Some("ok".into()), file_path: None,
            method: "direct".into(), cf_detected: false, elapsed_ms: 100, error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["method"], "direct");
        assert_eq!(json["body"], "ok");
        assert!(!json.as_object().unwrap().contains_key("error"));
    }

    #[test]
    fn fetch_smart_response_serializes_file() {
        let resp = FetchSmartResponse {
            status: 200, body: None,
            file_path: Some("/tmp/ox-browser/example.com_abc.html".into()),
            method: "direct".into(), cf_detected: false, elapsed_ms: 100, error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("body").is_none());
        assert_eq!(json["file_path"], "/tmp/ox-browser/example.com_abc.html");
    }
}
