//! POST /fetch-smart — two-stage fetch: wreq first, headless fallback on CF.

use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_http::{detect_cloudflare, ChallengeType};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::AppState;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct FetchSmartRequest {
    pub url: String,
    /// Timeout in seconds. If not set, uses server config default.
    pub timeout: Option<u64>,
    /// Save response body to file and return path instead of inline body.
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
    /// "direct" or "solved"
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
    let domain = Url::parse(&req.url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default();

    // Stage 1: Fast wreq fetch.
    let resp = match state.http_client.get(&req.url).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(make_response(0, String::new(), "direct", false, start, save, &url, Some(e.to_string()))),
            );
        }
    };

    let cf = detect_cloudflare(&resp);
    if cf.is_none() {
        return (
            StatusCode::OK,
            Json(make_response(resp.status, resp.body, "direct", false, start, save, &url, None)),
        );
    }

    let challenge = cf.unwrap();
    tracing::info!(
        domain = %domain,
        challenge = %challenge.challenge_type,
        "CF detected, attempting headless solve"
    );

    // Block challenges are not solvable.
    if challenge.challenge_type == ChallengeType::Block {
        return (
            StatusCode::OK,
            Json(make_response(resp.status, resp.body, "direct", true, start, save, &url, Some("CF block — not solvable".into()))),
        );
    }

    // Stage 2: Headless solve -> get cookies -> retry.
    match state.provider.solve(&req.url, challenge.challenge_type).await {
        Ok(solved) => {
            state.cache.put(&domain, solved);
            tracing::info!(domain = %domain, "CF solved, retrying with cookies");

            match state.http_client.get(&req.url).await {
                Ok(retry_resp) => (
                    StatusCode::OK,
                    Json(make_response(retry_resp.status, retry_resp.body, "solved", true, start, save, &url, None)),
                ),
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    Json(make_response(0, String::new(), "solved", true, start, save, &url, Some(format!("retry after solve failed: {e}")))),
                ),
            }
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(make_response(resp.status, resp.body, "direct", true, start, save, &url, Some(format!("solve failed: {e}")))),
        ),
    }
}

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
                tracing::warn!(error = %e, "failed to save response, returning inline");
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
        assert!(!json.as_object().unwrap().contains_key("file_path"));
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
