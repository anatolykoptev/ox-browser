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
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_timeout() -> u64 {
    30
}

#[derive(Serialize)]
pub struct FetchSmartResponse {
    pub status: u16,
    pub body: String,
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
                Json(FetchSmartResponse {
                    status: 0,
                    body: String::new(),
                    method: "direct".into(),
                    cf_detected: false,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: Some(e.to_string()),
                }),
            );
        }
    };

    let cf = detect_cloudflare(&resp);
    if cf.is_none() {
        return (
            StatusCode::OK,
            Json(FetchSmartResponse {
                status: resp.status,
                body: resp.body,
                method: "direct".into(),
                cf_detected: false,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: None,
            }),
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
            Json(FetchSmartResponse {
                status: resp.status,
                body: resp.body,
                method: "direct".into(),
                cf_detected: true,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some("CF block — not solvable".into()),
            }),
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
                    Json(FetchSmartResponse {
                        status: retry_resp.status,
                        body: retry_resp.body,
                        method: "solved".into(),
                        cf_detected: true,
                        elapsed_ms: start.elapsed().as_millis() as u64,
                        error: None,
                    }),
                ),
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    Json(FetchSmartResponse {
                        status: 0,
                        body: String::new(),
                        method: "solved".into(),
                        cf_detected: true,
                        elapsed_ms: start.elapsed().as_millis() as u64,
                        error: Some(format!("retry after solve failed: {e}")),
                    }),
                ),
            }
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(FetchSmartResponse {
                status: resp.status,
                body: resp.body,
                method: "direct".into(),
                cf_detected: true,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some(format!("solve failed: {e}")),
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_smart_request_defaults() {
        let json = r#"{"url": "https://example.com"}"#;
        let req: FetchSmartRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.timeout, 30);
    }

    #[test]
    fn fetch_smart_response_serializes() {
        let resp = FetchSmartResponse {
            status: 200,
            body: "ok".into(),
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 100,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["method"], "direct");
        assert!(!json.as_object().unwrap().contains_key("error"));
    }
}
