//! POST /fetch — fast wreq+BoringSSL fetch without headless browser.

use std::collections::HashMap;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_http::detect_cloudflare;
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct FetchRequest {
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_timeout() -> u64 {
    15
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

    match state.http_client.get(&req.url).await {
        Ok(resp) => {
            let cf = detect_cloudflare(&resp);
            let cf_detected = cf.is_some();
            let cf_type = cf.map(|c| c.challenge_type.to_string());

            let headers: HashMap<String, String> = resp
                .headers
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str().ok().map(|val| (k.to_string(), val.to_owned()))
                })
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
        Err(e) => (
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_request_defaults() {
        let json = r#"{"url": "https://example.com"}"#;
        let req: FetchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.url, "https://example.com");
        assert_eq!(req.timeout, 15);
        assert!(req.headers.is_empty());
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
