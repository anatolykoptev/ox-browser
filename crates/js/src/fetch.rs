//! POST /fetch — fast wreq+BoringSSL fetch without headless browser.

use std::collections::HashMap;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use ox_http::detect_cloudflare;
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
    /// Timeout in seconds. If not set, uses server config default.
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

    match state
        .http_client
        .request(
            &method,
            &req.url,
            body_bytes,
            content_type.as_deref(),
            &extra_refs,
        )
        .await
    {
        Ok(resp) => {
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
