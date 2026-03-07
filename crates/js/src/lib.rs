//! HTTP API server exposing CF solver via POST /solve for go-stealth.

mod analyze;
pub mod analyze_types;
mod fetch;
mod fetch_smart;
mod image_search;
mod security;

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use ox_http::{ChallengeType, CookieCache, CookieProvider, HttpClient};
use serde::{Deserialize, Serialize};
use url::Url;

/// Shared application state for all HTTP endpoints.
#[derive(Clone)]
pub struct AppState {
    pub provider: Arc<dyn CookieProvider>,
    pub cache: Arc<CookieCache>,
    pub http_client: Arc<HttpClient>,
}

/// Incoming solve request body.
#[derive(Deserialize)]
pub struct SolveRequest {
    pub url: String,
    #[serde(default = "default_challenge_type")]
    pub challenge_type: String,
}

fn default_challenge_type() -> String {
    "js_challenge".into()
}

/// Response returned by the /solve endpoint.
#[derive(Serialize, Deserialize)]
pub struct SolveResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookies: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Builds the Axum router with /health, /solve, /fetch and /fetch-smart.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/solve", post(solve))
        .route("/fetch", post(fetch::fetch))
        .route("/fetch-smart", post(fetch_smart::fetch_smart))
        .route("/analyze", post(analyze::analyze))
        .route("/security", post(security::security_scan))
        .route("/images/search", post(image_search::image_search))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn solve(
    State(state): State<AppState>,
    Json(req): Json<SolveRequest>,
) -> (StatusCode, Json<SolveResponse>) {
    let challenge_type = match req.challenge_type.as_str() {
        "js_challenge" => ChallengeType::JsChallenge,
        "managed_challenge" | "turnstile" => ChallengeType::Turnstile,
        "managed_challenge_200" => ChallengeType::ManagedChallenge,
        "block" => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SolveResponse {
                    status: "error".into(),
                    cookies: None,
                    user_agent: None,
                    error: Some("block challenges are not solvable".into()),
                }),
            );
        }
        _ => ChallengeType::JsChallenge,
    };

    let domain = match Url::parse(&req.url) {
        Ok(u) => u.host_str().unwrap_or("unknown").to_owned(),
        Err(_) => "unknown".to_owned(),
    };

    if let Some(cached) = state.cache.get(&domain) {
        tracing::debug!(domain, "cache hit");
        return (
            StatusCode::OK,
            Json(SolveResponse {
                status: "ok".into(),
                cookies: Some(cached.cookies),
                user_agent: Some(cached.user_agent),
                error: None,
            }),
        );
    }

    match state.provider.solve(&req.url, challenge_type).await {
        Ok(solved) => {
            state.cache.put(&domain, solved.clone());
            tracing::info!(domain, "challenge solved");
            (
                StatusCode::OK,
                Json(SolveResponse {
                    status: "ok".into(),
                    cookies: Some(solved.cookies),
                    user_agent: Some(solved.user_agent),
                    error: None,
                }),
            )
        }
        Err(e) => {
            tracing::warn!(domain, error = %e, "solve failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(SolveResponse {
                    status: "error".into(),
                    cookies: None,
                    user_agent: None,
                    error: Some(e),
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use ox_http::{HttpConfig, SolvedChallenge};
    use std::time::Duration;
    use tower::ServiceExt;

    struct MockProvider;

    #[async_trait]
    impl CookieProvider for MockProvider {
        async fn solve(
            &self,
            _url: &str,
            _ct: ChallengeType,
        ) -> Result<SolvedChallenge, String> {
            let mut cookies = HashMap::new();
            cookies.insert("cf_clearance".into(), "test-token".into());
            Ok(SolvedChallenge {
                cookies,
                user_agent: "TestUA/1.0".into(),
            })
        }
    }

    fn test_state() -> AppState {
        AppState {
            provider: Arc::new(MockProvider),
            cache: Arc::new(CookieCache::new(Duration::from_secs(300))),
            http_client: Arc::new(
                HttpClient::new(HttpConfig::default()).unwrap(),
            ),
        }
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let app = router(test_state());
        let req = axum::http::Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn solve_returns_cookies() {
        let app = router(test_state());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/solve")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "url": "https://example.com/page",
                    "challenge_type": "js_challenge"
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: SolveResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.status, "ok");
        let cookies = parsed.cookies.unwrap();
        assert_eq!(cookies.get("cf_clearance").unwrap(), "test-token");
    }

    #[tokio::test]
    async fn solve_block_rejected() {
        let app = router(test_state());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/solve")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "url": "https://example.com",
                    "challenge_type": "block"
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: SolveResponse = serde_json::from_slice(&body).unwrap();
        assert!(parsed.error.unwrap().contains("not solvable"));
    }

    #[tokio::test]
    async fn solve_caches_result() {
        let state = test_state();
        let app = router(state.clone());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/solve")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "url": "https://cached.example.com/test"
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(state.cache.get("cached.example.com").is_some());
    }
}
