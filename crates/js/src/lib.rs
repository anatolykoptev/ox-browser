//! HTTP API server exposing CF solver via POST /solve for go-stealth.

mod analyze;
pub mod analyze_types;
mod crawl;
mod fetch;
mod fetch_smart;
mod image_search;
mod media_download;
mod read;
mod readability;
mod reverse_search;
mod security;
mod site_audit;
pub mod site_twitter;
mod solve;
mod twitter_login;

pub use solve::SolveResponse;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use ox_http::read_pipeline::SiteHandler;
use ox_http::{CookieCache, CookieProvider, HttpClient};
use tokio::sync::Semaphore;

/// Runtime defaults configurable via config.toml.
#[derive(Clone, Debug)]
pub struct EndpointDefaults {
    pub fetch_timeout_secs: u64,
    pub smart_timeout_secs: u64,
    pub image_max_results: usize,
    pub image_min_width: u32,
    pub reverse_max_results: usize,
}

impl Default for EndpointDefaults {
    fn default() -> Self {
        Self {
            fetch_timeout_secs: 15,
            smart_timeout_secs: 30,
            image_max_results: 10,
            image_min_width: 400,
            reverse_max_results: 20,
        }
    }
}

/// Shared application state for all HTTP endpoints.
#[derive(Clone)]
pub struct AppState {
    pub provider: Arc<dyn CookieProvider>,
    pub cache: Arc<CookieCache>,
    pub http_client: Arc<HttpClient>,
    pub defaults: EndpointDefaults,
    pub media_config: ox_media::MediaConfig,
    /// Injected site-specific handlers for the read pipeline.
    pub site_handlers: Arc<Vec<SiteHandler>>,
    pub twitter_config: ox_twitter::login::TwitterLoginConfig,
    pub twitter_semaphore: Arc<Semaphore>,
}

impl AppState {
    /// Build AppState with the default set of site handlers (including Twitter).
    pub fn new(
        provider: Arc<dyn CookieProvider>,
        cache: Arc<CookieCache>,
        http_client: Arc<HttpClient>,
        defaults: EndpointDefaults,
        media_config: ox_media::MediaConfig,
        twitter_config: ox_twitter::login::TwitterLoginConfig,
    ) -> Self {
        let twitter_semaphore = Arc::new(Semaphore::new(twitter_config.max_concurrent));
        let handlers: Vec<SiteHandler> = vec![site_twitter::make_twitter_handler()];
        Self {
            provider,
            cache,
            http_client,
            defaults,
            media_config,
            site_handlers: Arc::new(handlers),
            twitter_config,
            twitter_semaphore,
        }
    }
}

/// Builds the Axum router with all REST endpoints.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/solve", post(solve::solve))
        .route("/fetch", post(fetch::fetch))
        .route("/fetch-smart", post(fetch_smart::fetch_smart))
        .route("/analyze", post(analyze::analyze))
        .route("/security", post(security::security_scan))
        .route("/images/search", post(image_search::image_search))
        .route("/images/reverse", post(reverse_search::reverse_search))
        .route("/media/download", post(media_download::media_download))
        .route("/readability", post(readability::readability))
        .route("/crawl", post(crawl::crawl))
        .route("/site-audit", post(site_audit::site_audit))
        .route("/read", post(read::read))
        .route("/twitter/login", post(twitter_login::twitter_login))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use ox_http::{ChallengeType, HttpConfig, SolvedChallenge};
    use std::collections::HashMap;
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
                body: None,
            })
        }
    }

    fn test_state() -> AppState {
        AppState::new(
            Arc::new(MockProvider),
            Arc::new(CookieCache::new(Duration::from_secs(300))),
            Arc::new(HttpClient::new(HttpConfig::default()).unwrap()),
            EndpointDefaults::default(),
            ox_media::MediaConfig::default(),
            ox_twitter::login::TwitterLoginConfig::default(),
        )
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
