//! Cloudflare detection middleware.
//!
//! Port of go-stealth's `CloudflareDetectMiddleware`. Inspects responses
//! for Cloudflare challenge markers and converts them to errors.

use std::sync::Arc;

use async_trait::async_trait;

use crate::cloudflare::detect_cloudflare;
use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::{HttpResponse, Result};

/// Returns a middleware that detects Cloudflare challenges in responses.
///
/// When a challenge is detected, the response is converted to
/// [`HttpError::Cloudflare`]. This integrates with retry middleware:
/// place cloudflare detection *inside* retry so retries happen
/// automatically with a different proxy.
///
/// Chain order: `retry -> cloudflare_detect -> client_hints -> reqwest`
pub fn cloudflare_detect_middleware() -> MiddlewareFn {
    Arc::new(|next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(CloudflareDetectHandler { next })
    })
}

struct CloudflareDetectHandler {
    next: Arc<dyn Handler>,
}

#[async_trait]
impl Handler for CloudflareDetectHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let resp = self.next.handle(req).await?;
        if let Some(cf) = detect_cloudflare(&resp) {
            return Err(HttpError::Cloudflare(
                cf.challenge_type,
                cf.status,
                cf.ray_id,
            ));
        }
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare::ChallengeType;
    use crate::middleware::chain;
    use reqwest::header::HeaderMap;

    struct MockHandler {
        status: u16,
        body: String,
        server: String,
    }

    #[async_trait]
    impl Handler for MockHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            let mut headers = HeaderMap::new();
            headers.insert("server", self.server.parse().unwrap());
            Ok(HttpResponse {
                status: self.status,
                url: req.url,
                headers,
                body: self.body.clone(),
            })
        }
    }

    #[tokio::test]
    async fn returns_error_on_js_challenge() {
        let base: Arc<dyn Handler> = Arc::new(MockHandler {
            status: 503,
            body: "<script src=\"/cdn-cgi/challenge-platform/x.js\"></script>".into(),
            server: "cloudflare".into(),
        });
        let handler = chain(vec![cloudflare_detect_middleware()], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
        };
        let err = handler.handle(req).await.unwrap_err();
        match err {
            HttpError::Cloudflare(ct, status, _) => {
                assert_eq!(ct, ChallengeType::JsChallenge);
                assert_eq!(status, 503);
            }
            other => panic!("expected Cloudflare error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn passes_through_normal() {
        let base: Arc<dyn Handler> = Arc::new(MockHandler {
            status: 200,
            body: "ok".into(),
            server: "nginx".into(),
        });
        let handler = chain(vec![cloudflare_detect_middleware()], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
        };
        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn passes_through_non_cf_503() {
        let base: Arc<dyn Handler> = Arc::new(MockHandler {
            status: 503,
            body: "down".into(),
            server: "nginx".into(),
        });
        let handler = chain(vec![cloudflare_detect_middleware()], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
        };
        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 503);
    }
}
