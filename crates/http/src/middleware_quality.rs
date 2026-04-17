//! Quality-check middleware: converts anti-bot pages and fallback-worthy
//! HTTP errors into CF challenge errors, so the solver middleware can handle them.
//!
//! This replaces the `headless_read` fallback in `read_pipeline.rs` by
//! moving the detection logic into the middleware chain.

use std::sync::Arc;

use async_trait::async_trait;

use crate::cloudflare::ChallengeType;
use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::{HttpResponse, Result};

/// Returns a middleware that detects anti-bot stub pages and converts them
/// to CF challenge errors for the solver middleware to handle.
///
/// Position in chain: between cloudflare_detect and client_hints (innermost).
/// The solver middleware sits above and will catch the CF error.
pub fn quality_check_middleware() -> MiddlewareFn {
    Arc::new(move |next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(QualityCheckHandler { next })
    })
}

struct QualityCheckHandler {
    next: Arc<dyn Handler>,
}

/// HTTP status codes that indicate an anti-bot block (not CF-specific).
fn should_fallback(status: u16) -> bool {
    matches!(status, 401 | 403 | 429 | 503)
}

#[async_trait]
impl Handler for QualityCheckHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let resp = self.next.handle(req).await?;

        // Non-200 fallback-worthy status → trigger solver
        if should_fallback(resp.status) {
            tracing::info!(
                url = %resp.url,
                status = resp.status,
                "quality: fallback-worthy status, triggering solver"
            );
            return Err(HttpError::Cloudflare(
                ChallengeType::JsChallenge,
                resp.status,
                String::new(),
            ));
        }

        // 200 but low-quality content → likely anti-bot stub page.
        // Quick heuristic: large body (>5KB) with very little visible text.
        // Skip for JSON responses — they have no HTML tags by design.
        let first_non_ws = resp
            .body
            .as_bytes()
            .iter()
            .find(|b| !b.is_ascii_whitespace());
        let is_json = matches!(first_non_ws, Some(b'{') | Some(b'['));
        if resp.status == 200 && resp.body.len() > 5_000 && !is_json {
            let visible: usize = resp
                .body
                .split('<')
                .filter_map(|s| s.split_once('>').map(|(_, after)| after))
                .map(|text| text.chars().filter(|c| !c.is_whitespace()).count())
                .sum();
            if visible < 100 {
                tracing::info!(
                    url = %resp.url,
                    body_len = resp.body.len(),
                    visible_chars = visible,
                    "quality: low-quality 200, triggering solver"
                );
                return Err(HttpError::Cloudflare(
                    ChallengeType::JsChallenge,
                    200,
                    String::new(),
                ));
            }
        }

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::chain;
    use wreq::header::HeaderMap;

    struct FixedHandler {
        status: u16,
        body: String,
    }

    #[async_trait]
    impl Handler for FixedHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            Ok(HttpResponse {
                status: self.status,
                url: req.url,
                headers: HeaderMap::new(),
                body: self.body.clone(),
            })
        }
    }

    fn test_req() -> Request {
        Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
            proxy: None,
        }
    }

    #[tokio::test]
    async fn passes_through_200_with_good_content() {
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 200,
            body: "Hello world with good content".into(),
        });
        let handler = chain(vec![quality_check_middleware()], base);
        let resp = handler.handle(test_req()).await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn converts_403_to_cf_error() {
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 403,
            body: "Forbidden".into(),
        });
        let handler = chain(vec![quality_check_middleware()], base);
        let err = handler.handle(test_req()).await.unwrap_err();
        assert!(matches!(
            err,
            HttpError::Cloudflare(ChallengeType::JsChallenge, 403, _)
        ));
    }

    #[tokio::test]
    async fn converts_503_to_cf_error() {
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 503,
            body: "Service Unavailable".into(),
        });
        let handler = chain(vec![quality_check_middleware()], base);
        let err = handler.handle(test_req()).await.unwrap_err();
        assert!(matches!(
            err,
            HttpError::Cloudflare(ChallengeType::JsChallenge, 503, _)
        ));
    }

    #[tokio::test]
    async fn passes_through_404() {
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 404,
            body: "Not Found".into(),
        });
        let handler = chain(vec![quality_check_middleware()], base);
        let resp = handler.handle(test_req()).await.unwrap();
        assert_eq!(resp.status, 404);
    }

    #[tokio::test]
    async fn converts_large_empty_html_to_cf_error() {
        // Simulate anti-bot stub page: large HTML with no visible text nodes.
        // Pad with attribute noise (no actual text nodes outside tags).
        let attrs = format!(" data-x='{}'", "a".repeat(100));
        let divs: String = (0..60).map(|_| format!("<div{}></div>", attrs)).collect();
        let body = format!(
            "<html><head><meta charset='utf-8'/></head><body>{}</body></html>",
            divs
        );
        assert!(body.len() > 5_000);
        let base: Arc<dyn Handler> = Arc::new(FixedHandler { status: 200, body });
        let handler = chain(vec![quality_check_middleware()], base);
        let err = handler.handle(test_req()).await.unwrap_err();
        assert!(matches!(
            err,
            HttpError::Cloudflare(ChallengeType::JsChallenge, 200, _)
        ));
    }

    #[tokio::test]
    async fn passes_large_html_with_real_content() {
        // Large HTML but with real visible text
        let body = format!(
            "<html><body><p>{}</p></body></html>",
            "This is real content with lots of words. ".repeat(50)
        );
        let base: Arc<dyn Handler> = Arc::new(FixedHandler { status: 200, body });
        let handler = chain(vec![quality_check_middleware()], base);
        let resp = handler.handle(test_req()).await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn passes_large_json_response() {
        // Large JSON (e.g. Reddit API) should not trigger quality check
        let body = format!(
            r#"{{"data":{{"children":[{}]}}}}"#,
            (0..200)
                .map(|i| format!(
                    r#"{{"data":{{"title":"post{i}","body":"{}"}}}}"#,
                    "x".repeat(30)
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(body.len() > 5_000);
        let base: Arc<dyn Handler> = Arc::new(FixedHandler { status: 200, body });
        let handler = chain(vec![quality_check_middleware()], base);
        let resp = handler.handle(test_req()).await.unwrap();
        assert_eq!(resp.status, 200);
    }
}
