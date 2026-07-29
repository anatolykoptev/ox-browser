//! Quality-check middleware: converts anti-bot pages and fallback-worthy
//! HTTP errors into CF challenge errors, so the solver middleware can handle them.
//!
//! This replaces the `headless_read` fallback in `read_pipeline.rs` by
//! moving the detection logic into the middleware chain.

use std::sync::Arc;

use async_trait::async_trait;

use crate::cloudflare::detect_cloudflare;
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

        // If this is a GENUINE Cloudflare challenge (real CF markers + ray
        // id), raise `HttpError::Cloudflare` directly — a genuine challenge
        // where CF intercepted the request and the origin never saw it. The
        // re-senders (solver, residential) treat genuine CF as safe to retry
        // on any method.
        //
        // Both provenance decisions live here rather than delegating the
        // genuine case to the outer `cloudflare_detect` middleware: that
        // middleware is only attached when `config.cloudflare_detect` is
        // true (`client.rs:142`), and `HttpConfig::default()` has it false
        // with `quality_check: true` (`config.rs:86,92`). The Browser
        // (`crates/core/src/browser.rs:16-26`) and the CLI client builder
        // (`src/cli.rs:83-87`) both inherit that pair via
        // `..HttpConfig::default()`. Delegating to a middleware they may not
        // have wired let a genuine CF challenge surface as `Ok(503,
        // challenge-body)` — the caller printed the challenge HTML as if it
        // were the page, and the solver never fired because no `Cloudflare`
        // error was raised. Raising the error here removes that dependency.
        //
        // When `cloudflare_detect` IS attached, it sits outer to this
        // middleware and does `self.next.handle(req).await?` — the `?`
        // propagates this `Err` untouched, so the solver sees the same
        // `Err(Cloudflare)` it saw when `cloudflare_detect` did the
        // conversion. No double-classification, no swallowing.
        //
        // Only responses WITHOUT CF markers are converted to
        // `CloudflareInferred` below — those are bare status codes where the
        // origin MAY have processed the request.
        if let Some(cf) = detect_cloudflare(&resp) {
            tracing::info!(
                url = %resp.url,
                status = resp.status,
                challenge = %cf.challenge_type,
                "quality: genuine CF challenge, raising Cloudflare error"
            );
            return Err(HttpError::Cloudflare(
                cf.challenge_type,
                resp.status,
                cf.ray_id,
            ));
        }

        // Non-200 fallback-worthy status → inferred challenge. The origin
        // MAY have processed the request — carry the response so a gate that
        // declines to re-send a non-idempotent method can return it intact.
        if should_fallback(resp.status) {
            tracing::info!(
                url = %resp.url,
                status = resp.status,
                "quality: fallback-worthy status (inferred), triggering solver"
            );
            return Err(HttpError::CloudflareInferred(resp.status, Box::new(resp)));
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
                    "quality: low-quality 200 (inferred), triggering solver"
                );
                return Err(HttpError::CloudflareInferred(200, Box::new(resp)));
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
    async fn converts_403_to_inferred_error() {
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 403,
            body: "Forbidden".into(),
        });
        let handler = chain(vec![quality_check_middleware()], base);
        let err = handler.handle(test_req()).await.unwrap_err();
        assert!(matches!(err, HttpError::CloudflareInferred(403, _)));
    }

    #[tokio::test]
    async fn converts_503_to_inferred_error() {
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 503,
            body: "Service Unavailable".into(),
        });
        let handler = chain(vec![quality_check_middleware()], base);
        let err = handler.handle(test_req()).await.unwrap_err();
        assert!(matches!(err, HttpError::CloudflareInferred(503, _)));
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

    /// A genuine CF 503 (with CF markers) is converted to `Err(Cloudflare)`
    /// — NOT `CloudflareInferred` — so the re-senders treat it as safe to
    /// retry on any method. This is the provenance seam: CF-marker responses
    /// are genuine, not inferred.
    ///
    /// Both provenance decisions live in `quality_check` rather than
    /// delegating the genuine case to the outer `cloudflare_detect`
    /// middleware, which is only attached when `config.cloudflare_detect` is
    /// true. See the handler comment for the full rationale.
    #[tokio::test]
    async fn genuine_cf_503_raises_cloudflare_error() {
        struct CfHandler;
        #[async_trait]
        impl Handler for CfHandler {
            async fn handle(&self, req: Request) -> Result<HttpResponse> {
                let mut headers = wreq::header::HeaderMap::new();
                headers.insert("server", "cloudflare".parse().unwrap());
                headers.insert("cf-ray", "abc123-SJC".parse().unwrap());
                Ok(HttpResponse {
                    status: 503,
                    url: req.url,
                    headers,
                    body: r#"<script src="/cdn-cgi/challenge-platform/x.js"></script>"#.into(),
                })
            }
        }
        let base: Arc<dyn Handler> = Arc::new(CfHandler);
        let handler = chain(vec![quality_check_middleware()], base);
        let err = handler.handle(test_req()).await.unwrap_err();
        match err {
            HttpError::Cloudflare(_, 503, ray) => {
                assert_eq!(ray, "abc123-SJC");
            }
            HttpError::CloudflareInferred(_, _) => {
                panic!("genuine CF must raise Cloudflare, not CloudflareInferred");
            }
            other => panic!("expected Cloudflare error, got {other:?}"),
        }
    }

    /// F-A: a genuine CF response must reach the caller as an error when the
    /// client is built with `quality_check: true` and `cloudflare_detect:
    /// false` — the default-config pair inherited by the Browser
    /// (`crates/core/src/browser.rs:16-26`) and the CLI client builder
    /// (`src/cli.rs:83-87`). Before the fix, `quality_check` short-circuited
    /// on `Ok(resp)` relying on `cloudflare_detect` to convert it, but that
    /// middleware was not wired — the caller got `Ok(503, challenge-body)`
    /// and printed the challenge HTML as if it were the page. The solver
    /// never fired either, because no `Cloudflare` error was raised.
    ///
    /// Uses `HttpClient::with_chain` so the config→middleware-chain wiring
    /// (the same `build_middlewares` path as `HttpClient::new`) is exercised,
    /// not just the middleware in isolation.
    ///
    /// **Mutation probe**: restore the `return Ok(resp)` short-circuit in
    /// `QualityCheckHandler::handle` and this test fails — the client
    /// returns `Ok(503)` instead of `Err(Cloudflare)`.
    #[tokio::test]
    async fn genuine_cf_reaches_caller_as_error_without_cloudflare_detect() {
        use crate::HttpClient;
        use crate::HttpConfig;

        struct CfHandler;
        #[async_trait]
        impl Handler for CfHandler {
            async fn handle(&self, req: Request) -> Result<HttpResponse> {
                let mut headers = wreq::header::HeaderMap::new();
                headers.insert("server", "cloudflare".parse().unwrap());
                headers.insert("cf-ray", "abc-LAX".parse().unwrap());
                Ok(HttpResponse {
                    status: 503,
                    url: req.url,
                    headers,
                    body: r#"<script src="/cdn-cgi/challenge-platform/x.js"></script>"#.into(),
                })
            }
        }

        // The default-config pair: quality_check on, cloudflare_detect off.
        let config = HttpConfig {
            cloudflare_detect: false,
            quality_check: true,
            ..HttpConfig::default()
        };
        let client = HttpClient::with_chain(Arc::new(CfHandler), config);

        let err = client
            .request("GET", "https://example.com", None, None, &[])
            .await
            .unwrap_err();
        assert!(
            matches!(err, HttpError::Cloudflare(_, 503, _)),
            "genuine CF must reach caller as Err(Cloudflare), got {err:?}"
        );
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
        assert!(matches!(err, HttpError::CloudflareInferred(200, _)));
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
