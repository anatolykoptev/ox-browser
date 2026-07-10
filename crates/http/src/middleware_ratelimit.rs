//! Rate-limit middleware that integrates [`DomainLimiter`] into the
//! middleware chain.
//!
//! Port of go-stealth's `RateLimitMiddleware`. Waits for permission before
//! each request and automatically marks domains as rate-limited on 429
//! responses with a `Retry-After` header.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;

use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::ratelimit_domain::DomainLimiter;
use crate::retry_parse::parse_retry_after;
use crate::{HttpResponse, Result};

/// Returns a middleware that enforces per-domain rate limits.
///
/// Before each request, calls `limiter.wait(url)` to block until the
/// request is permitted. After receiving a 429, parses `Retry-After`
/// and marks the domain as blocked for the specified duration.
pub fn rate_limit_middleware(limiter: Arc<DomainLimiter>) -> MiddlewareFn {
    Arc::new(move |next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(RateLimitHandler {
            limiter: limiter.clone(),
            next,
        })
    })
}

struct RateLimitHandler {
    limiter: Arc<DomainLimiter>,
    next: Arc<dyn Handler>,
}

#[async_trait]
impl Handler for RateLimitHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        // Wait until rate limit allows this request.
        self.limiter.wait(&req.url).await;

        let resp = self.next.handle(req.clone()).await?;

        // On 429, parse Retry-After and mark the domain blocked.
        if resp.status == 429
            && let Some(ra) = resp.headers.get("retry-after")
            && let Some(dur) = parse_retry_after(ra.to_str().unwrap_or(""))
        {
            self.limiter
                .mark_rate_limited(&req.url, Instant::now() + dur);
        }

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::chain;
    use wreq::header::{HeaderMap, HeaderValue};

    struct FixedHandler {
        status: u16,
        headers: HeaderMap,
    }

    #[async_trait]
    impl Handler for FixedHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            Ok(HttpResponse {
                status: self.status,
                url: req.url,
                headers: self.headers.clone(),
                body: String::new(),
            })
        }
    }

    fn test_limiter() -> Arc<DomainLimiter> {
        use crate::ratelimit_domain::DomainConfig;
        use std::time::Duration;
        Arc::new(DomainLimiter::new(vec![DomainConfig {
            domain: String::new(), // catch-all
            requests_per_window: 100,
            window_duration: Duration::from_secs(60),
            min_delay: Duration::ZERO,
            random_delay: Duration::ZERO,
        }]))
    }

    fn test_req() -> Request {
        Request {
            method: "GET".into(),
            url: "https://example.com/page".into(),
            headers: vec![],
            body: None,
            proxy: None,
        }
    }

    #[tokio::test]
    async fn passes_through_on_200() {
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 200,
            headers: HeaderMap::new(),
        });
        let handler = chain(vec![rate_limit_middleware(test_limiter())], base);
        let resp = handler.handle(test_req()).await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn marks_rate_limited_on_429() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("60"));
        let limiter = test_limiter();
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 429,
            headers,
        });
        let handler = chain(vec![rate_limit_middleware(limiter.clone())], base);

        // First request goes through (returns 429, marks domain).
        let resp = handler.handle(test_req()).await.unwrap();
        assert_eq!(resp.status, 429);

        // The domain should now be marked as blocked in the limiter.
        assert!(!limiter.allow("https://example.com/other"));
    }
}
