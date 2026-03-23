//! Logging middleware that records request method, URL, status, and latency.
//!
//! Port of go-stealth's `LoggingMiddleware`.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;

use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::{HttpResponse, Result};

/// Returns a middleware that logs every request/response via `tracing::debug`.
///
/// On success: logs method, url, status code, and latency.
/// On error: logs method, url, error message, and latency.
pub fn logging_middleware() -> MiddlewareFn {
    Arc::new(|next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(LoggingHandler { next })
    })
}

struct LoggingHandler {
    next: Arc<dyn Handler>,
}

#[async_trait]
impl Handler for LoggingHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let method = req.method.clone();
        let url = req.url.clone();
        let start = Instant::now();

        match self.next.handle(req).await {
            Ok(resp) => {
                let latency = start.elapsed();
                tracing::debug!(
                    method = %method,
                    url = %url,
                    status = resp.status,
                    latency_ms = latency.as_millis() as u64,
                    "http request"
                );
                Ok(resp)
            }
            Err(err) => {
                let latency = start.elapsed();
                tracing::warn!(
                    method = %method,
                    url = %url,
                    error = %err,
                    latency_ms = latency.as_millis() as u64,
                    "http request failed"
                );
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::chain;
    use wreq::header::HeaderMap;

    struct StubHandler {
        status: u16,
    }

    #[async_trait]
    impl Handler for StubHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            Ok(HttpResponse {
                status: self.status,
                url: req.url,
                headers: HeaderMap::new(),
                body: String::new(),
            })
        }
    }

    #[tokio::test]
    async fn logging_does_not_alter_response() {
        let base: Arc<dyn Handler> = Arc::new(StubHandler { status: 201 });
        let handler = chain(vec![logging_middleware()], base);
        let req = Request {
            method: "POST".into(),
            url: "https://example.com/api".into(),
            headers: vec![],
            body: Some(b"hello".to_vec()),
            proxy: None,
        };
        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.url, "https://example.com/api");
    }

    #[tokio::test]
    async fn logging_propagates_error() {
        struct FailHandler;

        #[async_trait]
        impl Handler for FailHandler {
            async fn handle(&self, _req: Request) -> Result<HttpResponse> {
                Err(crate::HttpError::InvalidUrl("bad".into()))
            }
        }

        let base: Arc<dyn Handler> = Arc::new(FailHandler);
        let handler = chain(vec![logging_middleware()], base);
        let req = Request {
            method: "GET".into(),
            url: "bad-url".into(),
            headers: vec![],
            body: None,
            proxy: None,
        };
        let result = handler.handle(req).await;
        assert!(result.is_err());
    }
}
