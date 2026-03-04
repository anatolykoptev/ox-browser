//! Retry middleware that wraps a handler with exponential backoff.
//!
//! Port of go-stealth's `RetryMiddleware`. Retries requests on transient
//! HTTP errors (429, 500, 502, 503, 504) and retryable transport errors.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::retry::{is_retryable_status, retry_do, RetryConfig};
use crate::{HttpResponse, Result};

/// Returns a middleware that retries requests using exponential backoff.
///
/// On a retryable status code, the response is converted to
/// [`HttpError::RetryableStatus`] so the retry loop can catch and
/// re-attempt. The request is cloned for each retry.
pub fn retry_middleware(config: RetryConfig) -> MiddlewareFn {
    Arc::new(move |next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(RetryHandler {
            config: config.clone(),
            next,
        })
    })
}

struct RetryHandler {
    config: RetryConfig,
    next: Arc<dyn Handler>,
}

#[async_trait]
impl Handler for RetryHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let next = self.next.clone();
        let req = Arc::new(req);

        retry_do(&self.config, || {
            let next = next.clone();
            let req = req.clone();
            async move {
                let cloned_req = (*req).clone();
                let resp = next.handle(cloned_req).await?;
                if is_retryable_status(resp.status) {
                    return Err(HttpError::RetryableStatus(resp.status));
                }
                Ok(resp)
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::chain;
    use reqwest::header::HeaderMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct StatusHandler {
        statuses: Vec<u16>,
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Handler for StatusHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
            let status = self.statuses.get(idx).copied().unwrap_or(200);
            Ok(HttpResponse {
                status,
                url: req.url,
                headers: HeaderMap::new(),
                body: String::new(),
            })
        }
    }

    fn fast_config() -> RetryConfig {
        RetryConfig {
            max_retries: 3,
            initial_wait: Duration::from_millis(1),
            max_wait: Duration::from_millis(10),
            jitter_pct: 0.0,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn retries_on_503_then_succeeds() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(StatusHandler {
            statuses: vec![503, 503, 200],
            call_count: call_count.clone(),
        });

        let handler = chain(vec![retry_middleware(fast_config())], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
        };

        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn passes_through_on_200() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(StatusHandler {
            statuses: vec![200],
            call_count: call_count.clone(),
        });

        let handler = chain(vec![retry_middleware(fast_config())], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
        };

        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exhausts_retries_on_persistent_failure() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(StatusHandler {
            statuses: vec![502, 502, 502, 502],
            call_count: call_count.clone(),
        });

        let handler = chain(vec![retry_middleware(fast_config())], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
        };

        let result = handler.handle(req).await;
        assert!(result.is_err());
        // 1 initial + 3 retries = 4 total attempts.
        assert_eq!(call_count.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn retries_on_429() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(StatusHandler {
            statuses: vec![429, 200],
            call_count: call_count.clone(),
        });

        let handler = chain(vec![retry_middleware(fast_config())], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
        };

        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn does_not_retry_404() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(StatusHandler {
            statuses: vec![404],
            call_count: call_count.clone(),
        });

        let handler = chain(vec![retry_middleware(fast_config())], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
        };

        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 404);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }
}
