//! Retry middleware that wraps a handler with exponential backoff.
//!
//! Port of go-stealth's `RetryMiddleware`. Retries requests on transient
//! HTTP errors (429, 500, 502, 503, 504) and retryable transport errors.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::retry::{RetryConfig, is_retryable_status, retry_do};
use crate::{HttpResponse, Result};

/// Returns a middleware that retries requests using exponential backoff.
///
/// On a retryable status code, the response is converted to
/// [`HttpError::RetryableStatus`] so the retry loop can catch and
/// re-attempt. The request is cloned for each retry.
///
/// **Idempotency gate**: only idempotent methods (GET, HEAD, OPTIONS, TRACE,
/// PUT, DELETE) are retried. POST and PATCH are NOT retried — a 503 or
/// transport error is surfaced to the caller rather than risk a duplicate
/// mutation at the origin (issue #114). The response (or error) is returned
/// after a single attempt.
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

/// Methods safe to repeat without risk of duplicate side-effects at the
/// origin. POST and PATCH are excluded — re-issuing them can create
/// duplicate resources or apply a patch twice.
fn is_idempotent(method: &str) -> bool {
    matches!(
        method.to_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PUT" | "DELETE"
    )
}

#[async_trait]
impl Handler for RetryHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        // Non-idempotent methods (POST, PATCH) are not retried. A 503 or
        // transport error is returned after a single attempt — re-issuing
        // a POST that may have already been processed by the origin is a
        // duplicate-mutation hazard (issue #114).
        if !is_idempotent(&req.method) {
            let resp = self.next.handle(req).await?;
            if is_retryable_status(resp.status) {
                return Err(HttpError::RetryableStatus(resp.status));
            }
            return Ok(resp);
        }

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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use wreq::header::HeaderMap;

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
            proxy: None,
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
            proxy: None,
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
            proxy: None,
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
            proxy: None,
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
            proxy: None,
        };

        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 404);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    // ── Idempotency gate (issue #114) ───────────────────────────────────

    /// A POST is NOT retried on a 503 — the origin must not see a duplicate
    /// mutation. The 503 surfaces as a `RetryableStatus` error after a
    /// single attempt.
    ///
    /// **Mutation probe**: remove the `is_idempotent` gate in
    /// `RetryHandler::handle` (or make it always return `true`) and this
    /// test fails — `call_count` becomes 4 (1 + 3 retries) instead of 1.
    #[tokio::test]
    async fn post_is_not_retried_on_503() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(StatusHandler {
            statuses: vec![503, 503, 503, 503],
            call_count: call_count.clone(),
        });

        let handler = chain(vec![retry_middleware(fast_config())], base);
        let req = Request {
            method: "POST".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: Some(b"{}".to_vec()),
            proxy: None,
        };

        let result = handler.handle(req).await;
        assert!(result.is_err(), "POST on 503 must surface as an error");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "POST must NOT be retried — exactly one origin attempt"
        );
    }

    /// A PATCH is also not retried (non-idempotent).
    #[tokio::test]
    async fn patch_is_not_retried_on_503() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(StatusHandler {
            statuses: vec![503, 503, 503, 503],
            call_count: call_count.clone(),
        });

        let handler = chain(vec![retry_middleware(fast_config())], base);
        let req = Request {
            method: "PATCH".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: Some(b"{}".to_vec()),
            proxy: None,
        };

        let result = handler.handle(req).await;
        assert!(result.is_err());
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    /// A GET IS still retried on 503 — the idempotency gate must not
    /// disable retries wholesale.
    #[tokio::test]
    async fn get_is_still_retried_on_503() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(StatusHandler {
            statuses: vec![503, 200],
            call_count: call_count.clone(),
        });

        let handler = chain(vec![retry_middleware(fast_config())], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
            proxy: None,
        };

        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "GET must still be retried on 503"
        );
    }

    /// PUT is idempotent — it IS retried on 503.
    #[tokio::test]
    async fn put_is_retried_on_503() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(StatusHandler {
            statuses: vec![503, 200],
            call_count: call_count.clone(),
        });

        let handler = chain(vec![retry_middleware(fast_config())], base);
        let req = Request {
            method: "PUT".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: Some(b"{}".to_vec()),
            proxy: None,
        };

        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    /// DELETE is idempotent — it IS retried on 503.
    #[tokio::test]
    async fn delete_is_retried_on_503() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(StatusHandler {
            statuses: vec![503, 200],
            call_count: call_count.clone(),
        });

        let handler = chain(vec![retry_middleware(fast_config())], base);
        let req = Request {
            method: "DELETE".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
            proxy: None,
        };

        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn idempotency_classification() {
        assert!(is_idempotent("GET"));
        assert!(is_idempotent("get"));
        assert!(is_idempotent("HEAD"));
        assert!(is_idempotent("OPTIONS"));
        assert!(is_idempotent("TRACE"));
        assert!(is_idempotent("PUT"));
        assert!(is_idempotent("DELETE"));
        assert!(!is_idempotent("POST"));
        assert!(!is_idempotent("PATCH"));
        assert!(!is_idempotent("post"));
    }
}
