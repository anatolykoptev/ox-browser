//! Middleware framework for HTTP request processing.
//!
//! Ports the go-stealth middleware pattern: composable `Handler` trait,
//! `MiddlewareFn` type, and `chain()` function for ordered composition.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{HttpResponse, Result};

/// An HTTP request flowing through the middleware chain.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl Request {
    /// Look up the first header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Returns true if a header with `name` exists (case-insensitive).
    pub fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(name))
    }
}

/// Async handler that processes a [`Request`] and returns an [`HttpResponse`].
#[async_trait]
pub trait Handler: Send + Sync {
    async fn handle(&self, req: Request) -> Result<HttpResponse>;
}

/// A middleware function that wraps a handler to produce a new handler.
///
/// First middleware in the vec is the outermost (runs first on request,
/// last on response), matching the go-stealth `Chain()` semantics.
pub type MiddlewareFn = Arc<dyn Fn(Arc<dyn Handler>) -> Arc<dyn Handler> + Send + Sync>;

/// Compose middlewares around a base handler.
///
/// `middlewares[0]` is outermost (first to see the request), which matches
/// the go-stealth `Chain(a, b)(handler)` order: a wraps b wraps handler.
pub fn chain(middlewares: Vec<MiddlewareFn>, base: Arc<dyn Handler>) -> Arc<dyn Handler> {
    let mut handler = base;
    for mw in middlewares.into_iter().rev() {
        handler = mw(handler);
    }
    handler
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HttpResponse;
    use reqwest::header::HeaderMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Simple echo handler that returns 200 with the request URL as body.
    struct EchoHandler;

    #[async_trait]
    impl Handler for EchoHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            Ok(HttpResponse {
                status: 200,
                url: req.url.clone(),
                headers: HeaderMap::new(),
                body: req.url,
            })
        }
    }

    #[tokio::test]
    async fn chain_empty_passes_through() {
        let base: Arc<dyn Handler> = Arc::new(EchoHandler);
        let handler = chain(vec![], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
        };
        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "https://example.com");
    }

    #[tokio::test]
    async fn chain_order_outermost_first() {
        let order = Arc::new(AtomicUsize::new(0));

        // Middleware A should run first (outermost).
        let order_a = order.clone();
        let mw_a: MiddlewareFn = Arc::new(move |next: Arc<dyn Handler>| {
            let order_a = order_a.clone();
            let next = next.clone();
            let wrapper: Arc<dyn Handler> = Arc::new(OrderedMiddleware {
                expected_order: 0,
                order: order_a,
                next,
            });
            wrapper
        });

        // Middleware B should run second (inner).
        let order_b = order.clone();
        let mw_b: MiddlewareFn = Arc::new(move |next: Arc<dyn Handler>| {
            let order_b = order_b.clone();
            let next = next.clone();
            let wrapper: Arc<dyn Handler> = Arc::new(OrderedMiddleware {
                expected_order: 1,
                order: order_b,
                next,
            });
            wrapper
        });

        let base: Arc<dyn Handler> = Arc::new(EchoHandler);
        let handler = chain(vec![mw_a, mw_b], base);

        let req = Request {
            method: "GET".into(),
            url: "https://test.com".into(),
            headers: vec![],
            body: None,
        };
        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 200);
        // Both middlewares ran.
        assert_eq!(order.load(Ordering::SeqCst), 2);
    }

    struct OrderedMiddleware {
        expected_order: usize,
        order: Arc<AtomicUsize>,
        next: Arc<dyn Handler>,
    }

    #[async_trait]
    impl Handler for OrderedMiddleware {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            let current = self.order.fetch_add(1, Ordering::SeqCst);
            assert_eq!(current, self.expected_order);
            self.next.handle(req).await
        }
    }

    #[test]
    fn request_header_lookup() {
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![
                ("Content-Type".into(), "text/html".into()),
                ("User-Agent".into(), "test-ua".into()),
            ],
            body: None,
        };
        assert_eq!(req.header("content-type"), Some("text/html"));
        assert_eq!(req.header("USER-AGENT"), Some("test-ua"));
        assert_eq!(req.header("x-missing"), None);
        assert!(req.has_header("Content-Type"));
        assert!(!req.has_header("x-missing"));
    }
}
