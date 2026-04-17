//! Client Hints middleware that auto-injects `sec-ch-ua-*` headers.
//!
//! Port of go-stealth's `ClientHintsMiddleware`. Reads the `user-agent`
//! header from the request, generates matching Client Hints via
//! [`crate::profile_hints::client_hints_headers`], and injects them
//! without overwriting any already-present hint headers.

use std::sync::Arc;

use async_trait::async_trait;

use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::profile_hints::client_hints_headers;
use crate::{HttpResponse, Result};

/// Returns a middleware that auto-injects `sec-ch-ua-*` Client Hints headers
/// derived from the request's `user-agent` header.
///
/// Only adds hints that are not already present in the request, matching
/// the go-stealth behavior of never overwriting explicitly-set headers.
pub fn client_hints_middleware() -> MiddlewareFn {
    Arc::new(|next: Arc<dyn Handler>| -> Arc<dyn Handler> { Arc::new(ClientHintsHandler { next }) })
}

struct ClientHintsHandler {
    next: Arc<dyn Handler>,
}

#[async_trait]
impl Handler for ClientHintsHandler {
    async fn handle(&self, mut req: Request) -> Result<HttpResponse> {
        if let Some(ua) = req.header("user-agent").map(String::from) {
            let hints = client_hints_headers(&ua);
            for (key, value) in hints {
                if !req.has_header(&key) {
                    req.headers.push((key, value));
                }
            }
        }

        // Inject Accept-Language if not already present.
        // Anti-bot systems compare this with navigator.languages fingerprint.
        if !req.has_header("accept-language") {
            req.headers
                .push(("accept-language".into(), "en-US,en;q=0.9".into()));
        }

        self.next.handle(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::chain;
    use wreq::header::HeaderMap;

    /// Captures the final request headers so tests can inspect them.
    struct CaptureHandler {
        captured: Arc<tokio::sync::Mutex<Vec<(String, String)>>>,
    }

    #[async_trait]
    impl Handler for CaptureHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            *self.captured.lock().await = req.headers.clone();
            Ok(HttpResponse {
                status: 200,
                url: req.url,
                headers: HeaderMap::new(),
                body: String::new(),
            })
        }
    }

    fn chrome_ua() -> String {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
            .into()
    }

    #[tokio::test]
    async fn injects_hints_for_chrome() {
        let captured = Arc::new(tokio::sync::Mutex::new(vec![]));
        let base: Arc<dyn Handler> = Arc::new(CaptureHandler {
            captured: captured.clone(),
        });
        let handler = chain(vec![client_hints_middleware()], base);

        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![("user-agent".into(), chrome_ua())],
            body: None,
            proxy: None,
        };
        handler.handle(req).await.unwrap();

        let hdrs = captured.lock().await;
        assert!(hdrs.iter().any(|(k, _)| k == "sec-ch-ua"));
        assert!(hdrs.iter().any(|(k, _)| k == "sec-ch-ua-mobile"));
        assert!(hdrs.iter().any(|(k, _)| k == "sec-ch-ua-platform"));
    }

    #[tokio::test]
    async fn no_hints_for_firefox() {
        let captured = Arc::new(tokio::sync::Mutex::new(vec![]));
        let base: Arc<dyn Handler> = Arc::new(CaptureHandler {
            captured: captured.clone(),
        });
        let handler = chain(vec![client_hints_middleware()], base);

        let ua = "Mozilla/5.0 (Windows NT 10.0; rv:138.0) Gecko/20100101 Firefox/138.0";
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![("user-agent".into(), ua.into())],
            body: None,
            proxy: None,
        };
        handler.handle(req).await.unwrap();

        let hdrs = captured.lock().await;
        assert!(!hdrs.iter().any(|(k, _)| k.starts_with("sec-ch-ua")));
    }

    #[tokio::test]
    async fn does_not_overwrite_existing_hints() {
        let captured = Arc::new(tokio::sync::Mutex::new(vec![]));
        let base: Arc<dyn Handler> = Arc::new(CaptureHandler {
            captured: captured.clone(),
        });
        let handler = chain(vec![client_hints_middleware()], base);

        let custom_hint = "\"Custom\";v=\"99\"".to_owned();
        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![
                ("user-agent".into(), chrome_ua()),
                ("sec-ch-ua".into(), custom_hint.clone()),
            ],
            body: None,
            proxy: None,
        };
        handler.handle(req).await.unwrap();

        let hdrs = captured.lock().await;
        // The pre-existing sec-ch-ua should be preserved, not overwritten.
        let sec_ch_ua = hdrs
            .iter()
            .find(|(k, _)| k == "sec-ch-ua")
            .map(|(_, v)| v.as_str());
        assert_eq!(sec_ch_ua, Some(custom_hint.as_str()));
        // But sec-ch-ua-mobile and sec-ch-ua-platform should still be injected.
        assert!(hdrs.iter().any(|(k, _)| k == "sec-ch-ua-mobile"));
        assert!(hdrs.iter().any(|(k, _)| k == "sec-ch-ua-platform"));
    }

    #[tokio::test]
    async fn injects_accept_language() {
        let captured = Arc::new(tokio::sync::Mutex::new(vec![]));
        let base: Arc<dyn Handler> = Arc::new(CaptureHandler {
            captured: captured.clone(),
        });
        let handler = chain(vec![client_hints_middleware()], base);

        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![("user-agent".into(), chrome_ua())],
            body: None,
            proxy: None,
        };
        handler.handle(req).await.unwrap();

        let hdrs = captured.lock().await;
        let al = hdrs
            .iter()
            .find(|(k, _)| k == "accept-language")
            .map(|(_, v)| v.as_str());
        assert_eq!(al, Some("en-US,en;q=0.9"));
    }

    #[tokio::test]
    async fn does_not_overwrite_accept_language() {
        let captured = Arc::new(tokio::sync::Mutex::new(vec![]));
        let base: Arc<dyn Handler> = Arc::new(CaptureHandler {
            captured: captured.clone(),
        });
        let handler = chain(vec![client_hints_middleware()], base);

        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![
                ("user-agent".into(), chrome_ua()),
                ("accept-language".into(), "ru-RU,ru;q=0.9".into()),
            ],
            body: None,
            proxy: None,
        };
        handler.handle(req).await.unwrap();

        let hdrs = captured.lock().await;
        let al = hdrs
            .iter()
            .find(|(k, _)| k == "accept-language")
            .map(|(_, v)| v.as_str());
        assert_eq!(al, Some("ru-RU,ru;q=0.9"));
    }

    #[tokio::test]
    async fn no_ua_header_no_hints() {
        let captured = Arc::new(tokio::sync::Mutex::new(vec![]));
        let base: Arc<dyn Handler> = Arc::new(CaptureHandler {
            captured: captured.clone(),
        });
        let handler = chain(vec![client_hints_middleware()], base);

        let req = Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
            proxy: None,
        };
        handler.handle(req).await.unwrap();

        let hdrs = captured.lock().await;
        assert!(!hdrs.iter().any(|(k, _)| k.starts_with("sec-ch-ua")));
    }
}
