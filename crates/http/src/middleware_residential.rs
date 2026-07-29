//! Residential proxy retry middleware.
//!
//! On CF error (except Block), retries the request once with a residential
//! proxy URL set on the request. Many CF managed challenges pass residential
//! IPs without requiring a JS challenge.

use std::sync::Arc;

use async_trait::async_trait;

use crate::cloudflare::ChallengeType;
use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::middleware_retry::is_idempotent;
use crate::{HttpResponse, Result};

/// Returns a middleware that retries CF-blocked requests with a residential proxy.
///
/// Position in chain: between `retry` and `solver` (i.e., after retry but
/// before the headless solver). If the residential proxy also gets a CF
/// response, the error bubbles up to the solver middleware.
pub fn residential_proxy_middleware(proxy_url: String) -> MiddlewareFn {
    Arc::new(move |next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(ResidentialHandler {
            next,
            proxy_url: proxy_url.clone(),
        })
    })
}

struct ResidentialHandler {
    next: Arc<dyn Handler>,
    proxy_url: String,
}

#[async_trait]
impl Handler for ResidentialHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        // One-shot guard: if proxy already set, we already retried — propagate.
        if req.proxy.is_some() {
            return self.next.handle(req).await;
        }
        match self.next.handle(req.clone()).await {
            // Block errors are IP-level bans — residential won't help.
            Err(HttpError::Cloudflare(ChallengeType::Block, s, r)) => {
                Err(HttpError::Cloudflare(ChallengeType::Block, s, r))
            }
            // ManagedChallenge (200 body) requires JS execution, not a new IP.
            // Pass through to solver middleware which uses CloakBrowser CDP.
            Err(HttpError::Cloudflare(ChallengeType::ManagedChallenge, s, r)) => {
                Err(HttpError::Cloudflare(ChallengeType::ManagedChallenge, s, r))
            }
            // F1: inferred-from-status challenge on a non-idempotent method.
            // The origin MAY have processed the request — do not re-send
            // with a residential proxy. Return the original response so the
            // caller sees the real status + body.
            Err(HttpError::CloudflareInferred(_, resp)) if !is_idempotent(&req.method) => {
                tracing::info!(
                    url = %req.url,
                    method = %req.method,
                    "inferred CF on non-idempotent method — returning original response, not re-sending"
                );
                Ok(*resp)
            }
            // Any other CF challenge (genuine, or inferred idempotent) —
            // retry once with residential proxy.
            Err(HttpError::Cloudflare(ct, _s, _r)) => {
                tracing::info!(
                    url = %req.url,
                    challenge = %ct,
                    "CF detected, retrying with residential proxy"
                );
                let mut retry_req = req;
                retry_req.proxy = Some(self.proxy_url.clone());
                self.next.handle(retry_req).await
            }
            Err(HttpError::CloudflareInferred(_, _)) => {
                tracing::info!(
                    url = %req.url,
                    challenge = %ChallengeType::JsChallenge,
                    "inferred CF, retrying with residential proxy"
                );
                let mut retry_req = req;
                retry_req.proxy = Some(self.proxy_url.clone());
                self.next.handle(retry_req).await
            }
            // All other results pass through unchanged.
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::chain;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wreq::header::HeaderMap;

    fn ok_response(url: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            url: url.to_owned(),
            headers: HeaderMap::new(),
            body: "ok".to_owned(),
        }
    }

    fn make_req(url: &str) -> Request {
        Request {
            method: "GET".into(),
            url: url.to_owned(),
            headers: vec![],
            body: None,
            proxy: None,
        }
    }

    /// First call returns CF, second call returns 200.
    struct CfThenOkHandler {
        call_count: Arc<AtomicUsize>,
        captured_proxy: Arc<std::sync::Mutex<Option<String>>>,
    }

    #[async_trait]
    impl Handler for CfThenOkHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            let n = self.call_count.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                return Err(HttpError::Cloudflare(
                    ChallengeType::JsChallenge,
                    503,
                    "ray-1".into(),
                ));
            }
            *self.captured_proxy.lock().unwrap() = req.proxy.clone();
            Ok(ok_response(&req.url))
        }
    }

    #[tokio::test]
    async fn retries_with_residential_on_cf() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let captured_proxy = Arc::new(std::sync::Mutex::new(None::<String>));
        let base: Arc<dyn Handler> = Arc::new(CfThenOkHandler {
            call_count: call_count.clone(),
            captured_proxy: captured_proxy.clone(),
        });
        let proxy_url = "http://residential:8080".to_owned();
        let handler = chain(vec![residential_proxy_middleware(proxy_url.clone())], base);
        let resp = handler
            .handle(make_req("https://example.com"))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "should call handler twice"
        );
        let proxy = captured_proxy.lock().unwrap().clone();
        assert_eq!(proxy.as_deref(), Some("http://residential:8080"));
    }

    #[tokio::test]
    async fn passes_through_without_cf() {
        struct AlwaysOkHandler {
            call_count: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Handler for AlwaysOkHandler {
            async fn handle(&self, req: Request) -> Result<HttpResponse> {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                Ok(ok_response(&req.url))
            }
        }
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(AlwaysOkHandler {
            call_count: call_count.clone(),
        });
        let handler = chain(
            vec![residential_proxy_middleware("http://proxy:8080".into())],
            base,
        );
        let resp = handler
            .handle(make_req("https://normal.com"))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "should call handler exactly once"
        );
    }

    /// JsChallenge (503) persists even after residential retry — should propagate after 2 attempts.
    #[tokio::test]
    async fn propagates_cf_if_residential_fails() {
        struct AlwaysCfHandler {
            call_count: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Handler for AlwaysCfHandler {
            async fn handle(&self, _req: Request) -> Result<HttpResponse> {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                Err(HttpError::Cloudflare(
                    ChallengeType::JsChallenge,
                    503,
                    "ray-x".into(),
                ))
            }
        }
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(AlwaysCfHandler {
            call_count: call_count.clone(),
        });
        let handler = chain(
            vec![residential_proxy_middleware("http://proxy:8080".into())],
            base,
        );
        let err = handler
            .handle(make_req("https://hard.com"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, HttpError::Cloudflare(ChallengeType::JsChallenge, ..)),
            "should propagate CF error"
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "should have tried twice (initial + residential retry)"
        );
    }

    #[tokio::test]
    async fn does_not_retry_block_errors() {
        struct BlockHandler {
            call_count: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Handler for BlockHandler {
            async fn handle(&self, _req: Request) -> Result<HttpResponse> {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                Err(HttpError::Cloudflare(
                    ChallengeType::Block,
                    403,
                    "ray-block".into(),
                ))
            }
        }
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(BlockHandler {
            call_count: call_count.clone(),
        });
        let handler = chain(
            vec![residential_proxy_middleware("http://proxy:8080".into())],
            base,
        );
        let err = handler
            .handle(make_req("https://blocked.com"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, HttpError::Cloudflare(ChallengeType::Block, ..)),
            "block errors should pass through"
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "should NOT retry block errors"
        );
    }

    /// ManagedChallenge (200 body JS challenge) must NOT be retried with a
    /// residential proxy — it requires JS execution by the solver, not a
    /// different IP. The error must bubble through immediately (call_count == 1).
    #[tokio::test]
    async fn does_not_retry_managed_challenge() {
        struct ManagedChallengeHandler {
            call_count: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Handler for ManagedChallengeHandler {
            async fn handle(&self, _req: Request) -> Result<HttpResponse> {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                Err(HttpError::Cloudflare(
                    ChallengeType::ManagedChallenge,
                    200,
                    "ray-mc".into(),
                ))
            }
        }
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(ManagedChallengeHandler {
            call_count: call_count.clone(),
        });
        let handler = chain(
            vec![residential_proxy_middleware("http://proxy:8080".into())],
            base,
        );
        let err = handler
            .handle(make_req("https://cf-challenge.com"))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                HttpError::Cloudflare(ChallengeType::ManagedChallenge, ..)
            ),
            "ManagedChallenge should pass through unchanged"
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "ManagedChallenge must NOT be retried — residential IP doesn't help JS challenges"
        );
    }

    #[tokio::test]
    async fn does_not_retry_when_proxy_already_set() {
        struct AlwaysCfHandler2 {
            call_count: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Handler for AlwaysCfHandler2 {
            async fn handle(&self, _req: Request) -> Result<HttpResponse> {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                Err(HttpError::Cloudflare(
                    ChallengeType::ManagedChallenge,
                    200,
                    "ray".into(),
                ))
            }
        }
        let call_count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(AlwaysCfHandler2 {
            call_count: call_count.clone(),
        });
        let handler = chain(
            vec![residential_proxy_middleware("http://proxy:8080".into())],
            base,
        );
        let mut req = make_req("https://example.com");
        req.proxy = Some("http://existing:1234".into());
        let err = handler.handle(req).await.unwrap_err();
        assert!(matches!(err, HttpError::Cloudflare(..)));
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "should NOT retry when proxy already set"
        );
    }
}
