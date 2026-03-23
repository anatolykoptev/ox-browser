//! CF solver middleware — intercepts Cloudflare errors, solves via CookieProvider, retries.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use crate::cloudflare::ChallengeType;
use crate::cookie_cache::CookieCache;
use crate::cookie_provider::{CookieProvider, SolvedChallenge};
use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::{HttpResponse, Result};

/// Returns a middleware that auto-solves CF challenges via a [`CookieProvider`].
///
/// On `HttpError::Cloudflare` (except `Block`), calls the provider, caches
/// the result, injects cookies, and retries the request once.
pub fn solver_middleware(
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
) -> MiddlewareFn {
    Arc::new(move |next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(SolverHandler {
            next,
            provider: Arc::clone(&provider),
            cache: Arc::clone(&cache),
        })
    })
}

struct SolverHandler {
    next: Arc<dyn Handler>,
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
}

/// Extract the domain (host) from a URL string.
fn domain_from_url(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default()
}

/// Build a `cookie` header value from a solved challenge.
fn cookie_header(solution: &SolvedChallenge) -> String {
    solution
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Inject cookies from a solved challenge into the request.
fn inject_cookies(req: &mut Request, solution: &SolvedChallenge) {
    let value = cookie_header(solution);
    req.set_header("cookie", value);
}

#[async_trait]
impl Handler for SolverHandler {
    async fn handle(&self, mut req: Request) -> Result<HttpResponse> {
        let domain = domain_from_url(&req.url);

        // Check cache first — inject cookies if we have a prior solution.
        if let Some(solution) = self.cache.get(&domain) {
            debug!(domain = %domain, "solver: using cached cookies");
            inject_cookies(&mut req, &solution);
            return self.next.handle(req).await;
        }

        // No cached cookies — try the request normally.
        match self.next.handle(req.clone()).await {
            // Block errors are not solvable — pass through.
            Err(HttpError::Cloudflare(ChallengeType::Block, status, ray)) => {
                Err(HttpError::Cloudflare(ChallengeType::Block, status, ray))
            }
            // Solvable CF challenge — call provider, cache, retry once.
            Err(HttpError::Cloudflare(challenge_type, _status, _ray)) => {
                debug!(domain = %domain, challenge = %challenge_type, "solver: solving challenge");
                let solution = self
                    .provider
                    .solve(&req.url, challenge_type)
                    .await
                    .map_err(|e| HttpError::ProxyPool(format!("solver failed: {e}")))?;
                self.cache.put(&domain, solution.clone());
                inject_cookies(&mut req, &solution);
                self.next.handle(req).await
            }
            // Everything else passes through.
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::chain;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use wreq::header::HeaderMap;

    /// Mock handler that returns CF error on first call, 200 on second.
    struct CfThenOkHandler {
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Handler for CfThenOkHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            let n = self.call_count.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                return Err(HttpError::Cloudflare(
                    ChallengeType::JsChallenge, 503, "ray-1".into(),
                ));
            }
            let cookie = req.header("cookie").unwrap_or("").to_owned();
            Ok(HttpResponse {
                status: 200,
                url: req.url,
                headers: HeaderMap::new(),
                body: cookie,
            })
        }
    }

    /// Mock handler that always returns 200 with cookie header in body.
    struct EchoHandler;

    #[async_trait]
    impl Handler for EchoHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            let cookie = req.header("cookie").unwrap_or("none").to_owned();
            Ok(HttpResponse {
                status: 200,
                url: req.url,
                headers: HeaderMap::new(),
                body: cookie,
            })
        }
    }

    /// Mock provider that tracks call count.
    struct MockProvider {
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl CookieProvider for MockProvider {
        async fn solve(
            &self, _url: &str, _ct: ChallengeType,
        ) -> std::result::Result<SolvedChallenge, String> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let mut cookies = HashMap::new();
            cookies.insert("cf_clearance".into(), "solved-token".into());
            Ok(SolvedChallenge { cookies, user_agent: "Test/1.0".into() })
        }
    }

    #[tokio::test]
    async fn solves_js_challenge_and_retries() {
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(CfThenOkHandler {
            call_count: handler_calls.clone(),
        });
        let provider: Arc<dyn CookieProvider> = Arc::new(MockProvider {
            call_count: provider_calls.clone(),
        });
        let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));
        let handler = chain(vec![solver_middleware(provider, cache)], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com/page".into(),
            headers: vec![],
            body: None,
            proxy: None,
        };
        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("cf_clearance=solved-token"));
        assert_eq!(handler_calls.load(Ordering::SeqCst), 2);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn uses_cached_cookies() {
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(EchoHandler);
        let provider: Arc<dyn CookieProvider> = Arc::new(MockProvider {
            call_count: provider_calls.clone(),
        });
        let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));
        let mut cookies = HashMap::new();
        cookies.insert("cf_clearance".into(), "cached-tok".into());
        cache.put("example.com", SolvedChallenge {
            cookies,
            user_agent: "Cached/1.0".into(),
        });
        let handler = chain(vec![solver_middleware(provider, cache)], base);
        let req = Request {
            method: "GET".into(),
            url: "https://example.com/page".into(),
            headers: vec![],
            body: None,
            proxy: None,
        };
        let resp = handler.handle(req).await.unwrap();
        assert!(resp.body.contains("cf_clearance=cached-tok"));
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn block_not_solvable() {
        let provider_calls = Arc::new(AtomicUsize::new(0));
        struct BlockHandler;
        #[async_trait]
        impl Handler for BlockHandler {
            async fn handle(&self, _req: Request) -> Result<HttpResponse> {
                Err(HttpError::Cloudflare(
                    ChallengeType::Block, 403, "ray-block".into(),
                ))
            }
        }
        let base: Arc<dyn Handler> = Arc::new(BlockHandler);
        let provider: Arc<dyn CookieProvider> = Arc::new(MockProvider {
            call_count: provider_calls.clone(),
        });
        let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));
        let handler = chain(vec![solver_middleware(provider, cache)], base);
        let req = Request {
            method: "GET".into(),
            url: "https://blocked.com".into(),
            headers: vec![],
            body: None,
            proxy: None,
        };
        let err = handler.handle(req).await.unwrap_err();
        assert!(matches!(err, HttpError::Cloudflare(ChallengeType::Block, ..)));
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn passes_through_normal_requests() {
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn Handler> = Arc::new(EchoHandler);
        let provider: Arc<dyn CookieProvider> = Arc::new(MockProvider {
            call_count: provider_calls.clone(),
        });
        let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));
        let handler = chain(vec![solver_middleware(provider, cache)], base);
        let req = Request {
            method: "GET".into(),
            url: "https://normal.com".into(),
            headers: vec![],
            body: None,
            proxy: None,
        };
        let resp = handler.handle(req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn domain_extraction() {
        assert_eq!(domain_from_url("https://example.com/page"), "example.com");
        assert_eq!(domain_from_url("http://sub.test.org:8080/a"), "sub.test.org");
        assert_eq!(domain_from_url("not-a-url"), "");
    }
}
