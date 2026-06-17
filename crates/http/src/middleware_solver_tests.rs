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
                ChallengeType::JsChallenge,
                503,
                "ray-1".into(),
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
        &self,
        _url: &str,
        _ct: ChallengeType,
    ) -> std::result::Result<SolvedChallenge, String> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let mut cookies = HashMap::new();
        cookies.insert("cf_clearance".into(), "solved-token".into());
        Ok(SolvedChallenge {
            cookies,
            user_agent: "Test/1.0".into(),
            body: None,
        })
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
    cache.put(
        "example.com",
        SolvedChallenge {
            cookies,
            user_agent: "Cached/1.0".into(),
            body: None,
        },
    );
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
                ChallengeType::Block,
                403,
                "ray-block".into(),
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
    assert!(matches!(
        err,
        HttpError::Cloudflare(ChallengeType::Block, ..)
    ));
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

/// The retry-storm guard: a domain whose solves keep failing is put on
/// cooldown, after which the expensive provider.solve is skipped and the CF
/// error surfaces immediately.
#[tokio::test]
async fn negcache_short_circuits_after_repeated_failures() {
    use crate::solver_negcache::{SOLVER_GIVEUP_TOTAL, SolverNegCache};

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
                "ray".into(),
            ))
        }
    }

    /// Provider that always fails to solve.
    struct FailingProvider {
        call_count: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl CookieProvider for FailingProvider {
        async fn solve(
            &self,
            _url: &str,
            _ct: ChallengeType,
        ) -> std::result::Result<SolvedChallenge, String> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Err("solver unavailable".into())
        }
    }

    let handler_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let base: Arc<dyn Handler> = Arc::new(AlwaysCfHandler {
        call_count: handler_calls.clone(),
    });
    let provider: Arc<dyn CookieProvider> = Arc::new(FailingProvider {
        call_count: provider_calls.clone(),
    });
    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));
    // Threshold = 2: the 1st and 2nd attempts call the provider (and fail),
    // the 2nd failure trips the cooldown, so the 3rd+ attempts short-circuit.
    let negcache = Arc::new(SolverNegCache::new(
        2,
        Duration::from_secs(60),
        Duration::from_secs(60),
    ));
    let handler = chain(
        vec![solver_middleware_with_negcache(provider, cache, negcache)],
        base,
    );

    let giveup_before = SOLVER_GIVEUP_TOTAL.load(Ordering::Relaxed);

    let make = || Request {
        method: "GET".into(),
        url: "https://storm.example/page".into(),
        headers: vec![],
        body: None,
        proxy: None,
    };

    // Fire the same URL 6×. Without the guard, the provider would be hit 6×.
    for _ in 0..6 {
        let _ = handler.handle(make()).await;
    }

    // Provider should be invoked at most `max_failures` (2) times — after that
    // the domain is on cooldown and solves are skipped.
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        2,
        "provider must be called only until cooldown trips, not on every request"
    );
    let giveup_after = SOLVER_GIVEUP_TOTAL.load(Ordering::Relaxed);
    assert!(
        giveup_after >= giveup_before + 4,
        "give-up counter must bump for each short-circuited request (before={giveup_before}, after={giveup_after})"
    );
}

#[test]
fn domain_extraction() {
    assert_eq!(domain_from_url("https://example.com/page"), "example.com");
    assert_eq!(
        domain_from_url("http://sub.test.org:8080/a"),
        "sub.test.org"
    );
    assert_eq!(domain_from_url("not-a-url"), "");
}

#[tokio::test]
async fn returns_body_from_solver_directly() {
    // Mock handler that always returns CF error
    struct AlwaysCfHandler;
    #[async_trait]
    impl Handler for AlwaysCfHandler {
        async fn handle(&self, _req: Request) -> Result<HttpResponse> {
            Err(HttpError::Cloudflare(
                ChallengeType::JsChallenge,
                503,
                "ray".into(),
            ))
        }
    }

    // Mock provider that returns a body along with cookies
    struct BodyProvider;
    #[async_trait]
    impl CookieProvider for BodyProvider {
        async fn solve(
            &self,
            _url: &str,
            _ct: ChallengeType,
        ) -> std::result::Result<SolvedChallenge, String> {
            let mut cookies = HashMap::new();
            cookies.insert("cf_clearance".into(), "token".into());
            Ok(SolvedChallenge {
                cookies,
                user_agent: "Test/1.0".into(),
                body: Some("<html>solved content</html>".into()),
            })
        }
    }

    let base: Arc<dyn Handler> = Arc::new(AlwaysCfHandler);
    let provider: Arc<dyn CookieProvider> = Arc::new(BodyProvider);
    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));
    let handler = chain(vec![solver_middleware(provider, cache)], base);
    let req = Request {
        method: "GET".into(),
        url: "https://example.com".into(),
        headers: vec![],
        body: None,
        proxy: None,
    };
    let resp = handler.handle(req).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, "<html>solved content</html>");
}
