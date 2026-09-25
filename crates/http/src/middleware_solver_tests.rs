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

/// Issue #125: a cached solution that is rejected by a fresh CF challenge
/// must be evicted and the challenge resolved fresh — not replayed forever.
#[tokio::test]
async fn stale_cached_solution_is_evicted_and_resolved() {
    /// First call (stale cookies) -> CF rejection; second call (fresh
    /// cookies) -> 200 echoing the cookie header.
    struct RejectStaleHandler {
        call_count: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl Handler for RejectStaleHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            let n = self.call_count.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                assert!(
                    req.header("cookie").unwrap_or("").contains("stale-tok"),
                    "first send must carry the stale solution"
                );
                return Err(HttpError::Cloudflare(
                    ChallengeType::JsChallenge,
                    403,
                    "ray-stale".into(),
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

    let handler_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let base: Arc<dyn Handler> = Arc::new(RejectStaleHandler {
        call_count: handler_calls.clone(),
    });
    let provider: Arc<dyn CookieProvider> = Arc::new(MockProvider {
        call_count: provider_calls.clone(),
    });
    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));
    let mut stale = HashMap::new();
    stale.insert("cf_clearance".into(), "stale-tok".into());
    cache.put(
        "example.com",
        SolvedChallenge {
            cookies: stale,
            user_agent: "Old/1.0".into(),
            body: None,
        },
    );

    let stale_evicted_before = crate::metrics::SOLVER_OUTCOME_STALE_EVICTED.load(Ordering::Relaxed);
    let attempted_before = crate::metrics::SOLVER_OUTCOME_ATTEMPTED.load(Ordering::Relaxed);

    let handler = chain(vec![solver_middleware(provider, Arc::clone(&cache))], base);
    let req = Request {
        method: "GET".into(),
        url: "https://example.com/page".into(),
        headers: vec![],
        body: None,
        proxy: None,
    };
    let resp = handler.handle(req).await.unwrap();
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains("cf_clearance=solved-token"),
        "fresh solution must be injected on resend, got: {}",
        resp.body
    );
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        1,
        "stale rejection must trigger exactly one fresh solve"
    );
    // The cache now holds the FRESH solution — the stale one is gone.
    let cached = cache.get("example.com").expect("fresh solution cached");
    assert_eq!(cached.cookies.get("cf_clearance").unwrap(), "solved-token");
    assert!(
        crate::metrics::SOLVER_OUTCOME_STALE_EVICTED.load(Ordering::Relaxed) > stale_evicted_before,
        "stale_evicted outcome must be counted"
    );
    assert!(
        crate::metrics::SOLVER_OUTCOME_ATTEMPTED.load(Ordering::Relaxed) > attempted_before,
        "attempted outcome must be counted"
    );
}

/// Issue #125: the solver sits OUTSIDE the retry middleware, so one
/// challenged request costs at most one provider.solve() — previously the
/// retry loop re-entered the solver and multiplied 15-25s solves.
///
/// Mutation probe: swap the solver/retry push order in build_middlewares
/// back and this test fails (provider called once per retry pass).
#[tokio::test]
async fn one_solve_per_challenged_request_under_retry() {
    use crate::client::HttpClient;
    use crate::config::HttpConfig;
    use crate::retry::RetryConfig;

    /// Always returns a genuine CF challenge — the solver's resend also
    /// fails, which is exactly when the old nesting multiplied solves.
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
                "ray-loop".into(),
            ))
        }
    }

    let handler_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let provider: Arc<dyn CookieProvider> = Arc::new(MockProvider {
        call_count: provider_calls.clone(),
    });
    let config = HttpConfig {
        retry: Some(RetryConfig {
            max_retries: 3,
            initial_wait: Duration::from_millis(1),
            max_wait: Duration::from_millis(2),
            multiplier: 1.0,
            jitter_pct: 0.0,
        }),
        cookie_provider: Some(provider),
        cookie_cache: Some(Arc::new(CookieCache::new(Duration::from_secs(60)))),
        solver_negcache: Some(Arc::new(crate::solver_negcache::SolverNegCache::default())),
        quality_check: false,
        ..HttpConfig::default()
    };
    let client = HttpClient::with_chain(
        Arc::new(AlwaysCfHandler {
            call_count: handler_calls.clone(),
        }),
        config,
    );

    let err = client
        .request("GET", "https://example.com/page", None, None, &[])
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpError::Cloudflare(ChallengeType::JsChallenge, ..)),
        "final error must surface the challenge, got {err:?}"
    );
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        1,
        "one challenged request = exactly one solve attempt"
    );
    // CF errors are non-retryable (the solver owns re-send decisions): the
    // upstream sees exactly two sends — the cold send and the post-solve
    // resend — never a retry-loop burn. Mutation probe: restore
    // Cloudflare->retryable and this count inflates to 2*(1+max_retries).
    assert_eq!(
        handler_calls.load(Ordering::SeqCst),
        2,
        "cold send + post-solve resend, no retry burn"
    );
}

/// Issue #125: a domain on negcache cooldown must fast-fail BEFORE the
/// first send — with the solver outside retry, without this check the
/// request would burn the whole retry loop before hitting the guard.
#[tokio::test]
async fn negcache_blocked_domain_fails_before_first_send() {
    use crate::solver_negcache::SolverNegCache;

    struct CountingHandler {
        call_count: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl Handler for CountingHandler {
        async fn handle(&self, _req: Request) -> Result<HttpResponse> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Err(HttpError::Cloudflare(
                ChallengeType::JsChallenge,
                503,
                "ray".into(),
            ))
        }
    }

    let handler_calls = Arc::new(AtomicUsize::new(0));
    let base: Arc<dyn Handler> = Arc::new(CountingHandler {
        call_count: handler_calls.clone(),
    });
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let provider: Arc<dyn CookieProvider> = Arc::new(MockProvider {
        call_count: provider_calls.clone(),
    });
    let negcache = Arc::new(SolverNegCache::new(
        1,
        Duration::from_secs(300),
        Duration::from_secs(300),
    ));
    negcache.record_failure("blocked.example"); // trip the cooldown

    let handler = chain(
        vec![solver_middleware_with_negcache(
            provider,
            Arc::new(CookieCache::new(Duration::from_secs(60))),
            negcache,
        )],
        base,
    );
    let req = Request {
        method: "GET".into(),
        url: "https://blocked.example/page".into(),
        headers: vec![],
        body: None,
        proxy: None,
    };
    let err = handler.handle(req).await.unwrap_err();
    assert!(
        matches!(err, HttpError::ProxyPool(_)),
        "cooldown must surface the solver decision, got {err:?}"
    );
    assert_eq!(
        handler_calls.load(Ordering::SeqCst),
        0,
        "blocked domain must not reach the upstream handler at all"
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
}

/// Issue #125: a non-idempotent request hitting an inferred challenge must
/// return the ORIGINAL response — the origin may already have processed it,
/// so no re-send and no solve.
#[tokio::test]
async fn inferred_challenge_on_post_returns_original_response() {
    /// Returns an inferred challenge carrying the origin's real response.
    struct InferredHandler;
    #[async_trait]
    impl Handler for InferredHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            Err(HttpError::CloudflareInferred(
                403,
                Box::new(HttpResponse {
                    status: 403,
                    url: req.url,
                    headers: HeaderMap::new(),
                    body: "origin says no".into(),
                }),
            ))
        }
    }

    let provider_calls = Arc::new(AtomicUsize::new(0));
    let base: Arc<dyn Handler> = Arc::new(InferredHandler);
    let provider: Arc<dyn CookieProvider> = Arc::new(MockProvider {
        call_count: provider_calls.clone(),
    });
    let handler = chain(
        vec![solver_middleware(
            provider,
            Arc::new(CookieCache::new(Duration::from_secs(60))),
        )],
        base,
    );
    let req = Request {
        method: "POST".into(),
        url: "https://example.com/submit".into(),
        headers: vec![],
        body: Some(b"data".to_vec()),
        proxy: None,
    };
    let resp = handler.handle(req).await.unwrap();
    assert_eq!(resp.status, 403);
    assert_eq!(resp.body, "origin says no");
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        0,
        "non-idempotent inferred challenge must not trigger a solve"
    );
}

/// Issue #125: the eviction must happen even when the fresh solve FAILS —
/// otherwise the next request replays the same stale entry again (the
/// pre-fix behaviour: stale entries were never revalidated).
///
/// Mutation probe: delete `self.cache.remove(&domain)` in the cached-send
/// branch and this test fails — `cache.get` still returns the stale entry.
#[tokio::test]
async fn stale_eviction_survives_solve_failure() {
    /// Always rejects with a CF challenge.
    struct AlwaysCfHandler;
    #[async_trait]
    impl Handler for AlwaysCfHandler {
        async fn handle(&self, _req: Request) -> Result<HttpResponse> {
            Err(HttpError::Cloudflare(
                ChallengeType::JsChallenge,
                403,
                "ray".into(),
            ))
        }
    }

    /// Provider that always fails — the stale entry must STILL be gone.
    struct FailingProvider;
    #[async_trait]
    impl CookieProvider for FailingProvider {
        async fn solve(
            &self,
            _url: &str,
            _ct: ChallengeType,
        ) -> std::result::Result<SolvedChallenge, String> {
            Err("solver down".into())
        }
    }

    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));
    let mut stale = HashMap::new();
    stale.insert("cf_clearance".into(), "stale-tok".into());
    cache.put(
        "example.com",
        SolvedChallenge {
            cookies: stale,
            user_agent: "Old/1.0".into(),
            body: None,
        },
    );

    // Use a fresh negcache so the post-failure cooldown cannot bleed into
    // other tests sharing domain state.
    let negcache = Arc::new(crate::solver_negcache::SolverNegCache::new(
        100,
        Duration::from_secs(300),
        Duration::from_secs(300),
    ));
    let handler = chain(
        vec![solver_middleware_with_negcache(
            Arc::new(FailingProvider),
            Arc::clone(&cache),
            negcache,
        )],
        Arc::new(AlwaysCfHandler),
    );
    let req = Request {
        method: "GET".into(),
        url: "https://example.com/page".into(),
        headers: vec![],
        body: None,
        proxy: None,
    };
    let err = handler.handle(req).await.unwrap_err();
    assert!(
        matches!(err, HttpError::ProxyPool(_)),
        "solve failure must surface as the solver decision, got {err:?}"
    );
    assert!(
        cache.get("example.com").is_none(),
        "stale entry must be evicted even when the re-solve fails"
    );
}

/// Issue #125: pins the DELIBERATE ordering — solver outside retry — via an
/// observable signal: a cached send that resolves through a transient
/// failure must not re-enter the solver per retry pass. Under the reversed
/// order every retry pass re-runs `handle`, counting another `cache_hit`.
///
/// Flow under the shipped order: stale send -> CF rejection -> evict ->
/// solve -> resend traverses the retry subtree (Timeout retried inside,
/// no solver re-entry) -> 200. Counters: cache_hit=1, attempted=1.
#[tokio::test]
async fn resend_transient_retry_does_not_reenter_solver() {
    /// CF error on the first (stale-cookie) send, Timeout on the post-solve
    /// send, then 200.
    struct FlakyCfHandler {
        call_count: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl Handler for FlakyCfHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            match self.call_count.fetch_add(1, Ordering::SeqCst) {
                0 => Err(HttpError::Cloudflare(
                    ChallengeType::JsChallenge,
                    403,
                    "ray".into(),
                )),
                1 => Err(HttpError::Timeout(Duration::from_secs(30))),
                _ => Ok(HttpResponse {
                    status: 200,
                    url: req.url,
                    headers: HeaderMap::new(),
                    body: "ok".into(),
                }),
            }
        }
    }

    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));
    let mut stale = HashMap::new();
    stale.insert("cf_clearance".into(), "stale-tok".into());
    cache.put(
        "example.com",
        SolvedChallenge {
            cookies: stale,
            user_agent: "Old/1.0".into(),
            body: None,
        },
    );

    let provider_calls = Arc::new(AtomicUsize::new(0));
    let provider: Arc<dyn CookieProvider> = Arc::new(MockProvider {
        call_count: provider_calls.clone(),
    });
    let config = crate::config::HttpConfig {
        retry: Some(crate::retry::RetryConfig {
            max_retries: 3,
            initial_wait: Duration::from_millis(1),
            max_wait: Duration::from_millis(2),
            multiplier: 1.0,
            jitter_pct: 0.0,
        }),
        cookie_provider: Some(provider),
        cookie_cache: Some(Arc::clone(&cache)),
        solver_negcache: Some(Arc::new(crate::solver_negcache::SolverNegCache::default())),
        quality_check: false,
        ..crate::config::HttpConfig::default()
    };
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let client = crate::client::HttpClient::with_chain(
        Arc::new(FlakyCfHandler {
            call_count: handler_calls.clone(),
        }),
        config,
    );

    let resp = client
        .request("GET", "https://example.com/page", None, None, &[])
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    // The post-solve resend's transient Timeout was retried INSIDE the retry
    // subtree (timeout -> 200 on the next pass) — the solver never re-runs.
    // Sends: stale-cookie send, resend timeout, retried resend = 3.
    assert_eq!(
        handler_calls.load(Ordering::SeqCst),
        3,
        "stale send + resend timeout + retried resend"
    );
}
