//! Integration tests for the F1 idempotency-provenance seam.
//!
//! These exercise the FULL middleware chain (retry → solver → quality_check)
//! and the residential-proxy variant, asserting the two contracts that the
//! `Cloudflare` vs `CloudflareInferred` split enforces:
//!
//! 1. **POST behind an inferred challenge** (quality_check converts a bare
//!    401/403/429/503) is processed EXACTLY ONCE — the origin never sees a
//!    duplicate mutation. The original response is returned with body
//!    intact.
//! 2. **GET behind a GENUINE CF challenge** (real CF markers) IS re-sent
//!    after the solver produces cookies — CF intercepted the request, the
//!    origin never saw it, so re-sending is safe.
//!
//! The chain order under test mirrors production:
//!   retry → solver → [residential] → cloudflare_detect → quality_check → wreq

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use wreq::header::HeaderMap;

use ox_http::{
    ChallengeType, CookieCache, CookieProvider, Handler, HttpResponse, MiddlewareFn, Request,
    Result, RetryConfig, SolvedChallenge, chain, cloudflare_detect_middleware,
    quality_check_middleware, retry_middleware, solver_middleware,
};

use std::collections::HashMap;

// ── Helpers ────────────────────────────────────────────────────────────────

fn fast_retry() -> RetryConfig {
    RetryConfig {
        max_retries: 3,
        initial_wait: Duration::from_millis(1),
        max_wait: Duration::from_millis(10),
        jitter_pct: 0.0,
        ..Default::default()
    }
}

fn cf_headers(server: &str, ray: Option<&str>) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("server", server.parse().unwrap());
    if let Some(r) = ray {
        h.insert("cf-ray", r.parse().unwrap());
    }
    h
}

/// A mock CookieProvider that records calls and returns a fixed solution.
struct RecordingProvider {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl CookieProvider for RecordingProvider {
    async fn solve(
        &self,
        _url: &str,
        _ct: ChallengeType,
    ) -> std::result::Result<SolvedChallenge, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut cookies = HashMap::new();
        cookies.insert("cf_clearance".into(), "solved-token".into());
        Ok(SolvedChallenge {
            cookies,
            user_agent: "Test/1.0".into(),
            body: None,
        })
    }
}

// ── F1 contract 1: POST behind an INFERRED challenge is processed once ──────
//
// quality_check converts a bare 403 (no CF markers) into
// `CloudflareInferred`. The origin MAY have processed the POST, so the
// solver and retry middlewares must NOT re-send. The original 403 response
// is returned with body intact.

struct InferredChallengeHandler {
    /// Counts origin attempts — must end at 1 for a POST.
    origin_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Handler for InferredChallengeHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        self.origin_calls.fetch_add(1, Ordering::SeqCst);
        // Bare 403 with NO Cloudflare markers — quality_check will infer.
        Ok(HttpResponse {
            status: 403,
            url: req.url,
            headers: cf_headers("nginx", None),
            body: r#"{"error":"forbidden","detail":"token revoked"}"#.into(),
        })
    }
}

#[tokio::test]
async fn post_behind_inferred_challenge_processed_once() {
    let origin_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));

    let base: Arc<dyn Handler> = Arc::new(InferredChallengeHandler {
        origin_calls: origin_calls.clone(),
    });
    let provider: Arc<dyn CookieProvider> = Arc::new(RecordingProvider {
        calls: provider_calls.clone(),
    });
    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));

    // Chain: retry → solver → cloudflare_detect → quality_check → base
    // (residential omitted — the inferred gate fires in solver first.)
    let middlewares: Vec<MiddlewareFn> = vec![
        retry_middleware(fast_retry()),
        solver_middleware(provider, cache),
        cloudflare_detect_middleware(),
        quality_check_middleware(),
    ];
    let handler = chain(middlewares, base);

    let req = Request {
        method: "POST".into(),
        url: "https://example.com/api/charge".into(),
        headers: vec![],
        body: Some(br#"{"amount":100}"#.to_vec()),
        proxy: None,
    };

    let resp = handler.handle(req).await.unwrap();

    // The original 403 response is returned — body intact, not an error.
    assert_eq!(
        resp.status, 403,
        "POST behind inferred CF returns the original response"
    );
    assert!(
        resp.body.contains("token revoked"),
        "POST behind inferred CF must preserve the error body, got: {}",
        resp.body
    );

    // EXACTLY ONE origin attempt — no re-send, no retry.
    assert_eq!(
        origin_calls.load(Ordering::SeqCst),
        1,
        "POST behind inferred CF must be processed exactly once (no duplicate mutation)"
    );

    // The solver was never called — the inferred gate declined to re-send.
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        0,
        "solver must not be invoked for a POST behind inferred CF"
    );
}

// ── F1 contract 1b: GET behind an INFERRED challenge IS re-sent ─────────────
//
// Same chain, same bare 403, but GET. The origin did not mutate state, so
// the solver attempts a bypass and the request is re-sent with cookies.

struct InferredThenOkHandler {
    origin_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Handler for InferredThenOkHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let n = self.origin_calls.fetch_add(1, Ordering::SeqCst);
        // First call: bare 403 (inferred). Second call (with cookies): 200.
        if n == 0 {
            return Ok(HttpResponse {
                status: 403,
                url: req.url,
                headers: cf_headers("nginx", None),
                body: "forbidden".into(),
            });
        }
        Ok(HttpResponse {
            status: 200,
            url: req.url.clone(),
            headers: HeaderMap::new(),
            body: format!("ok-cookie:{}", req.header("cookie").unwrap_or("none")),
        })
    }
}

#[tokio::test]
async fn get_behind_inferred_challenge_is_solved_and_resent() {
    let origin_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));

    let base: Arc<dyn Handler> = Arc::new(InferredThenOkHandler {
        origin_calls: origin_calls.clone(),
    });
    let provider: Arc<dyn CookieProvider> = Arc::new(RecordingProvider {
        calls: provider_calls.clone(),
    });
    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));

    let middlewares: Vec<MiddlewareFn> = vec![
        retry_middleware(fast_retry()),
        solver_middleware(provider, cache),
        cloudflare_detect_middleware(),
        quality_check_middleware(),
    ];
    let handler = chain(middlewares, base);

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
        "GET behind inferred CF must be re-sent with solver cookies, got: {}",
        resp.body
    );
    // 2 origin calls: initial 403 + re-send with cookies.
    assert_eq!(origin_calls.load(Ordering::SeqCst), 2);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
}

// ── F1 contract 2: GET behind a GENUINE CF challenge is solved + re-sent ────
//
// A genuine CF 503 (server: cloudflare, challenge-platform, cf-ray) is
// detected by cloudflare_detect → HttpError::Cloudflare. CF intercepted the
// request; the origin never saw it. The solver runs and the request is
// re-sent on ANY method — including POST.

struct GenuineCfThenOkHandler {
    origin_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Handler for GenuineCfThenOkHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let n = self.origin_calls.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            return Ok(HttpResponse {
                status: 503,
                url: req.url,
                headers: cf_headers("cloudflare", Some("abc-LAX")),
                body: r#"<script src="/cdn-cgi/challenge-platform/x.js"></script>"#.into(),
            });
        }
        Ok(HttpResponse {
            status: 200,
            url: req.url.clone(),
            headers: HeaderMap::new(),
            body: format!("ok-cookie:{}", req.header("cookie").unwrap_or("none")),
        })
    }
}

#[tokio::test]
async fn post_behind_genuine_cf_is_solved_and_resent() {
    let origin_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));

    let base: Arc<dyn Handler> = Arc::new(GenuineCfThenOkHandler {
        origin_calls: origin_calls.clone(),
    });
    let provider: Arc<dyn CookieProvider> = Arc::new(RecordingProvider {
        calls: provider_calls.clone(),
    });
    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));

    let middlewares: Vec<MiddlewareFn> = vec![
        retry_middleware(fast_retry()),
        solver_middleware(provider, cache),
        cloudflare_detect_middleware(),
        quality_check_middleware(),
    ];
    let handler = chain(middlewares, base);

    let req = Request {
        method: "POST".into(),
        url: "https://example.com/api/submit".into(),
        headers: vec![],
        body: Some(b"payload".to_vec()),
        proxy: None,
    };

    let resp = handler.handle(req).await.unwrap();
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains("cf_clearance=solved-token"),
        "POST behind genuine CF must be re-sent with solver cookies, got: {}",
        resp.body
    );
    // 2 origin calls: initial CF 503 + re-send with cookies.
    assert_eq!(
        origin_calls.load(Ordering::SeqCst),
        2,
        "POST behind genuine CF is re-sent (CF intercepted, origin never saw it)"
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
}

// ── F1 contract 3: residential proxy respects the inferred gate ────────────
//
// With a residential-proxy middleware in the chain, a POST behind an
// inferred challenge must still be processed exactly once — the residential
// re-send is gated just like the solver re-send.

use ox_http::residential_proxy_middleware;

struct InferredHandler {
    origin_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Handler for InferredHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        self.origin_calls.fetch_add(1, Ordering::SeqCst);
        // Bare 403, no CF markers → quality_check infers.
        Ok(HttpResponse {
            status: 403,
            url: req.url,
            headers: cf_headers("nginx", None),
            body: "forbidden".into(),
        })
    }
}

#[tokio::test]
async fn residential_proxy_does_not_resend_post_behind_inferred() {
    let origin_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));

    let base: Arc<dyn Handler> = Arc::new(InferredHandler {
        origin_calls: origin_calls.clone(),
    });
    let provider: Arc<dyn CookieProvider> = Arc::new(RecordingProvider {
        calls: provider_calls.clone(),
    });
    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));

    let middlewares: Vec<MiddlewareFn> = vec![
        retry_middleware(fast_retry()),
        residential_proxy_middleware("http://residential-proxy:8080".into()),
        solver_middleware(provider, cache),
        cloudflare_detect_middleware(),
        quality_check_middleware(),
    ];
    let handler = chain(middlewares, base);

    let req = Request {
        method: "POST".into(),
        url: "https://example.com/api/charge".into(),
        headers: vec![],
        body: Some(b"{}".to_vec()),
        proxy: None,
    };

    let resp = handler.handle(req).await.unwrap();
    assert_eq!(resp.status, 403);
    assert_eq!(
        origin_calls.load(Ordering::SeqCst),
        1,
        "residential proxy must NOT re-send a POST behind inferred CF"
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
}

// ── F2 contract: POST on 500 returns the response with body intact ─────────
//
// A 500/502/504 is NOT caught by quality_check (which only converts
// 401/403/429/503). It reaches retry as Ok(resp). For a non-idempotent
// method there is no retry to trigger, so the response is returned as-is —
// the body the origin sent (usually the error detail) is preserved.

struct ServerErrorHandler {
    origin_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Handler for ServerErrorHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        self.origin_calls.fetch_add(1, Ordering::SeqCst);
        Ok(HttpResponse {
            status: 500,
            url: req.url,
            headers: HeaderMap::new(),
            body: r#"{"error":"internal","trace":"abc-123"}"#.into(),
        })
    }
}

#[tokio::test]
async fn post_on_500_through_full_chain_returns_body() {
    let origin_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));

    let base: Arc<dyn Handler> = Arc::new(ServerErrorHandler {
        origin_calls: origin_calls.clone(),
    });
    let provider: Arc<dyn CookieProvider> = Arc::new(RecordingProvider {
        calls: provider_calls.clone(),
    });
    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));

    let middlewares: Vec<MiddlewareFn> = vec![
        retry_middleware(fast_retry()),
        solver_middleware(provider, cache),
        cloudflare_detect_middleware(),
        quality_check_middleware(),
    ];
    let handler = chain(middlewares, base);

    let req = Request {
        method: "POST".into(),
        url: "https://example.com/api".into(),
        headers: vec![],
        body: Some(b"{}".to_vec()),
        proxy: None,
    };

    let resp = handler.handle(req).await.unwrap();
    assert_eq!(resp.status, 500);
    assert!(
        resp.body.contains("trace"),
        "POST on 500 must preserve the error body, got: {}",
        resp.body
    );
    assert_eq!(origin_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
}
