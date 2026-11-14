//! A non-Cloudflare interstitial must escalate through the real middleware
//! chain (quality check -> solver) exactly like a Cloudflare one: the solver
//! provider is called, and repeated failures trip the negative cache.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use wreq::header::{HeaderMap, HeaderValue};

use ox_http::solver_negcache::SolverNegCache;
use ox_http::{
    ChallengeType, CookieCache, CookieProvider, Handler, HttpResponse, Request, Result,
    SolvedChallenge, chain, quality_check_middleware, solver_middleware_with_negcache,
};

/// Real captured page: an Akamai-served "Access Denied" stub with HTTP 200.
fn akamai_denied_200() -> (HeaderMap, String) {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/interstitial/akamai_denied_200.http");
    let raw = std::fs::read_to_string(path).unwrap();
    let (head, body) = raw.split_once("\n\n").unwrap();
    let mut headers = HeaderMap::new();
    for l in head.lines().skip(1) {
        let (k, v) = l.split_once(':').unwrap();
        headers.append(
            wreq::header::HeaderName::from_bytes(k.trim().as_bytes()).unwrap(),
            HeaderValue::from_str(v.trim()).unwrap(),
        );
    }
    (headers, body.to_owned())
}

/// Origin: serves the vendor stub until a request carries solver cookies.
struct StubThenContent {
    calls: Arc<AtomicUsize>,
    always_stub: bool,
}

#[async_trait]
impl Handler for StubThenContent {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let has_cookie = req
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("cookie"));
        if has_cookie && !self.always_stub {
            return Ok(HttpResponse {
                status: 200,
                url: req.url,
                headers: HeaderMap::new(),
                body: "<html><body>real article</body></html>".into(),
            });
        }
        let (headers, body) = akamai_denied_200();
        Ok(HttpResponse {
            status: 200,
            url: req.url,
            headers,
            body,
        })
    }
}

struct CountingProvider {
    calls: Arc<AtomicUsize>,
    succeed: bool,
}

#[async_trait]
impl CookieProvider for CountingProvider {
    async fn solve(
        &self,
        _url: &str,
        _ct: ChallengeType,
        _authenticated: bool,
    ) -> std::result::Result<SolvedChallenge, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.succeed {
            return Err("solver unavailable".into());
        }
        let mut cookies = HashMap::new();
        cookies.insert("session".into(), "solved".into());
        Ok(SolvedChallenge {
            cookies,
            user_agent: "Test/1.0".into(),
            body: None,
        })
    }
}

fn get(url: &str) -> Request {
    Request {
        method: "GET".into(),
        url: url.into(),
        headers: vec![],
        body: None,
        proxy: None,
        authenticated: false,
    }
}

#[tokio::test]
async fn non_cloudflare_interstitial_at_200_reaches_the_solver() {
    let origin_calls = Arc::new(AtomicUsize::new(0));
    let solver_calls = Arc::new(AtomicUsize::new(0));
    let handler = chain(
        vec![
            solver_middleware_with_negcache(
                Arc::new(CountingProvider {
                    calls: solver_calls.clone(),
                    succeed: true,
                }),
                Arc::new(CookieCache::new(Duration::from_secs(60))),
                Arc::new(SolverNegCache::default()),
            ),
            quality_check_middleware(),
        ],
        Arc::new(StubThenContent {
            calls: origin_calls.clone(),
            always_stub: false,
        }),
    );
    let resp = handler.handle(get("https://example.test/a")).await.unwrap();
    assert_eq!(
        solver_calls.load(Ordering::SeqCst),
        1,
        "a vendor interstitial served with HTTP 200 must reach the solver"
    );
    assert!(resp.body.contains("real article"), "got: {}", resp.body);
    assert_eq!(origin_calls.load(Ordering::SeqCst), 2, "stub, then resend");
}

#[tokio::test]
async fn failing_solves_on_a_vendor_interstitial_trip_the_negative_cache() {
    let origin_calls = Arc::new(AtomicUsize::new(0));
    let solver_calls = Arc::new(AtomicUsize::new(0));
    let negcache = Arc::new(SolverNegCache::new(
        2,
        Duration::from_secs(60),
        Duration::from_secs(60),
    ));
    let handler = chain(
        vec![
            solver_middleware_with_negcache(
                Arc::new(CountingProvider {
                    calls: solver_calls.clone(),
                    succeed: false,
                }),
                Arc::new(CookieCache::new(Duration::from_secs(60))),
                negcache.clone(),
            ),
            quality_check_middleware(),
        ],
        Arc::new(StubThenContent {
            calls: origin_calls.clone(),
            always_stub: true,
        }),
    );
    for _ in 0..5 {
        let r = handler.handle(get("https://example.test/a")).await;
        assert!(r.is_err(), "the solver never succeeds, got {r:?}");
    }
    assert_eq!(
        solver_calls.load(Ordering::SeqCst),
        2,
        "after two failed solves the cooldown must skip the provider"
    );
    assert!(negcache.is_blocked("example.test", false));
    let origin_before = origin_calls.load(Ordering::SeqCst);
    let _ = handler.handle(get("https://example.test/a")).await;
    assert_eq!(
        origin_calls.load(Ordering::SeqCst),
        origin_before,
        "a domain on cooldown fast-fails before another origin send"
    );
}

#[tokio::test]
async fn ordinary_200_passes_through_without_solver() {
    let solver_calls = Arc::new(AtomicUsize::new(0));
    struct Plain;
    #[async_trait]
    impl Handler for Plain {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            Ok(HttpResponse {
                status: 200,
                url: req.url,
                headers: HeaderMap::new(),
                body: format!("<html><body>{}</body></html>", "word ".repeat(200)),
            })
        }
    }
    let handler = chain(
        vec![
            solver_middleware_with_negcache(
                Arc::new(CountingProvider {
                    calls: solver_calls.clone(),
                    succeed: true,
                }),
                Arc::new(CookieCache::new(Duration::from_secs(60))),
                Arc::new(SolverNegCache::default()),
            ),
            quality_check_middleware(),
        ],
        Arc::new(Plain),
    );
    handler.handle(get("https://example.test/a")).await.unwrap();
    assert_eq!(solver_calls.load(Ordering::SeqCst), 0);
}
