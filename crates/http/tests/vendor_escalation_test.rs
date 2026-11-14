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

/// Real captured ordinary page (24 KB, plenty of visible text).
fn ordinary_page() -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/interstitial/ok_usps.http");
    let raw = std::fs::read_to_string(path).unwrap();
    raw.split_once("\n\n").unwrap().1.replace("</body>", "")
}

/// Serves a fixed 200/202 response with the given headers.
struct Fixed {
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    body: String,
}

#[async_trait]
impl Handler for Fixed {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let mut headers = HeaderMap::new();
        for (k, v) in &self.headers {
            headers.append(
                wreq::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        Ok(HttpResponse {
            status: self.status,
            url: req.url,
            headers,
            body: self.body.clone(),
        })
    }
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

/// A healthy page that embeds a vendor's tag, or carries the vendor's response
/// header, must never reach the solver or the negative cache — whatever status
/// it is served with. The tags below carry the exact markers the stub rules
/// look for.
#[tokio::test]
async fn ordinary_pages_embedding_vendor_tags_never_escalate() {
    let embeds: [(&str, Vec<(&str, &str)>); 6] = [
        (
            "<script>var dd={'host':'geo.captcha-delivery.com'}</script><script src=\"https://ct.captcha-delivery.com/c.js\"></script>",
            vec![("x-datadome", "protected"), ("x-dd-b", "1")],
        ),
        (
            "<div id=\"px-captcha\"></div><script>var pxCaptchaSrc='/a/captcha/captcha.js'</script>",
            vec![("x-px-blocked", "1")],
        ),
        (
            "<a href=\"https://errors.edgesuite.net/x\">help</a><script src=\"/_sec/cp_challenge/ak.js\"></script>",
            vec![("server", "AkamaiGHost")],
        ),
        (
            "<script src=\"/_Incapsula_Resource?SWJIYLWA=1\"></script><!-- Incapsula incident ID: 1 -->",
            vec![("x-iinfo", "1-2"), ("x-cdn", "Imperva")],
        ),
        (
            "<script src=\"https://a.sdk.awswaf.com/a/challenge.js\"></script><script>AwsWafIntegration.saveReferrer()</script>",
            vec![("x-amzn-waf-action", "challenge")],
        ),
        // the AWS action header alone on an unmodified page
        ("", vec![("x-amzn-waf-action", "challenge")]),
    ];
    for status in [200u16, 202] {
        for (tag, headers) in &embeds {
            let solver_calls = Arc::new(AtomicUsize::new(0));
            let negcache = Arc::new(SolverNegCache::new(
                1,
                Duration::from_secs(60),
                Duration::from_secs(60),
            ));
            let body = format!("{}{tag}</body></html>", ordinary_page());
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
                Arc::new(Fixed {
                    status,
                    headers: headers.clone(),
                    body: body.clone(),
                }),
            );
            let resp = handler
                .handle(get("https://example.test/a"))
                .await
                .unwrap_or_else(|e| panic!("{status} {tag}: escalated: {e:?}"));
            assert_eq!(resp.body, body, "{status} {tag}: body must pass through");
            assert_eq!(solver_calls.load(Ordering::SeqCst), 0, "{status} {tag}");
            assert!(
                !negcache.is_blocked("example.test", false),
                "{status} {tag}"
            );
        }
    }
}

/// A small landing page (little text, under 16 KB) that embeds one vendor
/// script with several recognised markers, plus that vendor's header, must not
/// reach the solver at 200 or 202.
#[tokio::test]
async fn small_landing_page_with_one_vendor_script_never_escalates() {
    let cases: [(&str, Vec<(&str, &str)>); 3] = [
        (
            "<script>var dd={'host':'geo.captcha-delivery.com'}</script><script src=\"https://ct.captcha-delivery.com/c.js\"></script>",
            vec![("x-datadome", "protected"), ("x-dd-b", "1")],
        ),
        (
            "<script>var pxCaptchaSrc='/a/captcha/captcha.js'</script><script src=\"https://captcha.px-cdn.net/a/captcha.js\"></script>",
            vec![("x-px-blocked", "1")],
        ),
        (
            "<script src=\"https://a.sdk.awswaf.com/a/challenge.js\"></script><script>AwsWafIntegration.saveReferrer()</script>",
            vec![("x-amzn-waf-action", "challenge")],
        ),
    ];
    for status in [200u16, 202] {
        for (embed, headers) in &cases {
            let solver_calls = Arc::new(AtomicUsize::new(0));
            let body = format!("<html><body><p>Welcome.</p>{embed}</body></html>");
            let handler = chain(
                vec![
                    solver_middleware_with_negcache(
                        Arc::new(CountingProvider {
                            calls: solver_calls.clone(),
                            succeed: false,
                        }),
                        Arc::new(CookieCache::new(Duration::from_secs(60))),
                        Arc::new(SolverNegCache::default()),
                    ),
                    quality_check_middleware(),
                ],
                Arc::new(Fixed {
                    status,
                    headers: headers.clone(),
                    body: body.clone(),
                }),
            );
            let resp = handler
                .handle(get("https://example.test/a"))
                .await
                .unwrap_or_else(|e| panic!("{status} {embed}: escalated: {e:?}"));
            assert_eq!(resp.body, body);
            assert_eq!(solver_calls.load(Ordering::SeqCst), 0, "{status} {embed}");
        }
    }
}
