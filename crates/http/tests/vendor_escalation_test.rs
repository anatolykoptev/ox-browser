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

/// A captured fixture: status, headers, body.
fn fixture(name: &str) -> (u16, HeaderMap, String) {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/fixtures/interstitial/{name}.http"));
    let raw = std::fs::read_to_string(path).unwrap();
    let (head, body) = raw.split_once("\n\n").unwrap();
    let status = head.lines().next().unwrap()["HTTP ".len()..]
        .parse()
        .unwrap();
    let mut headers = HeaderMap::new();
    for l in head.lines().skip(1) {
        let (k, v) = l.split_once(':').unwrap();
        headers.append(
            wreq::header::HeaderName::from_bytes(k.trim().as_bytes()).unwrap(),
            HeaderValue::from_str(v.trim()).unwrap(),
        );
    }
    (status, headers, body.to_owned())
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
    fixture: String,
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
        let (status, headers, body) = fixture(&self.fixture);
        Ok(HttpResponse {
            status,
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
async fn aws_waf_token_wait_stub_at_202_reaches_the_solver() {
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
            fixture: "aws_waf_202".into(),
        }),
    );
    let resp = handler.handle(get("https://example.test/a")).await.unwrap();
    assert_eq!(
        solver_calls.load(Ordering::SeqCst),
        1,
        "the AWS WAF 202 token-wait stub must reach the solver"
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
            fixture: "aws_waf_202".into(),
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

/// Run one 200/202 response through quality -> solver and assert it passes
/// through untouched with no solver call and no negative-cache entry.
async fn assert_never_escalates(
    what: &str,
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    body: String,
) {
    let solver_calls = Arc::new(AtomicUsize::new(0));
    let negcache = Arc::new(SolverNegCache::new(
        1,
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
        Arc::new(Fixed {
            status,
            headers,
            body: body.clone(),
        }),
    );
    let resp = handler
        .handle(get("https://example.test/a"))
        .await
        .unwrap_or_else(|e| panic!("{what} at {status}: escalated: {e:?}"));
    assert_eq!(resp.body, body, "{what}: body must pass through");
    assert_eq!(solver_calls.load(Ordering::SeqCst), 0, "{what} at {status}");
    assert!(
        !negcache.is_blocked("example.test", false),
        "{what} at {status}"
    );
}

/// Review counterexamples: pages that look like a vendor challenge on a
/// non-blocking status are only labelled, never escalated. The real captured
/// Akamai "Access Denied" stub served with 200 is one of them.
#[tokio::test]
async fn vendor_look_alikes_at_200_never_reach_the_solver() {
    let (_, h, body) = fixture("akamai_denied_200");
    let headers: Vec<(&str, &str)> = h
        .iter()
        .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
        .collect();
    // leak the borrowed strs into 'static for the helper: test-only
    let headers: Vec<(&'static str, &'static str)> = headers
        .into_iter()
        .map(|(k, v)| {
            (
                &*Box::leak(k.to_owned().into_boxed_str()),
                &*Box::leak(v.to_owned().into_boxed_str()),
            )
        })
        .collect();
    assert_never_escalates("captured Akamai denial stub", 200, headers, body).await;

    // an AWS-shaped token-wait stub served with 200 plus the token cookie
    let (_, _, aws) = fixture("aws_waf_202");
    assert_never_escalates(
        "AWS-shaped stub at 200 with a token cookie",
        200,
        vec![("set-cookie", "aws-waf-token=x; Path=/")],
        aws,
    )
    .await;

    let login = "<html><head><title>Sign in</title></head><body><h1>Sign in</h1><form action=\"/login\"><input name=u><input type=\"password\" name=p></form><iframe src=\"https://geo.captcha-delivery.com/captcha/?x=1\"></iframe></body></html>";
    assert_never_escalates(
        "login page with an embedded DataDome iframe",
        200,
        vec![
            ("x-datadome", "protected"),
            ("set-cookie", "datadome=x; Path=/"),
        ],
        login.into(),
    )
    .await;

    let px = "<html><head><title>Contact</title></head><body><h1>Contact us</h1><form><input name=q></form><div id=\"px-captcha\"></div></body></html>";
    assert_never_escalates(
        "contact page with a px-captcha widget",
        200,
        vec![("x-px-blocked", "1"), ("set-cookie", "_pxhd=x; Path=/")],
        px.into(),
    )
    .await;

    let help = "<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1><p>If you see this message you don't have permission to access the page \"/account\". Contact support.</p></body></html>";
    assert_never_escalates(
        "help page with both Akamai phrases",
        200,
        vec![
            ("server", "AkamaiGHost"),
            ("set-cookie", "ak_bmsc=x; Path=/"),
        ],
        help.into(),
    )
    .await;
}
