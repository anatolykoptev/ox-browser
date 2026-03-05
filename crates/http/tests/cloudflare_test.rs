//! Hard red tests for Cloudflare detection.
//!
//! Each test targets a real-world edge case that could cause false
//! positives or false negatives in production.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use wreq::header::HeaderMap;

use ox_http::{
    chain, cloudflare_detect_middleware, detect_cloudflare, retry_middleware, ChallengeType,
    Handler, HttpError, HttpResponse, MiddlewareFn, Request, Result, RetryConfig,
};

fn make_resp(status: u16, body: &str, headers: HeaderMap) -> HttpResponse {
    HttpResponse {
        status,
        url: "https://example.com".into(),
        headers,
        body: body.to_owned(),
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

// ── Edge case 1: No server header at all ────────────────────────────
// Real proxies/CDNs sometimes strip server headers entirely.
// Must not panic on missing header.

#[test]
fn no_server_header_returns_none() {
    let resp = make_resp(503, "challenge-platform", HeaderMap::new());
    assert!(
        detect_cloudflare(&resp).is_none(),
        "missing server header must not detect as CF"
    );
}

// ── Edge case 2: Empty body on CF 503 ───────────────────────────────
// Cloudflare sometimes returns empty body on network errors.
// Should NOT false-positive.

#[test]
fn empty_body_cf_503_returns_none() {
    let resp = make_resp(503, "", cf_headers("cloudflare", None));
    assert!(
        detect_cloudflare(&resp).is_none(),
        "empty body with CF server should not trigger detection"
    );
}

// ── Edge case 3: Detection priority — JsChallenge wins over Turnstile
// Real CF pages often contain BOTH challenge-platform AND turnstile
// markers. JsChallenge must win because it's checked first.

#[test]
fn js_challenge_priority_over_turnstile() {
    let body = r#"<html>
        <script src="/cdn-cgi/challenge-platform/x.js"></script>
        <div id="turnstile-wrapper"></div>
    </html>"#;
    let resp = make_resp(503, body, cf_headers("cloudflare", None));
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(
        cf.challenge_type,
        ChallengeType::JsChallenge,
        "JsChallenge should take priority when both markers present"
    );
}

// ── Edge case 4: Turnstile on 503 (not just 403) ───────────────────
// Cloudflare can serve turnstile on 503 too. Make sure it's detected.

#[test]
fn turnstile_on_503() {
    let resp = make_resp(
        503,
        "<html><div class=\"cf-turnstile\"></div></html>",
        cf_headers("cloudflare", None),
    );
    // 503 + cf-turnstile but no challenge-platform → should be Turnstile, not None
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Turnstile);
}

// ── Edge case 5: Block on 503 ───────────────────────────────────────
// cf-error-details can appear on 503 without challenge-platform.

#[test]
fn block_on_503() {
    let resp = make_resp(
        503,
        "<html><div class=\"cf-error-details\">err</div></html>",
        cf_headers("cloudflare", None),
    );
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Block);
}

// ── Edge case 6: Server header "cloudflare-nginx" ───────────────────
// Some reverse proxies append to server header. Contains check must work.

#[test]
fn server_header_contains_cloudflare() {
    let resp = make_resp(
        403,
        "you have been blocked",
        cf_headers("cloudflare-nginx", None),
    );
    assert!(
        detect_cloudflare(&resp).is_some(),
        "server containing 'cloudflare' should match"
    );
}

// ── Edge case 7: Ray ID empty when header missing ───────────────────
// Missing cf-ray should result in empty string, not panic.

#[test]
fn missing_ray_id_gives_empty_string() {
    let resp = make_resp(
        403,
        "you have been blocked",
        cf_headers("cloudflare", None),
    );
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.ray_id, "", "missing cf-ray should give empty string");
}

// ── Edge case 8: Body with markers in UPPER CASE ────────────────────
// Real CF pages have mixed case. Our lowercase conversion must catch it.

#[test]
fn uppercase_body_markers_detected() {
    let resp = make_resp(
        503,
        "<html><script src=\"/cdn-cgi/CHALLENGE-PLATFORM/x.js\"></script></html>",
        cf_headers("cloudflare", None),
    );
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::JsChallenge);
}

#[test]
fn uppercase_turnstile_detected() {
    let resp = make_resp(
        403,
        "<html><div id=\"TURNSTILE-WRAPPER\"></div></html>",
        cf_headers("cloudflare", None),
    );
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Turnstile);
}

#[test]
fn uppercase_block_detected() {
    let resp = make_resp(
        403,
        "<html>YOU HAVE BEEN BLOCKED</html>",
        cf_headers("cloudflare", None),
    );
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Block);
}

// ── Edge case 9: HttpError::Cloudflare Display format ───────────────
// Verify error message is parseable by logging/monitoring.

#[test]
fn cloudflare_error_display_format() {
    let err = HttpError::Cloudflare(ChallengeType::JsChallenge, 503, "abc-LAX".into());
    let msg = err.to_string();
    assert!(
        msg.contains("js_challenge"),
        "error message should contain challenge type: {msg}"
    );
    assert!(
        msg.contains("503"),
        "error message should contain status: {msg}"
    );
    assert!(
        msg.contains("abc-LAX"),
        "error message should contain ray id: {msg}"
    );
}

// ── Edge case 10: 429 from Cloudflare is NOT detected ───────────────
// Cloudflare rate limiting returns 429 but it's NOT a challenge page.
// Our detection only checks 403/503.

#[test]
fn cf_429_not_detected() {
    let resp = make_resp(
        429,
        "challenge-platform turnstile-wrapper you have been blocked",
        cf_headers("cloudflare", Some("ray-123")),
    );
    assert!(
        detect_cloudflare(&resp).is_none(),
        "429 should not trigger CF detection even with all markers"
    );
}

// ── Edge case 11: Real-world CF JS challenge HTML ───────────────────
// Abbreviated real Cloudflare challenge page.

#[test]
fn realistic_js_challenge_page() {
    let body = r#"<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <script src="/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1?ray=abc123"></script>
    </head><body><div class="main-wrapper"><div class="main-content">
    <h2 data-translate="checking_browser">Checking your browser before accessing</h2>
    </div></div></body></html>"#;
    let resp = make_resp(503, body, cf_headers("cloudflare", Some("abc123-LAX")));
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::JsChallenge);
    assert_eq!(cf.ray_id, "abc123-LAX");
}

// ── Edge case 12: Real-world CF block page ──────────────────────────

#[test]
fn realistic_block_page() {
    let body = r#"<!DOCTYPE html><html><head><title>Attention Required!</title></head>
    <body><div class="cf-section cf-wrapper"><h2>Sorry, you have been blocked</h2>
    <p>You are unable to access this website.</p>
    <div class="cf-error-details"><p>Ray ID: xyz789</p></div>
    </div></body></html>"#;
    let resp = make_resp(403, body, cf_headers("cloudflare", Some("xyz789-SIN")));
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Block);
}

// ── Edge case 13: Retry + CF middleware integration ─────────────────
// Verifies that CF errors are retried automatically when both
// middlewares are in the chain (retry wrapping cloudflare).

struct CfThenOkHandler {
    responses: Vec<(u16, String, String)>, // (status, body, server)
    call_count: Arc<AtomicUsize>,
}

#[async_trait]
impl Handler for CfThenOkHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
        let (status, body, server) = if idx < self.responses.len() {
            self.responses[idx].clone()
        } else {
            (200, "ok".into(), "nginx".into())
        };
        let mut headers = HeaderMap::new();
        headers.insert("server", server.parse().unwrap());
        Ok(HttpResponse {
            status,
            url: req.url,
            headers,
            body,
        })
    }
}

#[tokio::test]
async fn retry_middleware_retries_on_cloudflare_error() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let base: Arc<dyn Handler> = Arc::new(CfThenOkHandler {
        responses: vec![
            (
                503,
                "challenge-platform".into(),
                "cloudflare".into(),
            ),
            (200, "ok".into(), "nginx".into()),
        ],
        call_count: call_count.clone(),
    });

    let fast_retry = RetryConfig {
        max_retries: 3,
        initial_wait: Duration::from_millis(1),
        max_wait: Duration::from_millis(10),
        jitter_pct: 0.0,
        ..Default::default()
    };

    // Chain: retry(outer) -> cloudflare(inner)
    let middlewares: Vec<MiddlewareFn> = vec![
        retry_middleware(fast_retry),
        cloudflare_detect_middleware(),
    ];
    let handler = chain(middlewares, base);

    let req = Request {
        method: "GET".into(),
        url: "https://example.com".into(),
        headers: vec![],
        body: None,
    };
    let resp = handler.handle(req).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "should have retried once after CF detection"
    );
}

// ── Edge case 14: Persistent CF block exhausts retries ──────────────
// All attempts hit CF → final error should be Cloudflare variant.

#[tokio::test]
async fn persistent_cf_block_exhausts_retries() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let base: Arc<dyn Handler> = Arc::new(CfThenOkHandler {
        responses: vec![
            (403, "you have been blocked".into(), "cloudflare".into()),
            (403, "you have been blocked".into(), "cloudflare".into()),
            (403, "you have been blocked".into(), "cloudflare".into()),
            (403, "you have been blocked".into(), "cloudflare".into()),
        ],
        call_count: call_count.clone(),
    });

    let fast_retry = RetryConfig {
        max_retries: 3,
        initial_wait: Duration::from_millis(1),
        max_wait: Duration::from_millis(10),
        jitter_pct: 0.0,
        ..Default::default()
    };

    let middlewares: Vec<MiddlewareFn> = vec![
        retry_middleware(fast_retry),
        cloudflare_detect_middleware(),
    ];
    let handler = chain(middlewares, base);

    let req = Request {
        method: "GET".into(),
        url: "https://example.com".into(),
        headers: vec![],
        body: None,
    };
    let err = handler.handle(req).await.unwrap_err();
    match err {
        HttpError::Cloudflare(ct, status, _) => {
            assert_eq!(ct, ChallengeType::Block);
            assert_eq!(status, 403);
        }
        other => panic!("expected Cloudflare error, got {other:?}"),
    }
    // 1 initial + 3 retries = 4 total attempts
    assert_eq!(call_count.load(Ordering::SeqCst), 4);
}

// ── Edge case 15: Middleware propagates inner handler errors ─────────
// If the handler below CF middleware returns an error, it should
// pass through unchanged.

struct FailHandler;

#[async_trait]
impl Handler for FailHandler {
    async fn handle(&self, _req: Request) -> Result<HttpResponse> {
        Err(HttpError::Timeout(Duration::from_secs(30)))
    }
}

#[tokio::test]
async fn middleware_propagates_inner_error() {
    let base: Arc<dyn Handler> = Arc::new(FailHandler);
    let handler = chain(vec![cloudflare_detect_middleware()], base);
    let req = Request {
        method: "GET".into(),
        url: "https://example.com".into(),
        headers: vec![],
        body: None,
    };
    let err = handler.handle(req).await.unwrap_err();
    match err {
        HttpError::Timeout(d) => assert_eq!(d, Duration::from_secs(30)),
        other => panic!("expected Timeout, got {other:?}"),
    }
}

// ── Edge case 16: cf-turnstile alternate marker ─────────────────────
// Both "turnstile-wrapper" and "cf-turnstile" should trigger Turnstile.

#[test]
fn cf_turnstile_class_detected() {
    let resp = make_resp(
        403,
        r#"<div class="cf-turnstile" data-sitekey="xxx"></div>"#,
        cf_headers("cloudflare", None),
    );
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Turnstile);
}

// ── Edge case 17: Status preserved in challenge struct ──────────────
// Turnstile can appear on both 403 and 503; status must match response.

#[test]
fn challenge_status_matches_response_status() {
    for status in [403, 503] {
        let resp = make_resp(
            status,
            "<div id=\"turnstile-wrapper\"></div>",
            cf_headers("cloudflare", None),
        );
        let cf = detect_cloudflare(&resp).unwrap();
        assert_eq!(
            cf.status, status,
            "challenge status should match response status"
        );
    }
}

// ── Edge case 18: Huge body doesn't panic ───────────────────────────
// 10 MB body with no markers — must handle gracefully.

#[test]
fn huge_body_no_panic() {
    let body = "x".repeat(10_000_000);
    let resp = make_resp(503, &body, cf_headers("cloudflare", None));
    assert!(detect_cloudflare(&resp).is_none());
}
