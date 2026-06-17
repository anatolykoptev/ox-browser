use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use wreq::header::HeaderMap;

use super::*;
use crate::HttpConfig;
use crate::content::ReadParams;
use crate::middleware::{Handler, Request};
use crate::render_cache::{RenderMode, RenderModeCache};
use crate::solver_negcache::SolverNegCache;
use crate::{HttpResponse, Result};

// ─── helpers ─────────────────────────────────────────────────────────────────

fn params(url: &str) -> ReadParams {
    ReadParams {
        url: url.to_owned(),
        format: "text".into(),
        max_length: 0,
    }
}

/// Build a minimal HttpConfig with the supplied render cache and negcache.
fn config_with(
    render_cache: Option<Arc<RenderModeCache>>,
    negcache: Option<Arc<SolverNegCache>>,
) -> HttpConfig {
    let mut cfg = HttpConfig::default();
    cfg.render_cache = render_cache;
    cfg.solver_negcache = negcache;
    cfg
}

/// Handler that always returns HTTP 200 with dummy HTML.
struct OkHandler {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Handler for OkHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(HttpResponse {
            status: 200,
            url: req.url,
            headers: HeaderMap::new(),
            body: "<html><body>content</body></html>".into(),
        })
    }
}

// ─── BUILD TESTS ─────────────────────────────────────────────────────────────

#[test]
fn build_output_populates_all_fields() {
    let ext = crate::content::ExtractedContent {
        title: "T".into(),
        content: "C".into(),
        author: "A".into(),
        excerpt: "E".into(),
        length: 1,
        json_ld: vec![],
        og_image: String::new(),
        meta: crate::content::ArticleMeta::default(),
    };
    let p = params("https://x.com");
    let out = build_output(ext, &p, "direct", 42);
    assert_eq!(out.title, "T");
    assert_eq!(out.url, "https://x.com");
    assert_eq!(out.method, "direct");
    assert_eq!(out.elapsed_ms, 42);
    assert!(out.error.is_none());
}

#[test]
fn build_error_output_has_error() {
    let p = params("https://fail.com");
    let out = build_error_output(&p, "direct", 10, "connection refused");
    assert_eq!(out.error.as_deref(), Some("connection refused"));
    assert!(out.content.is_empty());
}

#[test]
fn truncation_applied_when_max_length_set() {
    let ext = crate::content::ExtractedContent {
        title: "T".into(),
        content: "A".repeat(500),
        author: String::new(),
        excerpt: String::new(),
        length: 500,
        json_ld: vec![],
        og_image: String::new(),
        meta: crate::content::ArticleMeta::default(),
    };
    let p = ReadParams {
        url: "https://x.com".into(),
        format: "text".into(),
        max_length: 50,
    };
    let out = build_output(ext, &p, "direct", 0);
    assert!(out.content.len() <= 55);
}

// ─── INTEGRATION TEST 1: gating — negcache blocked → fast-fail, no http.get ──
//
// Drives `read_page_inner` with a GiveUp-cached domain whose negcache is STILL
// BLOCKED. Verifies:
//   a) return value is the fast-fail error.
//   b) the underlying handler (http.get) is NEVER called.
//
// RED on revert: removing the GiveUp match-arm from read_pipeline.rs causes the
// function to fall through to http.get(). handler_calls increments to 1 and the
// assertion fails.
//
// Also RED if the is_blocked re-check is removed (BUG A fix guard): without the
// re-check, all GiveUp entries fast-fail regardless — this test still passes,
// but test 2 (recovery) goes RED.
#[tokio::test]
async fn giveup_with_active_negcache_fast_fails_without_http_get() {
    let domain = "blocked.test";
    let url = format!("https://{domain}/page");

    // Negcache: domain is blocked (1-failure threshold → immediately blocked).
    let nc = Arc::new(SolverNegCache::new(
        1,
        Duration::from_secs(300),
        Duration::from_secs(300),
    ));
    assert!(nc.record_failure(domain), "should block at threshold=1");
    assert!(nc.is_blocked(domain));

    // Render cache: GiveUp already set (as if a prior request set it).
    let render_cache = Arc::new(RenderModeCache::new(Duration::from_secs(3600)));
    render_cache.set(domain, RenderMode::GiveUp);

    let handler_calls = Arc::new(AtomicUsize::new(0));
    let handler: Arc<dyn Handler> = Arc::new(OkHandler {
        calls: handler_calls.clone(),
    });
    let cfg = config_with(Some(render_cache), Some(nc));
    let http = HttpClient::with_handler(handler, cfg);

    let out = read_page_inner(&http, &params(&url), &[]).await;

    // Must fast-fail with the GiveUp error message.
    assert!(
        out.error.is_some(),
        "expected fast-fail error, got success with content={:?}",
        out.content
    );
    assert!(
        out.error.as_deref().unwrap().contains("GiveUp"),
        "error must mention GiveUp; got: {:?}",
        out.error
    );
    // The underlying handler MUST NOT have been called — that's the whole point.
    assert_eq!(
        handler_calls.load(Ordering::SeqCst),
        0,
        "http.get() must not be called when GiveUp is active"
    );
}

// ─── INTEGRATION TEST 2: recovery — GiveUp cached but negcache cooldown lifted ─
//
// Drives `read_page_inner` with a GiveUp-cached domain whose negcache has
// EXPIRED (is_blocked returns false). Verifies:
//   a) the GiveUp entry is removed from RenderModeCache.
//   b) http.get() IS called (the domain gets a real fetch attempt).
//   c) a successful fetch returns a non-error output.
//
// This test is the canonical proof that BUG A is fixed.
// RED on revert: removing the is_blocked re-check (reverting BUG A fix) causes
// the function to always fast-fail on GiveUp regardless of negcache state —
// handler_calls stays 0 and the assertion at the bottom fails.
#[tokio::test]
async fn giveup_with_expired_negcache_falls_through_to_fetch() {
    let domain = "recovering.test";
    let url = format!("https://{domain}/page");

    // Negcache with 0ms cooldown → already expired by the time the test runs.
    let nc = Arc::new(SolverNegCache::new(
        1,
        Duration::from_millis(0), // expires immediately
        Duration::from_secs(300),
    ));
    nc.record_failure(domain);
    // Yield to allow the 0ms cooldown to expire.
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(!nc.is_blocked(domain), "cooldown should have expired");

    // Render cache: GiveUp set (simulates a prior request having set it with 3600s TTL).
    let render_cache = Arc::new(RenderModeCache::new(Duration::from_secs(3600)));
    render_cache.set(domain, RenderMode::GiveUp);

    let handler_calls = Arc::new(AtomicUsize::new(0));
    let handler: Arc<dyn Handler> = Arc::new(OkHandler {
        calls: handler_calls.clone(),
    });
    let cfg = config_with(Some(render_cache.clone()), Some(nc));
    let http = HttpClient::with_handler(handler, cfg);

    let out = read_page_inner(&http, &params(&url), &[]).await;

    // The GiveUp entry must have been removed.
    assert_eq!(
        render_cache.get(domain),
        None,
        "GiveUp entry must be removed when negcache cooldown has lifted"
    );

    // http.get() must have been called (domain got a real fetch attempt).
    assert_eq!(
        handler_calls.load(Ordering::SeqCst),
        1,
        "http.get() must be called after GiveUp eviction"
    );

    // The fetch succeeded → output should not have an error.
    assert!(
        out.error.is_none(),
        "recovered fetch must succeed; got error: {:?}",
        out.error
    );
}

// ─── INTEGRATION TEST 3: fetch_success_total for site-handler paths ──────────
//
// Drives `read_page_inner` via a site_handler that returns a successful
// ReadOutput. Verifies that `fetch_success_total` is incremented.
//
// This test is the canonical proof that BUG B is fixed for the site_handlers path.
// RED on revert: removing the `record_fetch_success()` call before the early
// return in the site_handlers loop causes `after == before` and the assertion fails.
#[tokio::test]
async fn site_handler_success_increments_fetch_success_total() {
    use crate::metrics::FETCH_SUCCESS_TOTAL;

    let before = FETCH_SUCCESS_TOTAL.load(Ordering::Relaxed);

    // A site_handler that returns a successful ReadOutput for any URL.
    let site_handler: SiteHandler = Arc::new(|p: ReadParams, _fmt, start| {
        Box::pin(async move {
            Some(build_output(
                crate::content::ExtractedContent {
                    title: "site".into(),
                    content: "body".into(),
                    author: String::new(),
                    excerpt: String::new(),
                    length: 4,
                    json_ld: vec![],
                    og_image: String::new(),
                    meta: crate::content::ArticleMeta::default(),
                },
                &p,
                "site",
                elapsed(start),
            ))
        })
    });

    let handler_calls = Arc::new(AtomicUsize::new(0));
    let handler: Arc<dyn Handler> = Arc::new(OkHandler {
        calls: handler_calls.clone(),
    });
    let cfg = config_with(None, None);
    let http = HttpClient::with_handler(handler, cfg);

    let out = read_page_inner(&http, &params("https://example.com/page"), &[site_handler]).await;

    // The site_handler succeeded → success counter must have incremented.
    let after = FETCH_SUCCESS_TOTAL.load(Ordering::Relaxed);
    assert!(
        after >= before + 1,
        "fetch_success_total must increment on site_handler success (before={before}, after={after})"
    );

    // The underlying http.get handler must NOT have been called (site_handler short-circuits).
    assert_eq!(
        handler_calls.load(Ordering::SeqCst),
        0,
        "http.get() must not be called when site_handler returns Some"
    );

    assert!(out.error.is_none());
}

// ─── INTEGRATION TEST 4: fetch_success_total NOT incremented on site-handler error ─
//
// Confirms the guard `output.error.is_none()` is correct: a site_handler that
// returns an error output does NOT increment the success counter.
#[tokio::test]
async fn site_handler_error_does_not_increment_fetch_success_total() {
    use crate::metrics::FETCH_SUCCESS_TOTAL;

    // A site_handler that returns an error ReadOutput.
    let site_handler: SiteHandler = Arc::new(|p: ReadParams, _fmt, start| {
        Box::pin(async move {
            Some(build_error_output(
                &p,
                "site",
                elapsed(start),
                "simulated error",
            ))
        })
    });

    let before = FETCH_SUCCESS_TOTAL.load(Ordering::Relaxed);

    let handler_calls = Arc::new(AtomicUsize::new(0));
    let handler: Arc<dyn Handler> = Arc::new(OkHandler {
        calls: handler_calls.clone(),
    });
    let cfg = config_with(None, None);
    let http = HttpClient::with_handler(handler, cfg);

    let out = read_page_inner(&http, &params("https://example.com/page"), &[site_handler]).await;

    let after = FETCH_SUCCESS_TOTAL.load(Ordering::Relaxed);
    assert_eq!(
        after, before,
        "fetch_success_total must NOT increment when site_handler returns an error"
    );

    assert!(out.error.is_some());
}
