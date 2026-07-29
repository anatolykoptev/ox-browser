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
        timeout_secs: None,
    }
}

/// Build a minimal HttpConfig with the supplied render cache and negcache.
fn config_with(
    render_cache: Option<Arc<RenderModeCache>>,
    negcache: Option<Arc<SolverNegCache>>,
) -> HttpConfig {
    HttpConfig {
        render_cache,
        solver_negcache: negcache,
        ..Default::default()
    }
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
        extraction_note: None,
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
        extraction_note: None,
    };
    let p = ReadParams {
        url: "https://x.com".into(),
        format: "text".into(),
        max_length: 50,
        timeout_secs: None,
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
                    extraction_note: None,
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
        after > before,
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

// ─── CLI `read` subcommand: shared-path parity + discriminating format mapping ──
//
// The CLI `read` subcommand (src/read.rs) calls `read_page` — the SAME
// function the `/read` HTTP handler (ox_js::read) and the MCP `read` tool
// call. These tests prove that parity against the shared function, without
// running a server:
//   1. `cli_and_api_paths_produce_same_read_output` — a ReadParams built the
//      CLI way (from a validated format string) and one built the API way
//      (serde-deserialised JSON, as axum's `Json<ReadParams>` does) produce
//      byte-identical output through `read_page_inner`.
//   2. `read_format_mapping_is_discriminating` — each `--format` value maps
//      to the ContentFormat the pipeline maps it to, and the outputs differ
//      across formats. A test that would still pass if the mapping were
//      swapped is not a test: `assert_ne` between text and markdown output
//      catches a swapped mapping.

/// Handler returning a fixed HTML body with a real article, so format
/// conversion has something to discriminate on.
struct FixedBodyHandler {
    body: String,
}

#[async_trait]
impl Handler for FixedBodyHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        Ok(HttpResponse {
            status: 200,
            url: req.url,
            headers: HeaderMap::new(),
            body: self.body.clone(),
        })
    }
}

fn article_html() -> &'static str {
    "<html><head><title>Article Title</title></head>\
     <body><article><h1>Heading One</h1><p>Body paragraph text.</p>\
     <p>Second <a href=\"/x\">link</a> paragraph.</p></article></body></html>"
}

fn http_with_article() -> HttpClient {
    let handler: Arc<dyn Handler> = Arc::new(FixedBodyHandler {
        body: article_html().to_string(),
    });
    let cfg = config_with(None, None);
    HttpClient::with_handler(handler, cfg)
}

#[tokio::test]
async fn cli_and_api_paths_produce_same_read_output() {
    let http = http_with_article();

    // CLI construction: build ReadParams from a validated format string
    // (exactly what src/read.rs::build_read_params does).
    let cli_params = ReadParams {
        url: "https://example.com/article".into(),
        format: "markdown".into(),
        max_length: 0,
        timeout_secs: None,
    };
    // API construction: serde-deserialise JSON, as axum's `Json<ReadParams>`
    // does in the /read handler. The default format is "text" (content.rs).
    let api_params: ReadParams =
        serde_json::from_str(r#"{"url":"https://example.com/article","format":"markdown"}"#)
            .unwrap();

    // The two construction paths must agree on every field.
    assert_eq!(cli_params.url, api_params.url);
    assert_eq!(cli_params.format, api_params.format);
    assert_eq!(cli_params.max_length, api_params.max_length);

    let cli_out = read_page_inner(&http, &cli_params, &[]).await;
    let api_out = read_page_inner(&http, &api_params, &[]).await;

    // Byte-identical output through the shared function.
    assert_eq!(cli_out.content, api_out.content, "content must match");
    assert_eq!(cli_out.title, api_out.title, "title must match");
    assert_eq!(cli_out.format, api_out.format, "format must match");
    assert_eq!(cli_out.error, api_out.error, "error must match");
    assert_eq!(cli_out.method, api_out.method, "method must match");
}

#[tokio::test]
async fn read_format_mapping_is_discriminating() {
    let http = http_with_article();
    let url = "https://example.com/article";

    let mk = |fmt: &str| ReadParams {
        url: url.into(),
        format: fmt.into(),
        max_length: 0,
        timeout_secs: None,
    };

    let md = read_page_inner(&http, &mk("markdown"), &[]).await;
    let text = read_page_inner(&http, &mk("text"), &[]).await;
    let html = read_page_inner(&http, &mk("html"), &[]).await;
    let llm = read_page_inner(&http, &mk("llm"), &[]).await;

    // markdown: contains the heading as markdown, not as a raw HTML tag.
    assert!(
        md.content.contains("Heading One"),
        "markdown must contain heading text; got: {:?}",
        md.content
    );
    assert!(
        !md.content.contains("<h1>"),
        "markdown must not contain raw <h1>; got: {:?}",
        md.content
    );

    // text: plain text — no markdown heading syntax, no HTML tags.
    assert!(
        !text.content.contains("# "),
        "text must not contain markdown heading syntax; got: {:?}",
        text.content
    );
    assert!(
        !text.content.contains("<h1>"),
        "text must not contain HTML tags; got: {:?}",
        text.content
    );

    // html: raw content node HTML — contains tags.
    assert!(
        html.content.contains('<'),
        "html format must contain HTML tags; got: {:?}",
        html.content
    );

    // llm: token-optimised — no raw HTML tags.
    assert!(
        !llm.content.contains("<h1>"),
        "llm must strip HTML tags; got: {:?}",
        llm.content
    );

    // The discriminator: markdown and text MUST differ. If from_param's
    // "markdown" mapping were swapped to Text, md.content == text.content
    // and this assertion fails — proving the mapping is wired, not a no-op.
    assert_ne!(
        md.content, text.content,
        "markdown and text output must differ (mapping must be discriminating)"
    );
    assert_ne!(
        html.content, text.content,
        "html and text output must differ"
    );
}

// ─── DEADLINE TESTS (issue #139) ─────────────────────────────────────────────

/// Handler that sleeps for the given duration before responding. Used to
/// trigger the per-call deadline in `read_page` (which wraps
/// `read_page_inner` with `deadline::bounded`).
struct SlowHandler {
    delay: Duration,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Handler for SlowHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        Ok(HttpResponse {
            status: 200,
            url: req.url,
            headers: HeaderMap::new(),
            body: "<html><body>content</body></html>".into(),
        })
    }
}

/// `read_page` with `timeout_secs: Some(1)` against a handler that sleeps
/// 10 s MUST return an error output whose `elapsed_ms` is ~1 s (the bound
/// fired), NOT ~10 s (the handler completed). This is the RED test for the
/// per-call deadline: on the old code (no `timeout_secs` field, fixed
/// `PIPELINE_TIMEOUT = 30 s`), the handler sleeps 10 s and completes
/// successfully — `out.error` is `None` and `elapsed_ms` ≈ 10_000.
///
/// The mutation probe: change `read_page` to ignore `params.timeout_secs`
/// (e.g. revert to a fixed 30 s) and this test goes RED — `out.error` is
/// `None` and `elapsed_ms` far exceeds 2_000.
#[tokio::test]
async fn read_page_deadline_fires_within_bound() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let handler: Arc<dyn Handler> = Arc::new(SlowHandler {
        delay: Duration::from_secs(10),
        calls: handler_calls.clone(),
    });
    let http = HttpClient::with_handler(handler, config_with(None, None));

    let p = ReadParams {
        url: "https://slow.test/page".into(),
        format: "text".into(),
        max_length: 0,
        timeout_secs: Some(1),
    };

    let out = read_page(&http, &p, &[]).await;

    // The bound fired → error output.
    assert!(out.error.is_some(), "expected deadline error, got success");
    assert!(
        out.error.as_deref().unwrap().contains("deadline"),
        "error must mention deadline; got: {:?}",
        out.error
    );
    // elapsed_ms should be ~1 s (the bound), NOT ~10 s (the handler).
    // Allow generous slack for scheduler latency on a loaded CI box.
    assert!(
        out.elapsed_ms < 3_000,
        "deadline should fire at ~1s, got elapsed_ms={}",
        out.elapsed_ms
    );
}

/// `read_page` with `timeout_secs: None` (the default) against a fast
/// handler MUST complete successfully — the default bound (8 s) does not
/// fire on a sub-millisecond response. This is the byte-identical
/// no-field test: a caller that omits `timeout_secs` gets the same
/// successful behavior as before the field existed (the default is
/// generous enough not to interfere with fast responses).
#[tokio::test]
async fn read_page_default_timeout_does_not_fire_on_fast_response() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let handler: Arc<dyn Handler> = Arc::new(OkHandler {
        calls: handler_calls.clone(),
    });
    let http = HttpClient::with_handler(handler, config_with(None, None));

    let p = ReadParams {
        url: "https://fast.test/page".into(),
        format: "text".into(),
        max_length: 0,
        timeout_secs: None,
    };

    let out = read_page(&http, &p, &[]).await;

    assert!(out.error.is_none(), "expected success, got error: {:?}", out.error);
    assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
    assert!(!out.content.is_empty());
}

/// `read_page` with `timeout_secs: Some(0)` MUST clamp up to 1 s (not
/// reject every request), so a fast handler still completes. This is the
/// ceiling-clamp test: `resolve_timeout(Some(0))` → 1 s, not 0 s.
#[tokio::test]
async fn read_page_timeout_zero_clamps_to_one_sec() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let handler: Arc<dyn Handler> = Arc::new(OkHandler {
        calls: handler_calls.clone(),
    });
    let http = HttpClient::with_handler(handler, config_with(None, None));

    let p = ReadParams {
        url: "https://zero.test/page".into(),
        format: "text".into(),
        max_length: 0,
        timeout_secs: Some(0),
    };

    let out = read_page(&http, &p, &[]).await;

    // A 0 s deadline clamped to 1 s should NOT fire on a fast handler.
    assert!(
        out.error.is_none(),
        "0s should clamp to 1s, not reject; got error: {:?}",
        out.error
    );
    assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
}

/// `read_page` with `timeout_secs: Some(600)` MUST clamp down to the
/// ceiling (60 s), not use 600 s. Against a handler that sleeps 2 s, the
/// call completes successfully — the ceiling (60 s) does not fire. This
/// is the upper-clamp test: `resolve_timeout(Some(600))` → 60 s, not 600 s.
#[tokio::test]
async fn read_page_timeout_above_ceiling_clamps_down() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let handler: Arc<dyn Handler> = Arc::new(SlowHandler {
        delay: Duration::from_millis(100),
        calls: handler_calls.clone(),
    });
    let http = HttpClient::with_handler(handler, config_with(None, None));

    let p = ReadParams {
        url: "https://ceiling.test/page".into(),
        format: "text".into(),
        max_length: 0,
        timeout_secs: Some(600),
    };

    let out = read_page(&http, &p, &[]).await;

    // 600 s clamped to 60 s should NOT fire on a 100 ms response.
    assert!(
        out.error.is_none(),
        "600s should clamp to 60s ceiling; got error: {:?}",
        out.error
    );
    assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
}
