//! Minimal process-level metrics registry, rendered in Prometheus text format.
//!
//! ox-browser had no `/metrics` endpoint — the only fetch/fallback signal was a
//! `tracing::warn!` line you had to grep for. That made fallback-rate and
//! solver-giveup invisible to the operator and to Prometheus alerting.
//!
//! This module hand-rolls a handful of monotonic `AtomicU64` counters (the same
//! pattern already used by [`crate::proxy_fallback::PROXY_DIAL_FALLBACK_TOTAL`]) and a
//! [`render`] function that emits them in Prometheus exposition format. No
//! `prometheus` crate dependency — the counter set is tiny and fixed, so a
//! hand-rolled exporter keeps the dependency surface (and Docker build time) flat.
//!
//! All counters are RED-style (Rate, Errors, Duration-less) request counters.
//! Increment them at the relevant call sites via the `record_*` helpers.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::Result;
use crate::cloudflare::detect_cloudflare;
use crate::deadline::CallOutcome;
use crate::error::HttpError;
use crate::proxy_fallback::PROXY_DIAL_FALLBACK_TOTAL;
use crate::response::HttpResponse;

/// Total read-path attempts entering `read_page_inner` (`/read`, MCP `read`,
/// CLI `read`). Renamed from `oxbrowser_fetch_total` (issue #128): the old
/// name said "fetch" but the increment lived in `read_page_inner`, so
/// `POST /fetch` never touched it — a dashboard built on it looked like it
/// covered `/fetch` and did not. The fetch path is now covered by the
/// labelled `oxbrowser_fetch_outcome_total` counter, incremented in the
/// `/fetch` (and MCP `fetch`) handler — NOT here. These two counters have
/// no overlap.
pub static READ_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Fetch attempts that returned a usable HTTP 200 body.
pub static FETCH_SUCCESS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Times the request first attempted through *some* upstream proxy
/// (static, pool, residential, or per-request override).
pub static PROXY_USED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Times an HTTP 402 response was observed while the request was proxied.
/// Observation-only — a 402 relayed by a healthy forward proxy may have
/// originated at the origin (metered APIs, x402), so this counter does NOT
/// trigger degradation. The previous attribution heuristic that used this
/// counter as a fallback trigger has been removed (issue #90); a 402 now
/// surfaces to the caller unchanged.
pub static PROXY_402_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Times a per-request proxy URL (from `req.proxy` or the rotating pool) was
/// unparsable and the request failed closed instead of silently degrading to
/// direct. Each bump is also a `tracing::warn!` naming the reason — without
/// this counter the rejection is indistinguishable from any other
/// `InvalidUrl` error (issue: unobservable_enforcement).
pub static PROXY_ATTACH_INVALID_URL_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Times an upstream proxy was unreachable at the dial step (connect
/// refused / timeout / DNS / TLS handshake to the proxy host) for ANY target
/// scheme. This is the trigger condition for the dial-failure fallback, but
/// the fallback itself is gated more narrowly (HTTP targets + `max_redirects
/// == 0` only — see `proxy_fallback::looks_like_proxy_dial_failure`).
/// `HttpConfig::max_redirects` defaults to `10` and nothing in production
/// sets it to `0`, so under the default configuration
/// `oxbrowser_proxy_dial_fallback_total` stays at zero for ALL schemes — a
/// gap between the two counters is the normal state and not by itself
/// evidence about HTTPS (issue #86; tracking issue ox-browser#90).
pub static PROXY_DIAL_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Record a read-path attempt entering `read_page_inner` (any outcome).
/// Call once per top-level `/read` / MCP `read` / CLI `read`. Renamed from
/// `record_fetch` (issue #128) — see [`READ_TOTAL`].
pub fn record_read() {
    READ_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record a successful (HTTP 200, usable body) fetch.
pub fn record_fetch_success() {
    FETCH_SUCCESS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record that the first attempt routed through an upstream proxy.
pub fn record_proxy_used() {
    PROXY_USED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record an upstream-proxy HTTP 402 (observation-only — see [`PROXY_402_TOTAL`]).
pub fn record_proxy_402() {
    PROXY_402_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record that a per-request proxy URL was unparsable and the request failed
/// closed (issue: unobservable_enforcement). Each bump is also a
/// `tracing::warn!` in the handler.
pub fn record_proxy_attach_invalid_url() {
    PROXY_ATTACH_INVALID_URL_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record an upstream-proxy dial failure (proxy host unreachable) detected
/// for ANY target scheme. Mirrors [`record_proxy_402`]: counts the trigger
/// condition regardless of whether a direct fallback was wired/applied, so a
/// gap between this and `oxbrowser_proxy_dial_fallback_total` is visible.
pub fn record_proxy_dial() {
    PROXY_DIAL_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record a crawler dedup cap eviction (URL or content dedup hit its
/// `max_capacity` and dropped the eldest hash). Mirrors the
/// `record_solver_giveup` pattern.
pub fn record_crawler_dedup_evicted() {
    CRAWLER_DEDUP_EVICTED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record a frontier capacity drop (a URL was rejected because the frontier
/// was at `max_size`). Mirrors the `record_crawler_dedup_evicted` pattern.
pub fn record_frontier_dropped() {
    FRONTIER_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record a body-cap rejection (a response body exceeded the per-call byte
/// cap). Mirrors the `record_frontier_dropped` pattern — each bump is also
/// a `tracing::warn!` in `body_cap`.
pub fn record_body_cap_rejection() {
    BODY_CAP_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record a post-extraction sanity-gate rejection (the extracted subtree was
/// discarded and the whole document returned instead). Mirrors the
/// `record_body_cap_rejection` pattern — each bump is also a
/// `tracing::info!` in `content::extract_content` with the bounded
/// `reason` token, and the response carries the same token in
/// `ReadOutput::extraction_note`.
pub fn record_read_extraction_rejected() {
    READ_EXTRACTION_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

// ── Outbound in-flight gauge ───────────────────────────────────────────────
//
// Issue #128/#139: the mechanism that stops the service accumulating
// orphaned work is the per-call bound dropping the inner future. The gauge
// makes "did the abandoned request stop?" answerable from OUTSIDE: a scrape
// showing in-flight above baseline after a caller disconnect indicates
// orphaned work surviving its bound. Incremented/decremented only by the
// `deadline::bounded` seam (via `OutboundGuard`), so a surface that forgets
// the seam cannot forget the gauge.

/// Outbound fetch/read calls currently in flight (point-in-time, can go up
/// and down). Incremented on entry to `deadline::bounded` and decremented
/// on exit — including when the deadline fires and the inner future is
/// dropped. Covers all six outbound surfaces (the seam is the single
/// constructor).
pub static OUTBOUND_INFLIGHT: AtomicU64 = AtomicU64::new(0);

/// Increment the outbound in-flight gauge. Called only by the
/// `deadline::bounded` seam's `OutboundGuard`.
pub fn inc_outbound_inflight() {
    OUTBOUND_INFLIGHT.fetch_add(1, Ordering::Relaxed);
}

/// Decrement the outbound in-flight gauge. Called only by the
/// `deadline::bounded` seam's `OutboundGuard` (on drop, including when the
/// deadline fires).
pub fn dec_outbound_inflight() {
    OUTBOUND_INFLIGHT.fetch_sub(1, Ordering::Relaxed);
}

// ── /fetch outcome counter (labelled) ──────────────────────────────────────
//
// Issue #128: `/fetch` was unmetered. This counter is incremented in the
// `/fetch` (and MCP `fetch`) handler — NOT in `read_page_inner` — labelled
// by outcome so an operator can see the fetch failure mix (challenge vs
// upstream vs rate-limited vs the per-call bound) without grepping logs.
// Each label's doc below says exactly which branch increments it; a counter
// whose doc overstates what it observes has already bitten this repo
// (`oxbrowser_fetch_total`).

/// `/fetch` outcome `ok`: the call completed within the deadline and
/// returned a usable response with NO Cloudflare challenge detected and
/// status != 429. Incremented in the `/fetch` and MCP `fetch` handlers.
pub static FETCH_OUTCOME_OK: AtomicU64 = AtomicU64::new(0);
/// `/fetch` outcome `upstream_error`: the call completed within the deadline
/// but the upstream failed with a non-CF, non-429 error — a retryable 5xx
/// surfaced as `RetryableStatus` (after retry exhaust on idempotent
/// methods), a transport error, a wreq per-attempt timeout, or any other
/// non-CF `HttpError`. Distinct from `timeout` (the per-call bound fired).
pub static FETCH_OUTCOME_UPSTREAM_ERROR: AtomicU64 = AtomicU64::new(0);
/// `/fetch` outcome `challenge`: a Cloudflare challenge was detected —
/// either `detect_cloudflare` matched the returned response, or the chain
/// surfaced `HttpError::Cloudflare` (genuine CF markers) or
/// `HttpError::CloudflareInferred` (a bare 401/403/429/503 reclassified by
/// quality_check).
pub static FETCH_OUTCOME_CHALLENGE: AtomicU64 = AtomicU64::new(0);
/// `/fetch` outcome `rate_limited`: the upstream returned 429. Surfaces as
/// `Ok(resp{429})` for non-idempotent methods (POST/PATCH, not retried), or
/// as `Err(RetryableStatus(429))` for idempotent methods after the retry
/// loop exhausts its attempts.
pub static FETCH_OUTCOME_RATE_LIMITED: AtomicU64 = AtomicU64::new(0);
/// `/fetch` outcome `timeout`: the per-call deadline fired
/// (`CallOutcome::DeadlineExceeded`). This is the bound THIS change
/// introduced (issue #139) — distinct from a wreq per-attempt timeout
/// (`HttpError::Timeout`, classified `upstream_error`), which is the
/// per-attempt transport timeout that multiplies across retries.
pub static FETCH_OUTCOME_TIMEOUT: AtomicU64 = AtomicU64::new(0);

/// The five `oxbrowser_fetch_outcome_total` label rows, as a `&'static`
/// slice so [`render`] can borrow them for the labelled sample lines
/// without a temporary that drops at end-of-statement.
static FETCH_OUTCOME_ROWS: &[(&str, &AtomicU64)] = &[
    ("ok", &FETCH_OUTCOME_OK),
    ("upstream_error", &FETCH_OUTCOME_UPSTREAM_ERROR),
    ("challenge", &FETCH_OUTCOME_CHALLENGE),
    ("rate_limited", &FETCH_OUTCOME_RATE_LIMITED),
    ("timeout", &FETCH_OUTCOME_TIMEOUT),
];

/// `/fetch` outcome label. One variant per `oxbrowser_fetch_outcome_total`
/// label; [`classify_fetch_outcome`] is total — every branch of
/// `CallOutcome<Result<HttpResponse>>` maps to exactly one variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchOutcome {
    Ok,
    UpstreamError,
    Challenge,
    RateLimited,
    Timeout,
}

/// Record a `/fetch` outcome by incrementing the matching labelled counter.
/// Called in the `/fetch` and MCP `fetch` handlers after the bounded call
/// resolves.
pub fn record_fetch_outcome(o: FetchOutcome) {
    let c = match o {
        FetchOutcome::Ok => &FETCH_OUTCOME_OK,
        FetchOutcome::UpstreamError => &FETCH_OUTCOME_UPSTREAM_ERROR,
        FetchOutcome::Challenge => &FETCH_OUTCOME_CHALLENGE,
        FetchOutcome::RateLimited => &FETCH_OUTCOME_RATE_LIMITED,
        FetchOutcome::Timeout => &FETCH_OUTCOME_TIMEOUT,
    };
    c.fetch_add(1, Ordering::Relaxed);
}

/// Classify a bounded `/fetch` result into an outcome label. The mapping is
/// total and is the single source of truth for which counter increments on
/// which branch — the `/fetch` and MCP `fetch` handlers both call this so
/// the classification cannot drift between them.
///
/// - `DeadlineExceeded` → `Timeout` (the per-call bound, NOT a wreq
///   per-attempt timeout).
/// - `Ok(resp)` with `detect_cloudflare` match → `Challenge`.
/// - `Ok(resp)` with `status == 429` → `RateLimited`.
/// - `Ok(resp)` otherwise → `Ok`.
/// - `Err(Cloudflare | CloudflareInferred)` → `Challenge`.
/// - `Err(RetryableStatus(429))` → `RateLimited` (idempotent retry exhaust).
/// - `Err(_)` otherwise → `UpstreamError`.
pub fn classify_fetch_outcome(outcome: &CallOutcome<Result<HttpResponse>>) -> FetchOutcome {
    match outcome {
        CallOutcome::DeadlineExceeded { .. } => FetchOutcome::Timeout,
        CallOutcome::Ok(Ok(resp)) => {
            if detect_cloudflare(resp).is_some() {
                FetchOutcome::Challenge
            } else if resp.status == 429 {
                FetchOutcome::RateLimited
            } else {
                FetchOutcome::Ok
            }
        }
        CallOutcome::Ok(Err(e)) => match e {
            HttpError::Cloudflare(_, _, _) | HttpError::CloudflareInferred(_, _) => {
                FetchOutcome::Challenge
            }
            HttpError::RetryableStatus(429) => FetchOutcome::RateLimited,
            _ => FetchOutcome::UpstreamError,
        },
    }
}

/// One counter row in the registry: metric name, help text, current value.
struct Counter {
    name: &'static str,
    help: &'static str,
    value: u64,
}

/// One gauge row in the registry: metric name, help text, current value.
///
/// Gauges differ from counters in that they can go up *or* down — they snapshot
/// a point-in-time quantity (cache size, active-proxy count, tmpfs usage) rather
/// than a monotonic event count. The Prometheus exposition format distinguishes
/// them only by the `# TYPE … gauge` line, so [`render`] emits the same
/// `# HELP` / sample shape and flips the type marker.
struct Gauge {
    name: &'static str,
    help: &'static str,
    value: u64,
}

/// A labelled counter: one `# HELP` / `# TYPE counter` header, then one
/// sample line per `(label_value, counter)` row, emitted as
/// `name{<label>="<value>"} <n>`. The label dimension name (e.g.
/// `outcome`) is fixed in the help text — the renderer only needs the
/// value, so it is not carried per-row. Mirrors the hand-rolled
/// convention (no `prometheus` crate); the only addition over [`Counter`]
/// is the `{label="value"}` suffix on the sample line.
struct LabelledCounter {
    name: &'static str,
    help: &'static str,
    label: &'static str,
    rows: &'static [(&'static str, &'static AtomicU64)],
}

/// Cookie-cache entry count at scrape time (point-in-time, can shrink).
pub static COOKIE_CACHE_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Render-mode-cache entry count at scrape time (point-in-time, can shrink).
pub static RENDER_CACHE_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Crawler dedup (URL + content) entry count at scrape time (point-in-time,
/// can shrink). Sampled at crawl end by the crawler engine.
pub static CRAWLER_DEDUP_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// SSRF allowlist valid-entry count, set once at server startup by
/// [`crate::middleware_ssrf::validate_allowlist`]. A gauge (not a counter)
/// because it snapshots the parsed-and-validated allowlist size — it does not
/// grow monotonically. A scrape showing `0` when the operator expected entries
/// means the env var was unset; a startup failure (server refused to start)
/// means a private/metadata IP was caught by the guard.
pub static SSRF_ALLOWLIST_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Whether outbound proxy is disabled via `PROXY_DISABLED` (1) or not (0).
/// Set once at startup from `config::proxy_disabled()` in `src/serve.rs` so
/// operators scraping Prometheus can see the degraded state without grepping
/// logs (issue #27, silent_downgrade).
pub static PROXY_DISABLED: AtomicU64 = AtomicU64::new(0);

/// Whether a real CF solver is configured (1 = GoBrowser/Byparr, 0 = NoOp).
/// Set once at startup in `config::build_cookie_provider` so a silent
/// downgrade to the NoOpProvider — which only errors "no solver configured" at
/// solve time — is visible to Prometheus alerting (issue #29, silent_downgrade).
pub static SOLVER_CONFIGURED: AtomicU64 = AtomicU64::new(0);

/// Per-domain rate-limiter entry count at scrape time (point-in-time, can
/// shrink). Updated after each insert and after `evict_expired` sweeps stale
/// domains so operators can confirm bounded growth (issue #20,
/// resource_exhaustion).
pub static RATELIMIT_DOMAINS: AtomicU64 = AtomicU64::new(0);

/// Proxy-health tracker entry count at scrape time (point-in-time, can
/// shrink). Updated after each `record_success`/`record_failure` and after
/// `evict_stale` sweeps stale deactivated proxies so operators can confirm
/// the health map is bounded (issue #21, resource_exhaustion).
pub static PROXY_HEALTH_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Media tmpfs directory size in bytes at scrape time (point-in-time, can
/// shrink as cleanup removes old files). Updated before each download by
/// `ox_media::download::check_quota` so operators can see near-capacity
/// state and alert before tmpfs exhaustion (issue #30, resource_exhaustion).
pub static MEDIA_TMPFS_BYTES: AtomicU64 = AtomicU64::new(0);

/// Total crawler dedup entries evicted because the bounded set hit its
/// `max_capacity` cap. Monotonic counter — compare against
/// `oxbrowser_crawler_dedup_entries` to detect sustained cap pressure on
/// large crawls (issue #19).
pub static CRAWLER_DEDUP_EVICTED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Total URLs dropped because the crawl frontier was at capacity
/// (`Frontier::push` / `push_with_priority` returned `false`). Monotonic
/// counter — every drop is also `tracing::warn!`-logged with the
/// `frontier_full_drop` tag so operators can correlate log + metric (issue #24).
pub static FRONTIER_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Total responses rejected because the body exceeded the per-call byte cap
/// (issue #117, resource_exhaustion). Monotonic counter — each bump is also
/// a `tracing::warn!` in `body_cap` naming the limit and observed size. This
/// counts rejections from BOTH stages (the Content-Length header check and
/// the streaming running-total check), because an operator needs the
/// rejection rate regardless of which stage caught it — the header stage is
/// an optimisation, the stream stage is the guarantee, and both indicate the
/// same condition: an origin served a body larger than the configured cap.
/// Compare against `oxbrowser_read_total` to measure the read-path
/// cap-rejection rate (body_cap applies to the page-fetch surface, which
/// covers both the read path and `/fetch`; the read counter is the closer
/// denominator available without double-counting).
pub static BODY_CAP_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Times the post-extraction sanity gate rejected the extracted subtree and
/// `extract_content` fell back to the whole document (issue #110). The gate
/// fires when the source page's visible text is above an absolute floor AND
/// the extracted subtree's visible text is below a fixed fraction of the
/// source — the readability-style extractor picks a wrong container on
/// list/index pages (e.g. a hidden loading curtain) and discards the real
/// content. Each bump is also a `tracing::info!` with `reason=
/// extraction_rejected_low_text_ratio`, and the response carries the same
/// token in `ReadOutput::extraction_note`. Compare against
/// `oxbrowser_fetch_total` for the rejection rate; a sustained non-zero
/// rate on a given route means the extractor is mis-selecting on that site
/// shape (which the fallback masks, so this counter is the only signal).
pub static READ_EXTRACTION_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Set a gauge's value. Thin convenience wrapper so call sites don't have to
/// import `Ordering` — mirrors the ergonomics of the `record_*` counter helpers.
pub fn set_gauge(gauge: &AtomicU64, value: u64) {
    gauge.store(value, Ordering::Relaxed);
}

/// Snapshot every counter and render it in Prometheus text exposition format.
///
/// The output is a valid `text/plain; version=0.0.4` body: a `# HELP` line, a
/// `# TYPE … counter` line, and a sample line per metric. The
/// `oxbrowser_proxy_dial_fallback_total` series reuses the
/// [`PROXY_DIAL_FALLBACK_TOTAL`] counter so the dial-fallback event already
/// logged by [`crate::proxy_fallback::record_proxy_dial_fallback`] is now
/// scrapeable.
pub fn render() -> String {
    let counters = [
        Counter {
            name: "oxbrowser_read_total",
            help: "Total read-path attempts entering read_page_inner (/read, MCP read, CLI read). Renamed from oxbrowser_fetch_total (issue #128) — does NOT cover /fetch; use oxbrowser_fetch_outcome_total for the fetch path.",
            value: READ_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_fetch_success_total",
            help: "Read-path attempts that returned a usable HTTP 200 body (incremented in read_page_inner).",
            value: FETCH_SUCCESS_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_proxy_used_total",
            help: "Requests whose first attempt routed through an upstream proxy.",
            value: PROXY_USED_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_proxy_402_total",
            help: "HTTP 402 responses observed while proxied (observation-only — does NOT trigger degradation; see issue #90).",
            value: PROXY_402_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_proxy_attach_invalid_url_total",
            help: "Per-request proxy URLs that were unparsable and failed closed (not silently degraded to direct).",
            value: PROXY_ATTACH_INVALID_URL_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_proxy_dial_total",
            help: "Upstream-proxy dial failures (proxy host unreachable) detected for any target scheme.",
            value: PROXY_DIAL_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_proxy_dial_fallback_total",
            help: "Direct-connection fallbacks taken because the upstream proxy could not be dialled (HTTP targets + max_redirects==0 only; stays 0 under the shipped default max_redirects=10 — see issue #90).",
            value: PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_solver_giveup_total",
            help: "CF-solver give-ups (per-domain negative-cache short-circuit fired).",
            value: crate::solver_negcache::SOLVER_GIVEUP_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_crawler_dedup_evicted_total",
            help: "Crawler dedup entries evicted because the bounded set hit max_capacity.",
            value: CRAWLER_DEDUP_EVICTED_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_frontier_dropped_total",
            help: "URLs dropped because the crawl frontier was at capacity (push returned false).",
            value: FRONTIER_DROPPED_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_body_cap_rejections_total",
            help: "Responses rejected because the body exceeded the per-call byte cap (header or stream stage).",
            value: BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_read_extraction_rejected_total",
            help: "Reads where the post-extraction sanity gate rejected the extracted subtree (visible-text ratio below threshold) and fell back to the whole document (issue #110).",
            value: READ_EXTRACTION_REJECTED_TOTAL.load(Ordering::Relaxed),
        },
    ];

    // /fetch outcome — labelled by `outcome`. Incremented in the /fetch and
    // MCP fetch handlers (NOT in read_page_inner). One counter, five labels;
    // each label's branch is documented on the matching FETCH_OUTCOME_* static.
    let labelled = [LabelledCounter {
        name: "oxbrowser_fetch_outcome_total",
        help: "/fetch (and MCP fetch) outcomes, labelled by outcome. Incremented in the fetch handler, not the read pipeline. Labels: ok, upstream_error, challenge, rate_limited, timeout (the per-call bound, distinct from a wreq per-attempt timeout).",
        label: "outcome",
        rows: FETCH_OUTCOME_ROWS,
    }];

    let gauges = [
        Gauge {
            name: "oxbrowser_outbound_inflight",
            help: "Outbound fetch/read calls currently in flight (point-in-time, can go down). Inc/dec by the deadline::bounded seam; a value above baseline after a caller disconnect indicates orphaned work surviving its bound (issues #128/#139).",
            value: OUTBOUND_INFLIGHT.load(Ordering::Relaxed),
        },
        Gauge {
            name: "oxbrowser_cookie_cache_entries",
            help: "Cookie-cache entry count at scrape time (point-in-time, can shrink).",
            value: COOKIE_CACHE_ENTRIES.load(Ordering::Relaxed),
        },
        Gauge {
            name: "oxbrowser_render_cache_entries",
            help: "Render-mode-cache entry count at scrape time (point-in-time, can shrink).",
            value: RENDER_CACHE_ENTRIES.load(Ordering::Relaxed),
        },
        Gauge {
            name: "oxbrowser_crawler_dedup_entries",
            help: "Crawler dedup (URL + content) entry count at scrape time (point-in-time, can shrink).",
            value: CRAWLER_DEDUP_ENTRIES.load(Ordering::Relaxed),
        },
        Gauge {
            name: "oxbrowser_ssrf_allowlist_entries",
            help: "SSRF allowlist valid-entry count (set at startup; 0 = unset, startup failure = private/metadata IP caught).",
            value: SSRF_ALLOWLIST_ENTRIES.load(Ordering::Relaxed),
        },
        Gauge {
            name: "oxbrowser_proxy_disabled",
            help: "1 if outbound proxy is disabled (PROXY_DISABLED env set), 0 otherwise.",
            value: PROXY_DISABLED.load(Ordering::Relaxed),
        },
        Gauge {
            name: "oxbrowser_solver_configured",
            help: "1 if a real CF solver is configured (GoBrowser/Byparr), 0 if NoOpProvider (no solver).",
            value: SOLVER_CONFIGURED.load(Ordering::Relaxed),
        },
        Gauge {
            name: "oxbrowser_ratelimit_domains",
            help: "Per-domain rate-limiter entry count at scrape time (point-in-time, can shrink).",
            value: RATELIMIT_DOMAINS.load(Ordering::Relaxed),
        },
        Gauge {
            name: "oxbrowser_proxy_health_entries",
            help: "Proxy-health tracker entry count at scrape time (point-in-time, can shrink).",
            value: PROXY_HEALTH_ENTRIES.load(Ordering::Relaxed),
        },
        Gauge {
            name: "oxbrowser_media_tmpfs_bytes",
            help: "Media tmpfs directory size in bytes at scrape time (point-in-time, can shrink).",
            value: MEDIA_TMPFS_BYTES.load(Ordering::Relaxed),
        },
    ];

    let mut out = String::with_capacity((counters.len() + gauges.len()) * 160);
    for c in &counters {
        out.push_str("# HELP ");
        out.push_str(c.name);
        out.push(' ');
        out.push_str(c.help);
        out.push('\n');
        out.push_str("# TYPE ");
        out.push_str(c.name);
        out.push_str(" counter\n");
        out.push_str(c.name);
        out.push(' ');
        out.push_str(&c.value.to_string());
        out.push('\n');
    }
    for lc in &labelled {
        out.push_str("# HELP ");
        out.push_str(lc.name);
        out.push(' ');
        out.push_str(lc.help);
        out.push('\n');
        out.push_str("# TYPE ");
        out.push_str(lc.name);
        out.push_str(" counter\n");
        for (value, counter) in lc.rows {
            out.push_str(lc.name);
            out.push('{');
            out.push_str(lc.label);
            out.push_str("=\"");
            out.push_str(value);
            out.push_str("\"} ");
            out.push_str(&counter.load(Ordering::Relaxed).to_string());
            out.push('\n');
        }
    }
    for g in &gauges {
        out.push_str("# HELP ");
        out.push_str(g.name);
        out.push(' ');
        out.push_str(g.help);
        out.push('\n');
        out.push_str("# TYPE ");
        out.push_str(g.name);
        out.push_str(" gauge\n");
        out.push_str(g.name);
        out.push(' ');
        out.push_str(&g.value.to_string());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex;

    /// Gauge-publishing tests read/write the shared process-global `PROXY_DISABLED`
    /// static. When run in parallel they race on that atomic, producing flaky
    /// assertions. This mutex serializes them so the gauge value is deterministic
    /// within each test — mirrors the T2 render_cache gauge test pattern.
    ///
    /// `tokio::sync::Mutex` (not `std::sync`): the two `bounded` gauge tests
    /// hold the guard across an `.await` on the in-flight gauge, and a
    /// `std::sync::MutexGuard` is not `Send` — clippy `await_holding_lock`
    /// flags it, and on a single-threaded runtime a second task blocking on
    /// the same lock would deadlock rather than yield. The sync tests use
    /// `blocking_lock()` (the documented way to acquire a tokio mutex from
    /// non-async code).
    static GAUGE_TEST_LOCK: Mutex<()> = Mutex::const_new(());

    #[test]
    fn render_emits_gauge_series_in_prometheus_format() {
        // Set a known gauge value and confirm render() emits the gauge TYPE
        // marker plus a matching sample line — the RED test for gauge support.
        set_gauge(&COOKIE_CACHE_ENTRIES, 42);
        let body = render();
        assert!(
            body.contains("# TYPE oxbrowser_cookie_cache_entries gauge"),
            "missing gauge TYPE line: {body}"
        );
        assert!(
            body.lines()
                .any(|l| l == "oxbrowser_cookie_cache_entries 42"),
            "missing/incorrect gauge sample line: {body}"
        );
    }

    #[test]
    fn render_emits_all_series_in_prometheus_format() {
        let body = render();
        for series in [
            "oxbrowser_read_total",
            "oxbrowser_fetch_success_total",
            "oxbrowser_proxy_used_total",
            "oxbrowser_proxy_402_total",
            "oxbrowser_proxy_attach_invalid_url_total",
            "oxbrowser_proxy_dial_total",
            "oxbrowser_proxy_dial_fallback_total",
            "oxbrowser_solver_giveup_total",
            "oxbrowser_crawler_dedup_evicted_total",
            "oxbrowser_frontier_dropped_total",
            "oxbrowser_body_cap_rejections_total",
            "oxbrowser_read_extraction_rejected_total",
        ] {
            assert!(
                body.contains(&format!("# TYPE {series} counter")),
                "missing TYPE line for {series}"
            );
            assert!(
                body.lines().any(|l| l.starts_with(&format!("{series} "))),
                "missing sample line for {series}"
            );
        }
        // The labelled /fetch outcome counter: one TYPE line, five labelled
        // sample lines.
        assert!(
            body.contains("# TYPE oxbrowser_fetch_outcome_total counter"),
            "missing TYPE line for oxbrowser_fetch_outcome_total: {body}"
        );
        for label in [
            "ok",
            "upstream_error",
            "challenge",
            "rate_limited",
            "timeout",
        ] {
            assert!(
                body.lines().any(|l| l.starts_with(&format!(
                    "oxbrowser_fetch_outcome_total{{outcome=\"{label}\"}} "
                ))),
                "missing labelled sample line for outcome={label}: {body}"
            );
        }
        for series in [
            "oxbrowser_outbound_inflight",
            "oxbrowser_cookie_cache_entries",
            "oxbrowser_render_cache_entries",
            "oxbrowser_crawler_dedup_entries",
            "oxbrowser_ssrf_allowlist_entries",
        ] {
            assert!(
                body.contains(&format!("# TYPE {series} gauge")),
                "missing gauge TYPE line for {series}"
            );
            assert!(
                body.lines().any(|l| l.starts_with(&format!("{series} "))),
                "missing gauge sample line for {series}"
            );
        }
    }

    #[test]
    fn record_helpers_increment_their_series() {
        let before = READ_TOTAL.load(Ordering::Relaxed);
        record_read();
        assert_eq!(READ_TOTAL.load(Ordering::Relaxed), before + 1);
    }

    /// Verify render() reads solver_negcache::SOLVER_GIVEUP_TOTAL (the live counter),
    /// not a dead local copy. Fails RED if the render() line is reverted to a local atomic.
    #[test]
    fn render_giveup_reads_solver_negcache_counter() {
        let before = crate::solver_negcache::SOLVER_GIVEUP_TOTAL.load(Ordering::Relaxed);
        crate::solver_negcache::record_solver_giveup("test.example");
        let after = crate::solver_negcache::SOLVER_GIVEUP_TOTAL.load(Ordering::Relaxed);
        assert_eq!(
            after,
            before + 1,
            "solver_negcache counter did not increment"
        );

        // render() must reflect the updated counter.
        let body = render();
        let expected_line = format!("oxbrowser_solver_giveup_total {after}");
        assert!(
            body.lines().any(|l| l == expected_line),
            "render() does not reflect solver_negcache::SOLVER_GIVEUP_TOTAL; line not found: {expected_line}"
        );
    }

    /// RED test for issue #27: render() must emit `oxbrowser_proxy_disabled`
    /// reflecting the gauge value so operators scraping Prometheus can see the
    /// PROXY_DISABLED degraded state. With the gauge set to 1 (proxy disabled),
    /// render() emits `oxbrowser_proxy_disabled 1`; with 0, it emits `… 0`.
    #[test]
    fn render_emits_proxy_disabled_gauge() {
        let _guard = GAUGE_TEST_LOCK.blocking_lock();

        // Proxy disabled → gauge 1 → render shows "oxbrowser_proxy_disabled 1"
        set_gauge(&PROXY_DISABLED, 1);
        let body = render();
        assert!(
            body.contains("# TYPE oxbrowser_proxy_disabled gauge"),
            "missing gauge TYPE line: {body}"
        );
        assert!(
            body.lines().any(|l| l == "oxbrowser_proxy_disabled 1"),
            "missing/incorrect gauge sample line (expected 1): {body}"
        );

        // Proxy enabled → gauge 0 → render shows "oxbrowser_proxy_disabled 0"
        set_gauge(&PROXY_DISABLED, 0);
        let body = render();
        assert!(
            body.lines().any(|l| l == "oxbrowser_proxy_disabled 0"),
            "missing/incorrect gauge sample line (expected 0): {body}"
        );

        // Reset to avoid leaking state into other tests.
        set_gauge(&PROXY_DISABLED, 0);
    }

    /// RED test for issue #29: render() must emit `oxbrowser_solver_configured`
    /// reflecting whether a real CF solver (GoBrowser/Byparr) is configured (1)
    /// or the NoOpProvider fallback is in effect (0). Set by
    /// `config::build_cookie_provider` at startup.
    #[test]
    fn render_emits_solver_configured_gauge() {
        let _guard = GAUGE_TEST_LOCK.blocking_lock();

        // Real solver configured → gauge 1
        set_gauge(&SOLVER_CONFIGURED, 1);
        let body = render();
        assert!(
            body.contains("# TYPE oxbrowser_solver_configured gauge"),
            "missing gauge TYPE line: {body}"
        );
        assert!(
            body.lines().any(|l| l == "oxbrowser_solver_configured 1"),
            "missing/incorrect gauge sample line (expected 1): {body}"
        );

        // NoOp fallback → gauge 0
        set_gauge(&SOLVER_CONFIGURED, 0);
        let body = render();
        assert!(
            body.lines().any(|l| l == "oxbrowser_solver_configured 0"),
            "missing/incorrect gauge sample line (expected 0): {body}"
        );

        // Reset to avoid leaking state into other tests.
        set_gauge(&SOLVER_CONFIGURED, 0);
    }

    /// RED test for issue #20: render() must emit
    /// `oxbrowser_ratelimit_domains` reflecting the per-domain rate-limiter
    /// entry count so operators can confirm bounded growth. Set after each
    /// insert and after `evict_expired` sweeps stale domains.
    #[test]
    fn render_emits_ratelimit_domains_gauge() {
        let _guard = GAUGE_TEST_LOCK.blocking_lock();

        // One domain tracked → gauge 1
        set_gauge(&RATELIMIT_DOMAINS, 1);
        let body = render();
        assert!(
            body.contains("# TYPE oxbrowser_ratelimit_domains gauge"),
            "missing gauge TYPE line: {body}"
        );
        assert!(
            body.lines().any(|l| l == "oxbrowser_ratelimit_domains 1"),
            "missing/incorrect gauge sample line (expected 1): {body}"
        );

        // No domains tracked → gauge 0
        set_gauge(&RATELIMIT_DOMAINS, 0);
        let body = render();
        assert!(
            body.lines().any(|l| l == "oxbrowser_ratelimit_domains 0"),
            "missing/incorrect gauge sample line (expected 0): {body}"
        );

        // Reset to avoid leaking state into other tests.
        set_gauge(&RATELIMIT_DOMAINS, 0);
    }

    /// RED test for issue #30: render() must emit `oxbrowser_media_tmpfs_bytes`
    /// reflecting the media tmpfs directory size so operators can see
    /// near-capacity state and alert before tmpfs exhaustion. Set before each
    /// download by `ox_media::download::check_quota`.
    #[test]
    fn render_emits_media_tmpfs_bytes_gauge() {
        let _guard = GAUGE_TEST_LOCK.blocking_lock();

        set_gauge(&MEDIA_TMPFS_BYTES, 1_500_000_000);
        let body = render();
        assert!(
            body.contains("# TYPE oxbrowser_media_tmpfs_bytes gauge"),
            "missing gauge TYPE line: {body}"
        );
        assert!(
            body.lines()
                .any(|l| l == "oxbrowser_media_tmpfs_bytes 1500000000"),
            "missing/incorrect gauge sample line: {body}"
        );

        // Reset to avoid leaking state into other tests.
        set_gauge(&MEDIA_TMPFS_BYTES, 0);
    }

    // ── /fetch outcome classifier tests (issue #128) ──────────────────────

    use crate::cloudflare::ChallengeType;
    use crate::deadline::CallOutcome;
    use crate::error::HttpError;
    use crate::response::HttpResponse;
    use std::time::Duration;
    use wreq::header::HeaderMap;

    fn ok_resp(status: u16) -> HttpResponse {
        HttpResponse {
            status,
            url: "https://x.test".into(),
            headers: HeaderMap::new(),
            body: String::new(),
        }
    }

    #[test]
    fn classify_ok_response() {
        let outcome: CallOutcome<Result<HttpResponse>> = CallOutcome::Ok(Ok(ok_resp(200)));
        assert_eq!(classify_fetch_outcome(&outcome), FetchOutcome::Ok);
    }

    #[test]
    fn classify_deadline_exceeded_as_timeout() {
        let outcome: CallOutcome<Result<HttpResponse>> = CallOutcome::DeadlineExceeded { secs: 8 };
        assert_eq!(classify_fetch_outcome(&outcome), FetchOutcome::Timeout);
    }

    #[test]
    fn classify_429_response_as_rate_limited() {
        let outcome: CallOutcome<Result<HttpResponse>> = CallOutcome::Ok(Ok(ok_resp(429)));
        assert_eq!(classify_fetch_outcome(&outcome), FetchOutcome::RateLimited);
    }

    #[test]
    fn classify_retryable_429_error_as_rate_limited() {
        let outcome: CallOutcome<Result<HttpResponse>> =
            CallOutcome::Ok(Err(HttpError::RetryableStatus(429)));
        assert_eq!(classify_fetch_outcome(&outcome), FetchOutcome::RateLimited);
    }

    #[test]
    fn classify_cloudflare_error_as_challenge() {
        let outcome: CallOutcome<Result<HttpResponse>> = CallOutcome::Ok(Err(
            HttpError::Cloudflare(ChallengeType::JsChallenge, 403, "ray-id".into()),
        ));
        assert_eq!(classify_fetch_outcome(&outcome), FetchOutcome::Challenge);
    }

    #[test]
    fn classify_inferred_cloudflare_as_challenge() {
        let outcome: CallOutcome<Result<HttpResponse>> = CallOutcome::Ok(Err(
            HttpError::CloudflareInferred(403, Box::new(ok_resp(403))),
        ));
        assert_eq!(classify_fetch_outcome(&outcome), FetchOutcome::Challenge);
    }

    #[test]
    fn classify_generic_error_as_upstream_error() {
        let outcome: CallOutcome<Result<HttpResponse>> =
            CallOutcome::Ok(Err(HttpError::Timeout(Duration::from_secs(20))));
        assert_eq!(
            classify_fetch_outcome(&outcome),
            FetchOutcome::UpstreamError
        );
    }

    #[test]
    fn classify_5xx_retryable_as_upstream_error() {
        let outcome: CallOutcome<Result<HttpResponse>> =
            CallOutcome::Ok(Err(HttpError::RetryableStatus(503)));
        assert_eq!(
            classify_fetch_outcome(&outcome),
            FetchOutcome::UpstreamError
        );
    }

    // ── in-flight gauge test (issue #128/#139) ────────────────────────────

    /// `bounded` increments the in-flight gauge on entry and decrements on
    /// exit — including when the deadline fires. This test verifies the
    /// gauge returns to its baseline after a bounded call completes, so a
    /// scrape showing in-flight above baseline after a caller disconnect
    /// indicates orphaned work surviving its bound.
    ///
    /// Serialized with `GAUGE_TEST_LOCK` because the gauge is a global
    /// atomic and parallel `bounded` calls from the deadline-exceeded test
    /// would race the baseline read.
    #[tokio::test]
    async fn outbound_inflight_gauge_returns_to_baseline_after_bounded_call() {
        let _guard = GAUGE_TEST_LOCK.lock().await;
        let baseline = OUTBOUND_INFLIGHT.load(Ordering::Relaxed);
        let outcome: CallOutcome<u32> =
            crate::deadline::bounded(Duration::from_secs(5), async { 42 }).await;
        assert!(matches!(outcome, CallOutcome::Ok(42)));
        assert_eq!(
            OUTBOUND_INFLIGHT.load(Ordering::Relaxed),
            baseline,
            "gauge must return to baseline after call completes"
        );
    }

    /// The gauge must also decrement when the deadline fires (the inner
    /// future is dropped) — the orphaned-work detection depends on it.
    ///
    /// Serialized with `GAUGE_TEST_LOCK` — same reason as the ok-path test.
    #[tokio::test]
    async fn outbound_inflight_gauge_decrements_on_deadline_exceeded() {
        let _guard = GAUGE_TEST_LOCK.lock().await;
        let baseline = OUTBOUND_INFLIGHT.load(Ordering::Relaxed);
        let outcome: CallOutcome<()> = crate::deadline::bounded(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(2)).await;
        })
        .await;
        assert!(matches!(outcome, CallOutcome::DeadlineExceeded { .. }));
        assert_eq!(
            OUTBOUND_INFLIGHT.load(Ordering::Relaxed),
            baseline,
            "gauge must return to baseline even when deadline fires"
        );
    }
}
