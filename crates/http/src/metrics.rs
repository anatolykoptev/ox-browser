//! Minimal process-level metrics registry, rendered in Prometheus text format.
//!
//! ox-browser had no `/metrics` endpoint — the only fetch/fallback signal was a
//! `tracing::warn!` line you had to grep for. That made fallback-rate and
//! solver-giveup invisible to the operator and to Prometheus alerting.
//!
//! This module hand-rolls a handful of monotonic `AtomicU64` counters (the same
//! pattern already used by [`crate::proxy_fallback::PROXY_FALLBACK_TOTAL`]) and a
//! [`render`] function that emits them in Prometheus exposition format. No
//! `prometheus` crate dependency — the counter set is tiny and fixed, so a
//! hand-rolled exporter keeps the dependency surface (and Docker build time) flat.
//!
//! All counters are RED-style (Rate, Errors, Duration-less) request counters.
//! Increment them at the relevant call sites via the `record_*` helpers.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::proxy_fallback::PROXY_FALLBACK_TOTAL;

/// Total fetch attempts entering the read/fetch path (any outcome).
pub static FETCH_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Fetch attempts that returned a usable HTTP 200 body.
pub static FETCH_SUCCESS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Times the request first attempted through *some* upstream proxy
/// (static, pool, residential, or per-request override).
pub static PROXY_USED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Times an upstream proxy surfaced an HTTP 402 (Webshare quota / billing).
/// This is the trigger condition for the direct-connection fallback; compare
/// against `oxbrowser_proxy_fallback_total` to confirm every 402 degraded.
pub static PROXY_402_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Record a fetch attempt (any outcome). Call once per top-level fetch/read.
pub fn record_fetch() {
    FETCH_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record a successful (HTTP 200, usable body) fetch.
pub fn record_fetch_success() {
    FETCH_SUCCESS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record that the first attempt routed through an upstream proxy.
pub fn record_proxy_used() {
    PROXY_USED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record an upstream-proxy HTTP 402 (quota exhausted).
pub fn record_proxy_402() {
    PROXY_402_TOTAL.fetch_add(1, Ordering::Relaxed);
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

/// Cookie-cache entry count at scrape time (point-in-time, can shrink).
pub static COOKIE_CACHE_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Render-mode-cache entry count at scrape time (point-in-time, can shrink).
pub static RENDER_CACHE_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Crawler dedup (URL + content) entry count at scrape time (point-in-time,
/// can shrink). Sampled at crawl end by the crawler engine.
pub static CRAWLER_DEDUP_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Whether outbound proxy is disabled via `PROXY_DISABLED` (1) or not (0).
/// Set once at startup from `config::proxy_disabled()` in `src/serve.rs` so
/// operators scraping Prometheus can see the degraded state without grepping
/// logs (issue #27, silent_downgrade).
pub static PROXY_DISABLED: AtomicU64 = AtomicU64::new(0);

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

/// Set a gauge's value. Thin convenience wrapper so call sites don't have to
/// import `Ordering` — mirrors the ergonomics of the `record_*` counter helpers.
pub fn set_gauge(gauge: &AtomicU64, value: u64) {
    gauge.store(value, Ordering::Relaxed);
}

/// Snapshot every counter and render it in Prometheus text exposition format.
///
/// The output is a valid `text/plain; version=0.0.4` body: a `# HELP` line, a
/// `# TYPE … counter` line, and a sample line per metric. The
/// `oxbrowser_proxy_fallback_total` series reuses the long-standing
/// [`PROXY_FALLBACK_TOTAL`] counter so the fallback event already logged by
/// [`crate::proxy_fallback::record_webshare_402_fallback`] is now scrapeable.
pub fn render() -> String {
    let counters = [
        Counter {
            name: "oxbrowser_fetch_total",
            help: "Total read-path attempts entering read_page_inner (/read and MCP read).",
            value: FETCH_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_fetch_success_total",
            help: "Fetch/read attempts that returned a usable HTTP 200 body.",
            value: FETCH_SUCCESS_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_proxy_used_total",
            help: "Requests whose first attempt routed through an upstream proxy.",
            value: PROXY_USED_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_proxy_402_total",
            help: "Upstream-proxy HTTP 402 responses (Webshare quota/billing exhausted).",
            value: PROXY_402_TOTAL.load(Ordering::Relaxed),
        },
        Counter {
            name: "oxbrowser_proxy_fallback_total",
            help: "Direct-connection fallbacks taken because a proxy returned HTTP 402.",
            value: PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed),
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
    ];

    let gauges = [
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
            name: "oxbrowser_proxy_disabled",
            help: "1 if outbound proxy is disabled (PROXY_DISABLED env set), 0 otherwise.",
            value: PROXY_DISABLED.load(Ordering::Relaxed),
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
    use std::sync::Mutex;

    /// Gauge-publishing tests read/write the shared process-global `PROXY_DISABLED`
    /// static. When run in parallel they race on that atomic, producing flaky
    /// assertions. This mutex serializes them so the gauge value is deterministic
    /// within each test — mirrors the T2 render_cache gauge test pattern.
    static GAUGE_TEST_LOCK: Mutex<()> = Mutex::new(());

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
            "oxbrowser_fetch_total",
            "oxbrowser_fetch_success_total",
            "oxbrowser_proxy_used_total",
            "oxbrowser_proxy_402_total",
            "oxbrowser_proxy_fallback_total",
            "oxbrowser_solver_giveup_total",
            "oxbrowser_crawler_dedup_evicted_total",
            "oxbrowser_frontier_dropped_total",
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
    }

    #[test]
    fn record_helpers_increment_their_series() {
        let before = FETCH_TOTAL.load(Ordering::Relaxed);
        record_fetch();
        assert_eq!(FETCH_TOTAL.load(Ordering::Relaxed), before + 1);
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
        let _guard = GAUGE_TEST_LOCK.lock().unwrap();

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
}
