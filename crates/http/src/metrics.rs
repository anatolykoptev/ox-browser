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

/// One counter row in the registry: metric name, help text, current value.
struct Counter {
    name: &'static str,
    help: &'static str,
    value: u64,
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
    ];

    let mut out = String::with_capacity(counters.len() * 160);
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
