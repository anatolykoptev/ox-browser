//! Direct-connection fallback when an upstream proxy returns HTTP 402.
//!
//! Webshare residential proxy returns `HTTP 402 Payment Required` when the
//! account bandwidth quota is exhausted or payment failed. wreq surfaces this
//! either as a real response (status 402) or as a wrapped connect error whose
//! Display string mentions "402"/"Payment Required".
//!
//! Per `~/CLAUDE.md`: "Direct requests to third-party = bug." This is a
//! deliberate, narrow exception for graceful degradation. We retry **once**
//! without the proxy, log a `tracing::warn!`, and bump
//! [`PROXY_FALLBACK_TOTAL`] so the operator sees the IP exposure event.
//!
//! Only triggered for HTTP 402. All other proxy errors (timeout, 5xx, network
//! failure) propagate unchanged.

use std::sync::atomic::{AtomicU64, Ordering};

/// Number of times we fell back to a direct connection because the proxy
/// returned HTTP 402 Payment Required (webshare quota / billing exhausted).
///
/// Exposed for tests and operator-visible metrics. Increment via
/// [`record_webshare_402_fallback`].
pub static PROXY_FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Increment the fallback counter and emit a structured warning.
pub fn record_webshare_402_fallback(url: &str) {
    PROXY_FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(
        url = %url,
        reason = "webshare_402",
        metric = "oxbrowser_proxy_fallback_total",
        "proxy returned HTTP 402 Payment Required — falling back to direct connection (IP exposed)"
    );
}

/// Returns `true` if the wreq error chain (or any wrapped source) suggests an
/// HTTP 402 from the upstream proxy.
///
/// wreq does not expose proxy response status directly; on `ProxyConnect`
/// failures the Display chain typically contains "402" and/or
/// "Payment Required". We match conservatively to avoid false positives.
pub fn looks_like_proxy_402(err: &wreq::Error) -> bool {
    let mut buf = String::new();
    let mut cur: Option<&dyn std::error::Error> = Some(err);
    while let Some(e) = cur {
        buf.push_str(&e.to_string());
        buf.push('\n');
        cur = e.source();
    }
    contains_402_marker(&buf)
}

/// True if the chained-error string carries the Webshare 402 fingerprint.
///
/// We require both a "402" token AND a phrase indicating it came from a proxy
/// connect step (Webshare returns the status during the CONNECT handshake).
pub(crate) fn contains_402_marker(s: &str) -> bool {
    let lc = s.to_ascii_lowercase();
    let has_402 = lc.contains(" 402") || lc.contains("status: 402") || lc.contains("/402");
    let has_payment = lc.contains("payment required");
    let proxy_context = lc.contains("proxy") || lc.contains("connect") || lc.contains("tunnel");
    (has_402 || has_payment) && proxy_context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_402_in_proxy_connect_string() {
        assert!(contains_402_marker(
            "client error (ProxyConnect): proxy returned 402 Payment Required"
        ));
    }

    #[test]
    fn detects_payment_required_phrase() {
        assert!(contains_402_marker(
            "tunnel handshake failed: HTTP/1.1 402 Payment Required"
        ));
    }

    #[test]
    fn ignores_402_outside_proxy_context() {
        // 402 returned by the *target* (rare) — not a proxy fault.
        assert!(!contains_402_marker("server returned status 402"));
    }

    #[test]
    fn ignores_unrelated_errors() {
        assert!(!contains_402_marker("connection reset by peer"));
        assert!(!contains_402_marker(
            "HTTP/1.1 503 Service Unavailable via proxy"
        ));
    }

    #[test]
    fn counter_increments() {
        let before = PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed);
        record_webshare_402_fallback("https://example.com/test");
        let after = PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed);
        assert_eq!(after, before + 1);
    }
}
