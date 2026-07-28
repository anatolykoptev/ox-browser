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

/// Number of times we fell back to a direct connection because the upstream
/// proxy could not be dialled at all (connect refused / timeout / DNS / TLS
/// handshake failure) — a dead or unpaid proxy host. Distinct from
/// [`PROXY_FALLBACK_TOTAL`]: a billing lapse (402) and a dead host are
/// different operational events and must stay separable in metrics.
///
/// Increment via [`record_proxy_dial_fallback`].
pub static PROXY_DIAL_FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);

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

/// Increment the proxy-dial-failure fallback counter and emit a structured
/// warning. Called when the upstream proxy is unreachable (not a 402): the
/// TCP/TLS/DNS dial to the proxy host itself failed. We degrade to a direct
/// connection so a dead proxy cannot 502 every request.
pub fn record_proxy_dial_fallback(url: &str) {
    PROXY_DIAL_FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(
        url = %url,
        reason = "proxy_dial_failure",
        metric = "oxbrowser_proxy_dial_fallback_total",
        "upstream proxy unreachable — falling back to direct connection (IP exposed)"
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

/// Returns `true` if the error is a failure to dial the upstream **proxy
/// host itself** (connect refused / timeout / DNS / TLS handshake to the
/// proxy), as opposed to a failure reaching the target *through* a working
/// proxy. Falling back to direct here is safe: the proxy is dead, so the
/// real IP would be exposed only to the target, which is the explicit
/// graceful-degradation tradeoff. The danger is the converse — falling back
/// when the proxy is fine but the *origin* is unreachable — which would leak
/// the real IP for no benefit. This classifier is built to NOT fire there.
///
/// ## How it classifies (and why it is precise, not string-matched)
///
/// wreq exposes a typed predicate [`wreq::Error::is_proxy_connect`], which
/// walks the error source chain and downcasts to the internal `ProxyConnect`
/// kind (NOT Display-string matching). Two proxy paths in wreq produce it:
///
/// - **HTTP target (forward proxy):** the connector calls `connect_auto_proxy`
///   and wraps any failure as `ProxyConnect` (`conn/connector.rs:456-460`).
///   That wrapper fires ONLY when the dial to the proxy host fails — a
///   target-side error here is impossible (the proxy hasn't been reached
///   yet). So for `http://` targets, `is_proxy_connect()` ⟹ proxy-dial
///   failure. Precise.
/// - **HTTPS target (CONNECT tunnel):** the connector uses `TunnelConnector`
///   (`conn/connector.rs:416-439`) whose `TunnelError` collapses two
///   semantically different cases into the same `ErrorKind::ProxyConnect`
///   (`client/layer/client.rs:988`): `ConnectFailed` (the inner dial to the
///   proxy host failed — a true proxy-dial failure) AND `TunnelUnsuccessful`
///   (the proxy returned a non-2xx to CONNECT — which is how a *reachable*
///   proxy reports that it could not reach the *origin*). From outside wreq
///   these two are indistinguishable: `TunnelError`, the internal `Error`,
///   and `ErrorKind` all live behind private modules (`mod conn;` / `mod
///   client;` are not `pub`), and `ProxyConnect` is `pub(crate)`.
///
/// So for HTTPS we CANNOT prove a `is_proxy_connect()` hit is a proxy-dial
/// failure rather than an origin-unreachable-through-proxy. Per the
/// "do not guess, do not widen" rule, we therefore narrow the classifier to
/// **HTTP targets only** (`url_scheme == http`), where the predicate is
/// provably precise. For HTTPS we conservatively do NOT fall back — a missing
/// fallback is strictly better than a too-broad one silently leaking the
/// real IP when the proxy is healthy but the origin is down.
///
/// See the OPEN CONCERN in the change report: HTTPS dead-proxy degradation
/// remains unhandled by design and needs an upstream wreq change (a public
/// way to split `TunnelError::ConnectFailed` from `TunnelUnsuccessful`).
///
/// Note: [`looks_like_proxy_402`] above matches on Display strings ("402" +
/// "proxy"/"connect"/"tunnel"). That is fragile — a target URL containing
/// "proxy" could in principle contribute — but it is the existing 402 path
/// and is NOT extended here. The dial classifier deliberately uses the typed
/// predicate instead, because the IP-exposure stakes are higher.
pub fn looks_like_proxy_dial_failure(err: &wreq::Error, url: &str) -> bool {
    err.is_proxy_connect() && is_http_target(url)
}

/// True iff `url` parses with scheme exactly `http` (not `https`, not
/// anything else). Used to gate the dial-failure fallback to the provably
/// precise forward-proxy path. A malformed URL returns `false` (conservative
/// — never fall back on an unparseable target).
fn is_http_target(url: &str) -> bool {
    url::Url::parse(url)
        .map(|u| u.scheme() == "http")
        .unwrap_or(false)
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

    #[test]
    fn dial_counter_increments() {
        let before = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);
        record_proxy_dial_fallback("https://example.com/dial");
        let after = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);
        assert_eq!(after, before + 1);
    }

    #[test]
    fn is_http_target_discriminates_scheme() {
        assert!(is_http_target("http://127.0.0.1:8080/x"));
        assert!(is_http_target("http://example.com/"));
        assert!(!is_http_target("https://127.0.0.1:8080/x"));
        assert!(!is_http_target("https://example.com/"));
        assert!(!is_http_target("not a url"));
        assert!(!is_http_target("ftp://example.com/"));
    }

    /// Build a REAL `wreq::Error` from a dead proxy (reserve a port, drop it
    /// -> connect refused) so the typed predicate is exercised against
    /// genuine wreq output, not a hand-authored string.
    async fn dead_proxy_error(target: &str) -> wreq::Error {
        let dead_port = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let client = wreq::Client::builder()
            .proxy(wreq::Proxy::all(format!("http://127.0.0.1:{dead_port}")).unwrap())
            .build()
            .unwrap();
        client
            .get(target)
            .send()
            .await
            .expect_err("dead proxy must error")
    }

    /// HTTP target + dead proxy: forward-proxy path, `is_proxy_connect()` is
    /// precisely a proxy-dial failure -> classifier fires.
    #[tokio::test]
    async fn detects_real_dead_proxy_http_target() {
        let err = dead_proxy_error("http://example.com/").await;
        assert!(
            err.is_proxy_connect(),
            "sanity: wreq reports a ProxyConnect for a dead HTTP proxy"
        );
        assert!(
            looks_like_proxy_dial_failure(&err, "http://example.com/"),
            "HTTP + dead proxy must be classified as a proxy-dial failure"
        );
    }

    /// HTTPS target + dead proxy: the same `is_proxy_connect()` is true, but
    /// the classifier MUST refuse — for HTTPS the predicate is ambiguous
    /// (could be `TunnelUnsuccessful` = origin unreachable through a healthy
    /// proxy), so falling back would risk leaking the real IP for no benefit.
    /// This is the guard that keeps the classifier from being blanket.
    #[tokio::test]
    async fn does_not_classify_https_target_even_if_proxy_connect() {
        let err = dead_proxy_error("https://example.com/").await;
        assert!(
            err.is_proxy_connect(),
            "sanity: wreq still reports ProxyConnect for a dead HTTPS proxy"
        );
        assert!(
            !looks_like_proxy_dial_failure(&err, "https://example.com/"),
            "HTTPS targets must NOT trigger the dial fallback — is_proxy_connect \
             is ambiguous for the tunnel path"
        );
    }
}
