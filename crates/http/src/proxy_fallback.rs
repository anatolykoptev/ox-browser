//! Direct-connection fallback when an upstream proxy cannot be dialled.
//!
//! The **response-inferred 402 degradation** that previously lived here has
//! been removed. Three attempts to attribute a relayed `HTTP 402` to the
//! upstream proxy (by status code, by response header, by URL scheme) were
//! each bypassable — a plain-HTTP forward proxy relays the origin's own
//! headers, so the origin can forge any marker and trigger a direct re-send
//! of the identical request from the real IP. The sound design (probe the
//! proxy directly instead of inferring from the response) is specified in
//! issue **#90** and belongs there, not here.
//!
//! What survives is the **dial-failure fallback**: when the proxy host itself
//! is unreachable (connect refused / timeout / DNS / TLS handshake to the
//! proxy), degrading to direct is safe — the proxy is dead, so the real IP
//! is exposed only to the target, which is the explicit graceful-degradation
//! tradeoff. The classifier uses wreq's typed `is_proxy_connect()` predicate
//! (not Display-string matching) and is gated to the provably precise
//! forward-proxy path.
//!
//! ## SOCKS feature guard
//!
//! The dial-failure classifier [`looks_like_proxy_dial_failure`] relies on
//! wreq's `is_proxy_connect()` being precise for HTTP-forward-proxy dial
//! failures. That precision argument assumes the `socks` feature is NOT
//! compiled: with socks enabled, socks-proxy connect errors also surface as
//! `is_proxy_connect()`, falsifying the proxy-dial-failure classification
//! and potentially degrading to direct on a socks-proxy error (origin
//! unreachable). Enabling the `socks` feature on `ox-http` triggers a
//! compile error below so the breakage is loud, not silent.

#[cfg(feature = "socks")]
compile_error!(
    "ox-http: the `socks` feature is enabled. The proxy-fallback dial \
     classifier (looks_like_proxy_dial_failure) assumes socks is NOT compiled \
     — socks-proxy errors surface as is_proxy_connect() and would falsify the \
     proxy-dial-failure classification, potentially leaking the real IP. \
     Disable the `socks` feature or widen the classifier before enabling it."
);

use std::sync::atomic::{AtomicU64, Ordering};

/// Number of times we fell back to a direct connection because the upstream
/// proxy could not be dialled at all (connect refused / timeout / DNS / TLS
/// handshake failure) — a dead or unpaid proxy host.
///
/// Increment via [`record_proxy_dial_fallback`].
pub static PROXY_DIAL_FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);

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
/// ## F2 — redirect safety (why `max_redirects == 0` is required)
///
/// Both call sites pass `&req.url` — the ORIGINAL caller URL — while the
/// client follows redirects internally (`client.rs` ssrf_redirect_policy,
/// default `max_redirects = 10`). `is_http_target` therefore measures the
/// scheme of the PRE-redirect URL. A seed `http://a/…` that 301s to
/// `https://b/…` opens a CONNECT tunnel on hop 2; a reachable proxy that
/// cannot reach the origin answers non-2xx → `TunnelError::TunnelUnsuccessful`
/// → `ErrorKind::ProxyConnect`. `is_http_target("http://a/…")` is still true,
/// so without the redirect guard the classifier would fire and degrade to
/// direct — verbatim the case this doc refuses, a real-IP leak.
///
/// We CANNOT gate on the scheme of the hop that actually failed: `wreq::Error::uri()`
/// carries the ORIGINAL request URI, not the redirect target (verified
/// empirically — the outer `Pending` future in `client/future.rs` overwrites
/// the uri with the original request's uri when the connector error has none).
/// So when `max_redirects > 0` the failing hop's scheme is unobservable from
/// outside wreq, and we refuse to classify at all. A missing fallback is
/// strictly better than one that leaks.
///
/// ## Operational consequence
///
/// `HttpConfig::max_redirects` defaults to `10` and nothing in production
/// sets it to `0`, so under the default configuration this predicate returns
/// `false` for every request — the dial-failure fallback is opt-in via
/// `max_redirects == 0` and dormant otherwise (tracking issue ox-browser#90).
pub fn looks_like_proxy_dial_failure(err: &wreq::Error, url: &str, max_redirects: usize) -> bool {
    err.is_proxy_connect() && is_http_target(url) && max_redirects == 0
}

/// True iff `url` parses with scheme exactly `http` (not `https`, not
/// anything else). Used to gate the dial-failure fallback to the provably
/// precise forward-proxy path. A malformed URL returns `false` (conservative
/// — never fall back on an unparseable target).
pub(crate) fn is_http_target(url: &str) -> bool {
    url::Url::parse(url)
        .map(|u| u.scheme() == "http")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// precisely a proxy-dial failure -> classifier fires (with `max_redirects == 0`).
    #[tokio::test]
    async fn detects_real_dead_proxy_http_target() {
        let err = dead_proxy_error("http://example.com/").await;
        assert!(
            err.is_proxy_connect(),
            "sanity: wreq reports a ProxyConnect for a dead HTTP proxy"
        );
        assert!(
            looks_like_proxy_dial_failure(&err, "http://example.com/", 0),
            "HTTP + dead proxy + no redirects must be classified as a proxy-dial failure"
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
            !looks_like_proxy_dial_failure(&err, "https://example.com/", 0),
            "HTTPS targets must NOT trigger the dial fallback — is_proxy_connect \
             is ambiguous for the tunnel path"
        );
    }

    /// F2: when `max_redirects > 0` the classifier MUST refuse even for an
    /// HTTP target — the scheme of the failing hop is unobservable (a redirect
    /// from http to https makes `is_http_target` measure the pre-redirect URL),
    /// so degrading could leak the real IP through a healthy proxy.
    #[tokio::test]
    async fn does_not_classify_when_redirects_enabled() {
        let err = dead_proxy_error("http://example.com/").await;
        assert!(
            err.is_proxy_connect(),
            "sanity: wreq reports a ProxyConnect for a dead HTTP proxy"
        );
        assert!(
            !looks_like_proxy_dial_failure(&err, "http://example.com/", 10),
            "with max_redirects > 0 the classifier must refuse — the failing \
             hop's scheme is unobservable after a redirect"
        );
    }
}
