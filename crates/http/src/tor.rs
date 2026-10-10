//! Tor routing for `.onion` targets (ox-browser#188).
//!
//! An onion name must never reach a local DNS resolver (RFC 7686 §2) and a
//! request for one must never leave this process any way except through the
//! operator's Tor HTTP tunnel. Everything that decides "is this Tor-bound" and
//! "which proxy is the Tor proxy" lives here so the pre-resolve tier
//! ([`crate::middleware_ssrf`]), the connect-time tier
//! ([`crate::ssrf_connect`]) and the terminal handler
//! ([`crate::handler_reqwest`]) cannot disagree.
//!
//! # Transport
//!
//! `OX_TOR_PROXY` points at an HTTP proxy that forwards to Tor's SOCKS port
//! with remote name resolution (Privoxy `forward-socks5t`, the `tor-privoxy`
//! service). It speaks forward-proxy HTTP for `http://` targets and CONNECT for
//! `https://` ones, which is exactly what wreq sends, so both reach Tor. Tor's
//! own `HTTPTunnelPort` would not do: it is CONNECT-only and an absolute-URI
//! forward request (what wreq sends for `http://`) gets an empty reply
//! (krolik-server#537).
//!
//! # Config
//!
//! [`TOR_PROXY_ENV`] (`OX_TOR_PROXY=http://host:port`) is the ONE place an
//! internal/private proxy address is accepted — it is operator config, not
//! caller input, so it deliberately bypasses `validate_proxy_url` and
//! `OX_PROXY_ALLOWLIST` — and it is used only for Tor-bound requests.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use url::Url;
use wreq::dns::{Addrs, Name, Resolve, Resolving};

use crate::middleware_ssrf::canonicalise_proxy_url;
use crate::ssrf_connect::SsrfBlockedError;
use crate::{HttpError, Result};

/// Env var holding the Tor HTTP-tunnel proxy URL (`http://host:port`).
pub const TOR_PROXY_ENV: &str = "OX_TOR_PROXY";

/// Default per-call deadline (seconds) for a `.onion` target when the caller
/// supplied no `timeout`: circuit build + rendezvous routinely exceeds the
/// clearnet defaults. Still clamped by `deadline::MAX_CALL_TIMEOUT_SECS`.
pub const ONION_DEFAULT_CALL_TIMEOUT_SECS: u64 = 60;

/// Per-attempt wreq timeout of the Tor client. Deliberately at the hard call
/// ceiling: the per-call deadline (`deadline::bounded`) is the real bound, this
/// only stops a dead tunnel from living forever.
pub const TOR_CLIENT_TIMEOUT_SECS: u64 = 120;

/// `true` if `host` is a `.onion` name: case-insensitive, trailing root dots
/// tolerated (`FOO.ONION.`), and the bare TLD `onion` itself.
pub fn is_onion_host(host: &str) -> bool {
    // ALL trailing root dots: `foo.onion..` is still the onion name to a
    // resolver that tolerates it.
    let host = host.trim_end_matches('.');
    let Some(tld) = host.rsplit('.').next() else {
        return false;
    };
    tld.eq_ignore_ascii_case("onion")
}

/// `true` if `url` parses and its host is a `.onion` name. Free-form values
/// (request-body strings searched by [`json_mentions_onion`]) are normalised
/// first: a `view-source:` wrapper is stripped, and a string with no scheme is
/// retried as `http://<s>` so bare `foo.onion` and protocol-relative
/// `//foo.onion/x` still hit the host check (issue #192). An unparsable URL
/// is not onion-bound here — the URL validator rejects it on its own.
pub fn is_onion_url(url: &str) -> bool {
    let s = match url.get(..12) {
        Some(prefix) if prefix.eq_ignore_ascii_case("view-source:") => &url[12..],
        _ => url,
    };
    let host_is_onion = |raw: &str| {
        Url::parse(raw)
            .ok()
            .and_then(|u| u.host_str().map(is_onion_host))
            .unwrap_or(false)
    };
    if host_is_onion(s) {
        return true;
    }
    // No scheme (`foo.onion`, `//foo.onion/x`): retry under http so the host
    // position is populated. A `:` before the first `/`, `?` or `#` is a
    // scheme per WHATWG — those already parsed above (or cannot be a host).
    let has_scheme = match (s.find(':'), s.find(['/', '?', '#'])) {
        (Some(c), Some(t)) => c < t,
        (Some(_), None) => true,
        _ => false,
    };
    !has_scheme && host_is_onion(&format!("http://{s}"))
}

/// Default call deadline for a URL: the endpoint's own default, raised to
/// [`ONION_DEFAULT_CALL_TIMEOUT_SECS`] for a `.onion` target. Feed it into
/// `caller.or(default_timeout_for_url(..))` so an explicit caller `timeout`
/// still wins.
pub fn default_timeout_for_url(url: &str, endpoint_default: Option<u64>) -> Option<u64> {
    if is_onion_url(url) {
        Some(
            endpoint_default.map_or(ONION_DEFAULT_CALL_TIMEOUT_SECS, |d| {
                d.max(ONION_DEFAULT_CALL_TIMEOUT_SECS)
            }),
        )
    } else {
        endpoint_default
    }
}

/// Refusal for a `.onion` target when no Tor proxy is configured. Counted:
/// a refusal is a silent-failure surface for the operator who forgot to set
/// `OX_TOR_PROXY`.
pub fn refuse_requires_tor() -> HttpError {
    crate::metrics::record_onion_refused();
    HttpError::OnionRequiresTor
}

/// Config gate shared by the pre-resolve tier and the terminal handler: an
/// onion target is admitted only when a Tor proxy is configured.
pub fn check_onion_target(tor_configured: bool) -> Result<()> {
    if tor_configured {
        Ok(())
    } else {
        Err(refuse_requires_tor())
    }
}

/// Lowercase and strip trailing root dots: the one normal form both the stored
/// proxy host and every name the resolver is asked about are compared in.
fn normalise_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Third-party endpoints (CF solver, Chrome render, reverse image search)
/// forward the caller's URL to a service that fetches outside Tor, so an onion
/// name must never reach them. `Some(refusal)` when `url` is an onion URL.
pub fn refuse_onion_for_third_party(url: &str) -> Option<HttpError> {
    is_onion_url(url).then(refuse_requires_tor)
}

/// `true` if any string anywhere in `value` is an onion URL (free-form request
/// bodies such as `/chrome/interact` carry URLs in nested actions).
pub fn json_mentions_onion(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => is_onion_url(s),
        serde_json::Value::Array(a) => a.iter().any(json_mentions_onion),
        serde_json::Value::Object(o) => o.values().any(json_mentions_onion),
        _ => false,
    }
}

/// A validated Tor HTTP proxy (`OX_TOR_PROXY`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorProxy {
    /// Canonical `http://host:port` URL to dial.
    url: String,
    /// Proxy host without IPv6 brackets, lowercase — the only name the Tor
    /// client's resolver will resolve.
    host: String,
}

impl TorProxy {
    /// Validate an `OX_TOR_PROXY` value: `http` scheme, explicit port, no
    /// credentials, no path/query. Where the proxy points is NOT vetted — it is
    /// operator config and legitimately an internal address (`tor-privoxy:8118`).
    pub fn parse(raw: &str) -> Result<Self> {
        let invalid = |why: &str| HttpError::InvalidUrl(format!("{TOR_PROXY_ENV}: {why}"));
        // Only the explicit `http://` form: `https` would need a TLS hop to
        // Tor's plaintext tunnel port and a bare `host:port` hides the scheme
        // the operator meant.
        let Some((scheme, rest)) = raw.split_once("://") else {
            return Err(invalid("must be http://host:port"));
        };
        if !scheme.eq_ignore_ascii_case("http") {
            return Err(invalid("scheme must be http (the proxy in front of Tor)"));
        }
        // The url crate drops `:80` for http, so the explicit-port rule is
        // decided on the raw authority.
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        let explicit_port = authority.rsplit_once(':').is_some_and(|(h, p)| {
            !h.is_empty() && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
        });
        if !explicit_port {
            return Err(invalid("an explicit :port is required"));
        }
        let canonical =
            canonicalise_proxy_url(raw).map_err(|_| invalid("not a valid proxy URL"))?;
        if canonical.has_userinfo {
            return Err(invalid("credentials are not supported"));
        }
        Ok(Self {
            url: canonical.url,
            host: normalise_host(&canonical.host),
        })
    }

    /// Read and validate [`TOR_PROXY_ENV`]. `Ok(None)` when unset/blank.
    pub fn from_env() -> Result<Option<Self>> {
        match std::env::var(TOR_PROXY_ENV) {
            Ok(v) if !v.trim().is_empty() => Self::parse(v.trim()).map(Some),
            _ => Ok(None),
        }
    }

    /// Canonical proxy URL to hand to wreq.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Resolver for the Tor client: admits only the proxy's own host.
    pub fn resolver(&self) -> TorProxyResolver {
        TorProxyResolver {
            proxy_host: self.host.clone(),
        }
    }
}

/// `wreq::dns::Resolve` of the Tor client. Through a CONNECT proxy wreq
/// resolves only the PROXY host (the target name travels inside the tunnel),
/// so this admits exactly that host — unfiltered, because the Tor proxy is
/// legitimately a private address — and refuses every other name, `.onion`
/// above all. The shared [`crate::ssrf_connect::SsrfGuardedResolver`] cannot
/// serve here: it would drop the private answer for `tor`.
#[derive(Debug, Clone)]
pub struct TorProxyResolver {
    proxy_host: String,
}

impl TorProxyResolver {
    /// The decision plus the lookup behind an injectable seam, so a test can
    /// count lookups without real DNS.
    pub(crate) async fn resolve_with<F, Fut>(
        &self,
        name: &str,
        lookup: F,
    ) -> std::result::Result<Vec<SocketAddr>, BoxedErr>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<Vec<SocketAddr>>>,
    {
        let host = normalise_host(name);
        if is_onion_host(&host) {
            return Err(Box::new(SsrfBlockedError(
                "onion_requires_tor: a .onion name is never resolved locally".into(),
            )));
        }
        if host != self.proxy_host {
            return Err(Box::new(SsrfBlockedError(format!(
                "tor client resolves only its proxy host, refusing {host}"
            ))));
        }
        lookup(host.clone())
            .await
            .map_err(|e| Box::new(SsrfBlockedError(format!("resolve {host}: {e}"))) as BoxedErr)
    }
}

type BoxedErr = Box<dyn std::error::Error + Send + Sync>;

impl Resolve for TorProxyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let this = self.clone();
        Box::pin(async move {
            let addrs = this
                .resolve_with(name.as_str(), |h| async move {
                    tokio::net::lookup_host((h.as_str(), 0))
                        .await
                        .map(|it| it.collect::<Vec<_>>())
                })
                .await?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Which side of the onion boundary a redirect hop to `host` lands on, seen
/// from a client that is Tor-bound (`from_tor`) or not. A crossing hop must
/// leave wreq's internal redirect loop and be routed afresh: following it in
/// place would silently keep a clearnet fetch on Tor, or hand an onion name to
/// a pooled third-party proxy.
pub fn crosses_onion_boundary(host: &str, from_tor: bool) -> bool {
    is_onion_host(host) != from_tor
}

/// Record a request routed through the Tor tunnel.
pub fn record_tor_request() {
    crate::metrics::TOR_REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_host_table() {
        for (h, want) in [
            ("foo.onion", true),
            ("FOO.ONION", true),
            ("foo.onion.", true),
            ("foo.onion..", true),
            ("FOO.ONION...", true),
            ("FOO.ONION.", true),
            ("a.b.foo.onion", true),
            ("onion", true),
            ("foo.onionx", false),
            ("onion.example.com", false),
            ("example.com", false),
            ("notonion", false),
            ("foo.onion.example.com", false),
            ("", false),
        ] {
            assert_eq!(is_onion_host(h), want, "is_onion_host({h:?})");
        }
    }

    #[test]
    fn onion_url_uses_the_parsed_host() {
        assert!(is_onion_url("https://FOO.ONION./x"));
        // `.onion` in the path/userinfo/query must not count.
        assert!(!is_onion_url("https://example.com/foo.onion"));
        assert!(!is_onion_url("https://foo.onion@example.com/"));
        assert!(!is_onion_url("not a url"));
    }

    /// #192: free-form strings a request body can carry still resolve to a
    /// host — bare `foo.onion`, protocol-relative `//foo.onion/x`, and a
    /// `view-source:` wrapper all count; clearnet strings do not.
    ///
    /// Falsification: drop the `http://{s}` retry in `is_onion_url` and the
    /// scheme-less rows go RED.
    #[test]
    fn onion_url_scheme_less_and_wrapped_forms() {
        for url in [
            "foo.onion",
            "FOO.ONION./",
            "//foo.onion/x",
            "view-source:http://foo.onion/",
            "View-Source:https://FOO.ONION.",
        ] {
            assert!(is_onion_url(url), "must match {url:?}");
        }
        for url in [
            "example.com",
            "https://onion.example.com/",
            "foo.onion.example.com",
            "mailto:x@foo.onion",
            "the .onion suffix in prose",
        ] {
            assert!(!is_onion_url(url), "must not match {url:?}");
        }
    }

    /// `json_mentions_onion` inherits the same normalisation for strings
    /// nested anywhere in a request body.
    #[test]
    fn json_mentions_onion_finds_scheme_less_and_wrapped_urls() {
        for v in [
            serde_json::json!("foo.onion"),
            serde_json::json!("//foo.onion/x"),
            serde_json::json!("view-source:http://foo.onion/"),
            serde_json::json!({"url": "https://clearnet.example/", "go": "//a.onion"}),
        ] {
            assert!(json_mentions_onion(&v), "{v}");
        }
        for v in [
            serde_json::json!("example.com"),
            serde_json::json!("https://onion.example.com/"),
            serde_json::json!("foo.onion.example.com"),
        ] {
            assert!(!json_mentions_onion(&v), "{v}");
        }
    }

    #[test]
    fn onion_default_timeout_is_raised_not_lowered() {
        assert_eq!(
            default_timeout_for_url("https://a.onion/", Some(15)),
            Some(60)
        );
        assert_eq!(
            default_timeout_for_url("https://a.onion/", Some(90)),
            Some(90)
        );
        assert_eq!(default_timeout_for_url("https://a.onion/", None), Some(60));
        assert_eq!(
            default_timeout_for_url("https://a.com/", Some(15)),
            Some(15)
        );
        assert_eq!(default_timeout_for_url("https://a.com/", None), None);
    }

    #[test]
    fn tor_proxy_parse_accepts_and_refuses() {
        let ok = TorProxy::parse("http://tor-privoxy:8118").expect("hostname proxy");
        assert_eq!(ok.url(), "http://tor-privoxy:8118");
        let ok = TorProxy::parse("http://127.0.0.1:9080/").expect("private IP proxy is the point");
        assert_eq!(ok.url(), "http://127.0.0.1:9080");
        // Explicit :80 must be required even though the url crate drops it.
        assert!(TorProxy::parse("http://tor:80").is_ok());
        for bad in [
            "tor-privoxy:8118",
            "http://tor",
            "http://tor:",
            "https://tor-privoxy:8118",
            "socks5://tor:9050",
            "http://u:p@tor-privoxy:8118",
            "http://tor-privoxy:8118/path",
            "http://tor-privoxy:8118?x=1",
            "http://:9080",
            "",
        ] {
            assert!(TorProxy::parse(bad).is_err(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn tor_proxy_errors_do_not_echo_credentials() {
        let err = TorProxy::parse("http://user:hunter2@tor-privoxy:8118")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("hunter2"), "credential leaked: {err}");
    }

    #[tokio::test]
    async fn tor_resolver_admits_only_its_proxy_host_and_never_onion() {
        // Stored with a trailing dot and mixed case: both sides normalise alike.
        let r = TorProxy::parse("http://Tor-Privoxy.:8118")
            .unwrap()
            .resolver();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let lookup = |_: String| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(vec![SocketAddr::from(([172, 20, 0, 5], 0))]) }
        };
        // The proxy host resolves even though the answer is private.
        for name in [
            "tor-privoxy",
            "TOR-PRIVOXY",
            "tor-privoxy.",
            "Tor-Privoxy..",
        ] {
            let before = calls.load(Ordering::SeqCst);
            let got = r.resolve_with(name, &lookup).await.expect(name);
            assert_eq!(got.len(), 1, "{name}");
            assert_eq!(calls.load(Ordering::SeqCst), before + 1, "{name}");
        }
        // Anything else, including an onion, is refused without a lookup.
        for name in [
            "example.com",
            "foo.onion",
            "FOO.ONION.",
            "foo.onion..",
            "tor.evil.com",
        ] {
            let before = calls.load(Ordering::SeqCst);
            assert!(r.resolve_with(name, &lookup).await.is_err(), "{name}");
            assert_eq!(calls.load(Ordering::SeqCst), before, "{name} did a lookup");
        }
    }

    #[test]
    fn boundary_crossing_is_symmetric() {
        assert!(crosses_onion_boundary("example.com", true));
        assert!(crosses_onion_boundary("foo.onion", false));
        assert!(!crosses_onion_boundary("bar.onion", true));
        assert!(!crosses_onion_boundary("example.org", false));
    }
}
