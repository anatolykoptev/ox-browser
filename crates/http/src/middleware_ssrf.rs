//! SSRF protection middleware — blocks requests to private/reserved IPs.
//!
//! This is the PRE-RESOLVE tier: it validates a URL before it enters the
//! middleware chain, using its own DNS lookup. It is fast-fail and catches
//! the common case, but — like any pre-resolve check — it cannot defeat a
//! DNS-rebind attack (a hostname that resolves to a public IP here and a
//! private IP by the time the terminal handler actually connects). The
//! CONNECT-TIME tier that closes that gap lives in [`crate::ssrf_connect`]
//! (a custom `wreq::dns::Resolve` wired via `ClientBuilder::dns_resolver`,
//! which is checked on the IP wreq is about to dial, immediately before the
//! TCP connect — the wreq-idiomatic equivalent of a `net.Dialer.Control`
//! hook). Both tiers share the same block predicate ([`is_private_ip`]) so
//! there is exactly one definition of "blocked" in this crate.
//!
//! This block-list mirrors `go-kit/httputil.IsBlockedIP` for fleet parity —
//! see that file's doc comment for the range rationale. Keep the two in
//! sync when either changes.
//!
//! # Allowlist override
//!
//! For legitimate sidecar / loopback setups (and integration tests that bind a
//! fake server on `127.0.0.1`) the env var `OX_HTTP_PRIVATE_ALLOWLIST` may
//! list a comma-separated set of `host:port` entries that bypass the private-IP
//! check. The match is exact on `host:port` after URL parsing — there is no
//! wildcard and no CIDR support, so this is a narrow escape hatch and must be
//! set explicitly per-deployment, never globally.
//!
//! **Startup validation** ([`validate_allowlist`]): every entry is parsed and
//! resolved at server startup. Entries that resolve to a private/loopback/
//! link-local/metadata IP (anything [`is_private_ip`] blocks, including
//! `169.254.169.254`) or that are unparseable cause the server to **refuse to
//! start**. This prevents an operator from accidentally opening an SSRF bypass
//! to a cloud-metadata endpoint or internal service.
//!
//! Example: `OX_HTTP_PRIVATE_ALLOWLIST=8.8.8.8:80,1.1.1.1:80`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use async_trait::async_trait;
use url::Url;

use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::{HttpError, HttpResponse, Result};

/// Returns a middleware that rejects requests to private/loopback/reserved IPs.
///
/// Resolves hostnames to IPs before checking, so Docker service names
/// (e.g. `redis`, `postgres`) that resolve to private IPs are also blocked.
pub fn ssrf_middleware() -> MiddlewareFn {
    ssrf_middleware_with(false, system_lookup())
}

/// [`ssrf_middleware`] with the two inputs the production chain varies:
/// whether a Tor proxy is configured (a `.onion` target is only admitted then)
/// and the DNS lookup seam (so a test can count lookups).
pub fn ssrf_middleware_with(tor_configured: bool, lookup: LookupHost) -> MiddlewareFn {
    Arc::new(move |next: Arc<dyn Handler>| {
        let handler: Arc<dyn Handler> = Arc::new(SsrfGuard {
            next,
            tor_configured,
            lookup: Arc::clone(&lookup),
        });
        handler
    })
}

/// Pre-resolve DNS lookup: host + port → addresses.
pub type LookupHost = Arc<dyn Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>> + Send + Sync>;

/// The system resolver (`getaddrinfo` via `ToSocketAddrs`).
pub fn system_lookup() -> LookupHost {
    Arc::new(|host: &str, port: u16| {
        format!("{host}:{port}")
            .to_socket_addrs()
            .map(Iterator::collect)
    })
}

struct SsrfGuard {
    next: Arc<dyn Handler>,
    tor_configured: bool,
    lookup: LookupHost,
}

#[async_trait]
impl Handler for SsrfGuard {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        validate_url_with(&req.url, self.tor_configured, self.lookup.as_ref())?;
        self.next.handle(req).await
    }
}

/// Validate that a URL does not target a private/reserved IP.
///
/// Pre-resolve tier — see the module doc for why this alone is not
/// rebind-proof, and [`crate::ssrf_connect`] for the tier that is.
pub fn validate_url(url_str: &str) -> Result<()> {
    // No Tor proxy in scope here (media downloads, ad-hoc callers): a `.onion`
    // target is refused outright.
    validate_url_with(url_str, false, system_lookup().as_ref())
}

/// [`validate_url`] with the Tor admission flag and the lookup seam explicit.
///
/// A `.onion` host is decided FIRST — before the private-IP allowlist, the IP
/// parse and the DNS lookup — because it must never be resolved locally
/// (RFC 7686 §2): with Tor configured it is admitted (see
/// [`crate::tor`]) and routed by the terminal handler; without, it is refused
/// as `onion_requires_tor`.
pub fn validate_url_with(
    url_str: &str,
    tor_configured: bool,
    lookup: &(dyn Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>> + Send + Sync),
) -> Result<()> {
    let url = Url::parse(url_str).map_err(|e| HttpError::InvalidUrl(e.to_string()))?;

    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(HttpError::InvalidUrl(format!(
            "URI scheme is not allowed: {scheme}"
        )));
    }

    let host = url
        .host_str()
        .ok_or_else(|| HttpError::InvalidUrl("missing host".into()))?;

    let port = url.port_or_known_default().unwrap_or(80);

    if crate::tor::is_onion_host(host) {
        return crate::tor::check_onion_target(tor_configured);
    }

    // Narrow escape hatch for sidecars / integration tests. Read fresh on
    // every call so tests can flip it per-test.
    if is_allowlisted(host, port) {
        return Ok(());
    }

    // Try parsing as IP directly first.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Err(HttpError::InvalidUrl(format!(
                "SSRF blocked: {host} is a private/reserved address"
            )));
        }
        return Ok(());
    }

    // Fail closed on a host that LOOKS like a non-standard numeral encoding
    // of an IP (decimal, octal, or hex — e.g. "2130706433", "0x7f000001",
    // "012.0.0.1") but that `host.parse::<IpAddr>()` above rejected. Some
    // resolvers (notably glibc's getaddrinfo) still parse these forms as
    // literal IPs; refusing outright here — rather than falling through to
    // a same-string DNS lookup — mirrors `go-kit/httputil.CheckURL` and
    // closes the exact bypass class that check exists to close.
    if looks_like_alt_encoded_ip(host) {
        return Err(HttpError::InvalidUrl(format!(
            "SSRF blocked: host {host:?} looks like a non-standard IP encoding"
        )));
    }

    // Resolve hostname to IP addresses.
    if let Ok(addrs) = lookup(host, port) {
        for socket_addr in addrs {
            if is_private_ip(&socket_addr.ip()) {
                return Err(HttpError::InvalidUrl(format!(
                    "SSRF blocked: {host} resolves to private address {}",
                    socket_addr.ip()
                )));
            }
        }
    }
    // If DNS fails, let the request proceed — the HTTP client will produce
    // a more descriptive connection error.

    Ok(())
}

/// Returns `true` if `host:port` is listed in `OX_HTTP_PRIVATE_ALLOWLIST`.
///
/// Comma-separated, case-insensitive on host. Exact match — no wildcards.
pub fn is_allowlisted(host: &str, port: u16) -> bool {
    let Ok(list) = std::env::var("OX_HTTP_PRIVATE_ALLOWLIST") else {
        return false;
    };
    let needle = format!("{}:{port}", host.to_ascii_lowercase());
    list.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .any(|entry| entry == needle)
}

/// Placeholder logged for a proxy URL that cannot be safely redacted.
const UNPARSABLE_PROXY: &str = "<unparsable proxy URL>";

/// Proxy URL reduced to `scheme://[***@]host:port`, for logs and errors.
///
/// Built on [`canonicalise_proxy_url`]: on success the output is assembled
/// from the canonical scheme, host and port — the parts that will actually be
/// dialled — and on failure it is `<unparsable proxy URL>`. It never renders
/// anything the dialler would not accept, so a credential the url crate would
/// parse outside the userinfo (as host, port, path, query or fragment) cannot
/// leak through it.
pub fn redact_proxy_userinfo(proxy_url: &str) -> String {
    let Ok(c) = canonicalise_proxy_url(proxy_url) else {
        return UNPARSABLE_PROXY.to_owned();
    };
    let creds = if c.has_userinfo { "***@" } else { "" };
    let host = if c.host.contains(':') {
        format!("[{}]", c.host)
    } else {
        c.host
    };
    format!("{}://{creds}{host}:{}", c.scheme, c.port)
}

/// Env var listing caller-supplied proxies (`host:port`, comma-separated,
/// case-insensitive host) that may point at a private address.
pub const PROXY_ALLOWLIST_ENV: &str = "OX_PROXY_ALLOWLIST";

/// Proxy schemes ox-browser will dial: `http` and `https` only. wreq is
/// built WITHOUT its `socks` feature (see `Cargo.toml`), so it has no
/// intercept for `socks*` — a `socks5://…` URL is never a SOCKS dial and
/// falls through to wreq's auto-proxy path, which can send the request
/// DIRECT from the real IP while the caller believes it is proxied
/// (issue #179). Any other scheme (`ftp`, `socks`, …) is likewise ignored.
/// Both [`validate_proxy_url`] and the pool path (`build_proxy`) refuse
/// anything outside this list.
pub const ALLOWED_PROXY_SCHEMES: &[&str] = &["http", "https"];

/// `socks*` schemes that are refused by name: a caller plausibly configured
/// one expecting it to work, so the refusal says which scheme it saw —
/// from this constant list, never the raw input (SEC-CR-025).
const SOCKS_SCHEMES: &[&str] = &["socks4", "socks4a", "socks5", "socks5h"];

/// Default port for a scheme when the proxy URL names none: 443 for https,
/// 80 for http.
pub fn default_proxy_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        _ => 80,
    }
}

/// A proxy URL rebuilt into the one form both the url crate and wreq read
/// the same way: lowercase known scheme, canonical host, explicit port,
/// userinfo kept (percent-encoded as parsed).
pub struct CanonicalProxy {
    /// `scheme://[userinfo@]host[:port]` — the string to dial.
    pub url: String,
    /// Lowercase scheme, one of [`ALLOWED_PROXY_SCHEMES`].
    pub scheme: String,
    /// Whether the URL carries a username or password.
    pub has_userinfo: bool,
    /// Host without IPv6 brackets.
    pub host: String,
    /// The port that will be dialled (the scheme default when none is given).
    pub port: u16,
}

/// Canonicalise a proxy URL without vetting where it points. Every proxy the
/// HTTP client hands to wreq goes through this (per-request via
/// [`validate_proxy_url`]; pool, static, media and the `doctor` probe via
/// `build_proxy`). wreq
/// dials its own re-parse of the raw string, and the url crate is lenient in
/// ways that let a credential end up as the host, port, path, query or
/// fragment, so the grammar is strict and everything is decided from ONE
/// parse:
///
/// - Accepted forms only: input that literally starts with
///   `<allowed-scheme>://` (scheme case-insensitive, [`ALLOWED_PROXY_SCHEMES`]
///   — anything else wreq cannot dial; a `socks*` scheme would fall through
///   to a direct request from the real IP, issue #179), or a bare
///   `host:port` (numeric port) with no `/`, `?`, `#`, `\` or `@` anywhere,
///   treated as http. `http:/…`, `http:…`, `socks5:/…` are refused.
/// - A backslash, control character or space is refused outright: it drives
///   the url/wreq parser differential (`1.1.1.1\@127.0.0.1:6379`
///   validates as one host, dials another) and ends a special-scheme
///   authority early.
/// - After parsing: no query, no fragment, and a path of "" or "/" only. A
///   `/`, `?` or `#` before the userinfo `@` makes the url crate end the
///   authority there (`u:12#pw@h` = host `u`, port 12), and this rule refuses
///   it (SEC-CR-021/022).
/// - Host and port come from the parse — never from the raw string. Only
///   special schemes are accepted, so the host is already canonicalised by
///   the parse itself (IPv4 shorthand → dotted-quad, IDNA).
/// - wreq treats an empty port as "no proxy": the emitted URL always carries
///   an explicit port, the scheme default when none was given
///   ([`default_proxy_port`]).
pub fn canonicalise_proxy_url(proxy_url: &str) -> Result<CanonicalProxy> {
    let blocked = |msg: &str| HttpError::InvalidUrl(format!("SSRF blocked: {msg}"));
    if proxy_url
        .bytes()
        .any(|b| b == b'\\' || b.is_ascii_control() || b == b' ')
    {
        return Err(blocked("proxy URL contains an illegal authority character"));
    }
    let owned;
    let with_scheme = match proxy_url.split_once("://") {
        Some((s, rest)) => {
            if !ALLOWED_PROXY_SCHEMES
                .iter()
                .any(|a| a.eq_ignore_ascii_case(s))
            {
                // The raw text before "://" is NEVER echoed — it may be a
                // username or password (SEC-CR-025). A `socks*` scheme is
                // named from the constant list instead: it is one a caller
                // plausibly configured expecting it to work, and the refusal
                // must say so (issue #179).
                return Err(
                    match SOCKS_SCHEMES.iter().find(|a| a.eq_ignore_ascii_case(s)) {
                        Some(scheme) => blocked(&format!(
                            "unsupported proxy scheme {scheme:?} — wreq is built \
                         without SOCKS support; use http or https"
                        )),
                        None => blocked("unsupported proxy scheme"),
                    },
                );
            }
            // Decide "no path, query or fragment" on the RAW text: the parsed
            // path is WHATWG-normalised, so `/..` and `/%2e%2e` collapse to
            // "/" and would hide a `/` before the userinfo `@`
            // (SEC-CR-026). One optional trailing `/` is the only slash kept.
            let authority = rest.strip_suffix('/').unwrap_or(rest);
            if authority.contains(['/', '?', '#', '\\']) {
                return Err(blocked("proxy URL must have no path, query or fragment"));
            }
            proxy_url
        }
        None => {
            let bare_host_port = !proxy_url.contains(['/', '?', '#', '@'])
                && proxy_url.rsplit_once(':').is_some_and(|(h, p)| {
                    !h.is_empty() && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
                });
            if !bare_host_port {
                return Err(blocked(
                    "proxy URL must be scheme://host[:port] or host:port",
                ));
            }
            owned = format!("http://{proxy_url}");
            &owned
        }
    };
    let url = url::Url::parse(with_scheme).map_err(|_| blocked("unparsable proxy URL"))?;
    let scheme = url.scheme().to_ascii_lowercase();
    if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
        return Err(blocked("proxy URL must have no path, query or fragment"));
    }
    // Only http/https reach this point, so the parse already canonicalised
    // the host (IPv4 shorthand → dotted-quad, IDNA on domains).
    let host = match url.host() {
        Some(h) => h,
        None => return Err(blocked("proxy URL has no host")),
    };
    // Special schemes drop their own default port, which is also ours.
    let port = url.port().unwrap_or_else(|| default_proxy_port(&scheme));
    let (host, host_out) = match host {
        url::Host::Ipv6(v6) => (v6.to_string(), format!("[{v6}]")),
        url::Host::Ipv4(v4) => (v4.to_string(), v4.to_string()),
        url::Host::Domain(d) => (d.to_owned(), d.to_owned()),
    };
    let has_userinfo = !url.username().is_empty() || url.password().is_some();
    let mut out = format!("{scheme}://");
    if has_userinfo {
        out.push_str(url.username());
        if let Some(pw) = url.password() {
            out.push(':');
            out.push_str(pw);
        }
        out.push('@');
    }
    out.push_str(&host_out);
    out.push_str(&format!(":{port}"));
    Ok(CanonicalProxy {
        url: out,
        scheme,
        has_userinfo,
        host,
        port,
    })
}

/// Validate a caller-supplied per-request proxy URL and return the exact,
/// canonical URL to dial ([`canonicalise_proxy_url`]). The caller must dial
/// the returned string, never the raw input.
///
/// Private targets: the connect-time
/// [`crate::ssrf_connect::SsrfGuardedResolver`] only sees HOSTNAMES; wreq
/// skips DNS for an IP-literal proxy. Refused here: IP literals that
/// [`is_private_ip`] blocks, `localhost` / `*.localhost`, and non-standard IP
/// encodings, all checked against the canonical host and the port that will
/// be dialled. A `host:port` listed in [`PROXY_ALLOWLIST_ENV`] is admitted;
/// other hostnames are left to the resolver.
pub fn validate_proxy_url(proxy_url: &str) -> Result<String> {
    let blocked = |msg: &str| HttpError::InvalidUrl(format!("SSRF blocked: {msg}"));
    let CanonicalProxy {
        url, host, port, ..
    } = canonicalise_proxy_url(proxy_url)?;
    if proxy_allowlisted(&host, port) {
        return Ok(url);
    }
    let lower = host.to_ascii_lowercase();
    // A trailing dot is the same name (`localhost.`); IDNA already mapped
    // U+3002 / U+FF0E to '.', so strip exactly one after the parse.
    let lower = lower.strip_suffix('.').unwrap_or(&lower);
    if lower == "localhost" || lower.ends_with(".localhost") {
        return Err(blocked(&format!("proxy host {host} is loopback")));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Err(blocked(&format!(
                "proxy host {host} is a private/reserved address"
            )));
        }
        return Ok(url);
    }
    if looks_like_alt_encoded_ip(&host) {
        return Err(blocked(&format!(
            "proxy host {host:?} looks like a non-standard IP encoding"
        )));
    }
    Ok(url)
}

fn proxy_allowlisted(host: &str, port: u16) -> bool {
    let Ok(list) = std::env::var(PROXY_ALLOWLIST_ENV) else {
        return false;
    };
    let needle = format!("{}:{port}", host.to_ascii_lowercase());
    list.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .any(|entry| entry == needle)
}

/// Validate the `OX_HTTP_PRIVATE_ALLOWLIST` env var at startup.
///
/// Parses each comma-separated entry as `host:port`, resolves hostnames via
/// DNS, and rejects any entry whose IP [`is_private_ip`] blocks — including
/// `169.254.169.254` (cloud metadata), `127.0.0.0/8` (loopback), `10.0.0.0/8`,
/// `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` (link-local), `::1`,
/// `fc00::/7`, `fe80::/10`, and IPv4-mapped IPv6 forms (`::ffff:127.0.0.1`).
/// Unparseable or unresolvable entries are also rejected.
///
/// This is a **fail-fast** security guard: any rejected entry causes the server
/// to refuse to start (the caller surfaces the error via `anyhow`). An
/// allowlist that silently dropped a metadata endpoint would be worse than no
/// allowlist at all — it would give a false sense of safety while leaving the
/// SSRF bypass open.
///
/// Returns the count of valid entries on success (for the
/// `oxbrowser_ssrf_allowlist_entries` gauge).
pub fn validate_allowlist() -> Result<usize> {
    let Ok(list) = std::env::var("OX_HTTP_PRIVATE_ALLOWLIST") else {
        return Ok(0);
    };
    let entries: Vec<&str> = list
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if entries.is_empty() {
        return Ok(0);
    }

    let mut valid = 0usize;
    for entry in &entries {
        // Try parsing as a literal-IP SocketAddr first (covers bare IPs and
        // IPv6 literals like [::1]:80).
        if let Ok(addr) = entry.parse::<SocketAddr>() {
            if is_private_ip(&addr.ip()) {
                tracing::error!(
                    entry = entry,
                    ip = %addr.ip(),
                    "SSRF allowlist entry rejected: private/reserved address"
                );
                return Err(HttpError::InvalidUrl(format!(
                    "SSRF allowlist entry {entry:?} rejected: {} is a private/reserved address",
                    addr.ip()
                )));
            }
            valid += 1;
            continue;
        }

        // Hostname:port — resolve via DNS and check every resolved IP.
        // A hostname that resolves to even one private IP is rejected (fail
        // closed — mirrors the pre-resolve validate_url policy).
        match entry.to_socket_addrs() {
            Ok(addrs) => {
                let resolved: Vec<SocketAddr> = addrs.collect();
                if resolved.is_empty() {
                    tracing::error!(
                        entry = entry,
                        "SSRF allowlist entry rejected: DNS resolved to no addresses"
                    );
                    return Err(HttpError::InvalidUrl(format!(
                        "SSRF allowlist entry {entry:?} rejected: DNS resolved to no addresses"
                    )));
                }
                for sa in &resolved {
                    if is_private_ip(&sa.ip()) {
                        tracing::error!(
                            entry = entry,
                            ip = %sa.ip(),
                            "SSRF allowlist entry rejected: hostname resolves to private/reserved address"
                        );
                        return Err(HttpError::InvalidUrl(format!(
                            "SSRF allowlist entry {entry:?} rejected: hostname resolves to private/reserved address {}",
                            sa.ip()
                        )));
                    }
                }
                valid += 1;
            }
            Err(e) => {
                tracing::error!(
                    entry = entry,
                    error = %e,
                    "SSRF allowlist entry rejected: unparseable or unresolvable"
                );
                return Err(HttpError::InvalidUrl(format!(
                    "SSRF allowlist entry {entry:?} rejected: unparseable or unresolvable: {e}"
                )));
            }
        }
    }
    Ok(valid)
}

/// Returns `true` if the IP address is private, loopback, link-local, or reserved.
///
/// The single, framework-owned SSRF block predicate for this crate — every
/// other guard (the pre-resolve [`validate_url`] and the connect-time
/// [`crate::ssrf_connect::SsrfGuardedResolver`] / redirect-hop check) is
/// built on top of this one function. Mirrors `go-kit/httputil.IsBlockedIP`.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    ip.is_loopback()           // 127.0.0.0/8
        || ip.is_private()     // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local()  // 169.254.0.0/16
        || ip.is_broadcast()   // 255.255.255.255
        || ip.is_unspecified() // 0.0.0.0
        || ip.is_multicast()   // 224.0.0.0/4
        || is_shared_v4(ip)    // 100.64.0.0/10 (CGNAT)
        || is_documentation_v4(ip) // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
}

fn is_private_v6(ip: &Ipv6Addr) -> bool {
    // Rust's `Ipv6Addr` predicates do NOT auto-unwrap an IPv4-mapped
    // address (`::ffff:a.b.c.d`) the way Go's `net.IP.IsLoopback()` et al.
    // do via their internal `To4()` call — so `::ffff:127.0.0.1` would
    // otherwise sail past every check below (`is_loopback()` on the *v6*
    // address checks only for the literal `::1` bit pattern). Unwrap first
    // and re-run the v4 predicate, matching Go's implicit behavior.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_v4(&v4);
    }

    ip.is_loopback()           // ::1
        || ip.is_unspecified() // ::
        || ip.is_multicast()   // ff00::/8 (covers link-local multicast too)
        || is_ula_v6(ip)       // fc00::/7 (unique local)
        || is_link_local_v6(ip) // fe80::/10
        || is_nat64_v6(ip)     // 64:ff9b::/96 (RFC 6052)
        || is_6to4_v6(ip)      // 2002::/16 (RFC 3056, deprecated)
        || is_ipv4_compatible_v6(ip) // ::/96, deprecated IPv4-compatible form
}

/// CGNAT (Shared Address Space) — RFC 6598.
fn is_shared_v4(ip: &Ipv4Addr) -> bool {
    ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64
}

/// Documentation ranges — RFC 5737.
fn is_documentation_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

/// Unique Local Addresses — fc00::/7.
fn is_ula_v6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFE00) == 0xFC00
}

/// Link-local — fe80::/10.
fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFFC0) == 0xFE80
}

/// NAT64 well-known prefix — 64:ff9b::/96 (RFC 6052). Embeds an IPv4
/// address in the low 32 bits; blocking the whole prefix is simpler and
/// safer than unpacking and re-checking the embedded address (mirrors
/// `go-kit/httputil.extraBlockedCIDRs`).
fn is_nat64_v6(ip: &Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0
}

/// 6to4 — 2002::/16 (RFC 3056). Encodes a full IPv4 address in bits 16-47;
/// deprecated and rare in legitimate traffic, so blocking the entire range
/// outright costs nothing.
fn is_6to4_v6(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] == 0x2002
}

/// IPv4-compatible IPv6 — ::/96 (deprecated, RFC 4291 §2.5.5.1), distinct
/// from the IPv4-MAPPED `::ffff:a.b.c.d` form handled via `to_ipv4_mapped()`
/// above. Embeds an IPv4 address in the low 32 bits with an all-zero high
/// 96 bits — this also matches `::` and `::1`, which are already caught by
/// `is_unspecified()`/`is_loopback()` earlier, same as Go's `Contains`
/// behavior on `::/96`.
fn is_ipv4_compatible_v6(ip: &Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0
}

/// Returns `true` if `host` resembles an alternate-encoding numeric IP
/// literal (hex, pure-decimal, or octal-per-component) that
/// `host.parse::<IpAddr>()` rejects but a permissive resolver may still
/// interpret as an IP address — a classic SSRF filter bypass technique.
/// Ported 1:1 from `go-kit/httputil.looksLikeAltEncodedIP` for fleet parity.
fn looks_like_alt_encoded_ip(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if host.to_ascii_lowercase().contains("0x") {
        return true;
    }
    if host.chars().all(|c| c.is_ascii_digit()) {
        // Pure-decimal integer form, e.g. "2130706433" == 127.0.0.1.
        return true;
    }
    for part in host.split('.') {
        let bytes = part.as_bytes();
        if bytes.len() >= 2 && bytes[0] == b'0' && part.chars().all(|c| c.is_ascii_digit()) {
            // Octal-looking dotted component, e.g. "012.0.0.1".
            return true;
        }
    }
    false
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn blocks_loopback() {
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"127.0.0.2".parse().unwrap()));
        assert!(is_private_ip(&"::1".parse().unwrap()));
    }

    #[test]
    fn blocks_private_ranges() {
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.31.255.255".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn blocks_link_local() {
        assert!(is_private_ip(&"169.254.1.1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn blocks_cloud_metadata() {
        // Oracle/AWS/GCP instance-metadata address — subset of link-local,
        // asserted explicitly so a future refactor of the link-local branch
        // can't silently stop covering it (mirrors go-kit's explicit check).
        assert!(is_private_ip(&"169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn blocks_cgnat() {
        assert!(is_private_ip(&"100.64.0.1".parse().unwrap()));
        assert!(is_private_ip(&"100.127.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_special() {
        assert!(is_private_ip(&"0.0.0.0".parse().unwrap()));
        assert!(is_private_ip(&"255.255.255.255".parse().unwrap()));
        assert!(is_private_ip(&"::".parse().unwrap()));
    }

    #[test]
    fn blocks_multicast() {
        assert!(is_private_ip(&"224.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"239.255.255.255".parse().unwrap()));
        assert!(is_private_ip(&"ff02::1".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv4_mapped_v6() {
        assert!(is_private_ip(&"::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"::ffff:169.254.169.254".parse().unwrap()));
        // Mapped PUBLIC v4 must still be allowed.
        assert!(!is_private_ip(&"::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn blocks_nat64() {
        assert!(is_private_ip(&"64:ff9b::127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"64:ff9b::808:808".parse().unwrap()));
    }

    #[test]
    fn blocks_6to4() {
        assert!(is_private_ip(&"2002:c000:0204::1".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv4_compatible_v6() {
        assert!(is_private_ip(&"::127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"::8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn allows_public_ips() {
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"93.184.215.14".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip(&"2606:4700::6810:85e5".parse().unwrap()));
    }

    #[test]
    fn alt_encoded_ip_detection() {
        assert!(looks_like_alt_encoded_ip("2130706433")); // decimal 127.0.0.1
        assert!(looks_like_alt_encoded_ip("0x7f000001")); // hex
        assert!(looks_like_alt_encoded_ip("0X7F000001")); // hex, uppercase
        assert!(looks_like_alt_encoded_ip("012.0.0.1")); // octal component
        assert!(!looks_like_alt_encoded_ip("example.com"));
        assert!(!looks_like_alt_encoded_ip("127.0.0.1")); // real dotted-quad, parses as IpAddr already
        assert!(!looks_like_alt_encoded_ip(""));
    }

    #[test]
    fn validate_blocks_alt_encoded_ip() {
        // Whatever the `url` crate does with these forms internally, the
        // fail-closed heuristic must catch anything that slips through as
        // a non-IP host string.
        for candidate in ["http://2130706433/", "http://0x7f000001/"] {
            match validate_url(candidate) {
                Ok(()) => {
                    // If `url` already normalized this to a literal loopback
                    // IP, the earlier IP-literal branch must have caught it.
                    let parsed = Url::parse(candidate).unwrap();
                    let host = parsed.host_str().unwrap();
                    assert!(
                        host.parse::<IpAddr>().is_ok_and(|ip| is_private_ip(&ip)),
                        "{candidate} was allowed through without being recognized as a blocked literal IP"
                    );
                }
                Err(e) => assert!(e.to_string().contains("SSRF blocked")),
            }
        }
    }

    #[test]
    fn validate_blocks_private() {
        let err = validate_url("http://127.0.0.1:8080/health").unwrap_err();
        assert!(err.to_string().contains("SSRF blocked"));
    }

    #[test]
    fn validate_blocks_private_v6() {
        let err = validate_url("http://[::1]/test").unwrap_err();
        assert!(err.to_string().contains("SSRF blocked"));
    }

    #[test]
    fn validate_allows_public() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("https://8.8.8.8").is_ok());
    }

    #[test]
    fn validate_rejects_bad_scheme() {
        let err = validate_url("ftp://example.com").unwrap_err();
        assert!(err.to_string().contains("scheme is not allowed"));
    }

    #[test]
    fn allowlist_unset_does_not_match() {
        // SAFETY: single-threaded test, no other test reads the same var concurrently.
        unsafe {
            std::env::remove_var("OX_HTTP_PRIVATE_ALLOWLIST");
        }
        assert!(!is_allowlisted("127.0.0.1", 8080));
    }

    // --- validate_allowlist startup validation (issue #28) ---
    //
    // All validation tests run in a single function to avoid env-var races
    // between parallel test threads. Each sub-case sets the var, calls
    // validate_allowlist, and asserts the outcome before the next sub-case.

    #[test]
    fn validate_allowlist_rejects_private_loopback_linklocal_metadata() {
        unsafe {
            // Cloud metadata IP (169.254.169.254) — the primary finding.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "169.254.169.254:80");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("private/reserved"),
                "metadata IP not rejected: {err}"
            );

            // Loopback.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "127.0.0.1:80");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("private/reserved"),
                "loopback not rejected: {err}"
            );

            // Private 10.0.0.0/8.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "10.0.0.1:80");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("private/reserved"),
                "10/8 not rejected: {err}"
            );

            // Private 172.16.0.0/12.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "172.16.0.1:80");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("private/reserved"),
                "172.16/12 not rejected: {err}"
            );

            // Private 192.168.0.0/16.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "192.168.1.1:80");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("private/reserved"),
                "192.168/16 not rejected: {err}"
            );

            // Link-local.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "169.254.1.1:80");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("private/reserved"),
                "link-local not rejected: {err}"
            );

            // IPv6 loopback.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "[::1]:80");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("private/reserved"),
                "::1 not rejected: {err}"
            );

            // IPv4-mapped IPv6 loopback.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "[::ffff:127.0.0.1]:80");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("private/reserved"),
                "::ffff:127.0.0.1 not rejected: {err}"
            );

            // Clean up so other tests see an unset var.
            std::env::remove_var("OX_HTTP_PRIVATE_ALLOWLIST");
        }
    }

    #[test]
    fn validate_allowlist_rejects_unparseable_entries() {
        unsafe {
            // No port — not a valid host:port.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "not-a-valid-entry");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("rejected"),
                "unparseable entry not rejected: {err}"
            );

            // Garbage with a port.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "!!!:80");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("rejected"),
                "garbage entry not rejected: {err}"
            );

            std::env::remove_var("OX_HTTP_PRIVATE_ALLOWLIST");
        }
    }

    #[test]
    fn validate_allowlist_accepts_valid_public_entries() {
        unsafe {
            // Single valid public IP.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "8.8.8.8:80");
            let count = validate_allowlist().expect("valid public IP should pass");
            assert_eq!(count, 1, "valid entry count mismatch");

            // Multiple valid public IPs.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "8.8.8.8:80,1.1.1.1:443");
            let count = validate_allowlist().expect("valid public IPs should pass");
            assert_eq!(count, 2, "valid entry count mismatch for multiple");

            // Whitespace is trimmed.
            std::env::set_var(
                "OX_HTTP_PRIVATE_ALLOWLIST",
                "  8.8.8.8:80  ,  1.1.1.1:443  ",
            );
            let count = validate_allowlist().expect("trimmed valid IPs should pass");
            assert_eq!(count, 2, "whitespace trimming broke count");

            std::env::remove_var("OX_HTTP_PRIVATE_ALLOWLIST");
        }
    }

    #[test]
    fn validate_allowlist_unset_returns_zero() {
        unsafe {
            std::env::remove_var("OX_HTTP_PRIVATE_ALLOWLIST");
        }
        assert_eq!(validate_allowlist().unwrap(), 0);

        unsafe {
            // Empty string → zero entries.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "");
        }
        assert_eq!(validate_allowlist().unwrap(), 0);

        unsafe {
            // Only commas/whitespace → zero entries.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "  ,  ,  ");
        }
        assert_eq!(validate_allowlist().unwrap(), 0);

        unsafe {
            std::env::remove_var("OX_HTTP_PRIVATE_ALLOWLIST");
        }
    }

    #[test]
    fn validate_allowlist_rejects_hostname_resolving_to_private() {
        unsafe {
            // `localhost` resolves to 127.0.0.1 on any standard Linux host —
            // the startup guard must reject it. If DNS is unavailable the
            // entry is still rejected (unresolvable), so the assertion holds
            // either way.
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "localhost:80");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("rejected"),
                "localhost should be rejected: {err}"
            );

            std::env::remove_var("OX_HTTP_PRIVATE_ALLOWLIST");
        }
    }

    #[test]
    fn validate_allowlist_rejects_mixed_valid_and_private() {
        unsafe {
            // A valid public entry followed by a private one — the first
            // valid entry is counted, but the private one must still cause
            // a hard failure (fail fast, do not silently drop).
            std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", "8.8.8.8:80,127.0.0.1:80");
            let err = validate_allowlist().unwrap_err();
            assert!(
                err.to_string().contains("private/reserved"),
                "private entry in mixed list not rejected: {err}"
            );

            std::env::remove_var("OX_HTTP_PRIVATE_ALLOWLIST");
        }
    }

    #[test]
    #[serial_test::serial]
    fn validate_proxy_url_allowlist_admits_only_listed_host_port() {
        unsafe {
            std::env::set_var(PROXY_ALLOWLIST_ENV, "127.0.0.1:9050, 172.18.0.1:1082");
        }
        assert!(validate_proxy_url("http://172.18.0.1:1082").is_ok());
        // A listed loopback entry is admitted — the allowlist is checked
        // before the private-host veto.
        assert!(validate_proxy_url("http://127.0.0.1:9050").is_ok());
        assert!(validate_proxy_url("http://172.18.0.1:8765").is_err());
        unsafe {
            std::env::remove_var(PROXY_ALLOWLIST_ENV);
        }
        assert!(validate_proxy_url("http://172.18.0.1:1082").is_err());
        assert!(validate_proxy_url("http://p.webshare.io:80").is_ok());
        assert!(validate_proxy_url("http://user:pw@8.8.8.8:80").is_ok());
        assert!(validate_proxy_url("http://0x7f000001:80").is_err());
    }

    /// Proxy credentials must never reach logs (SEC-CR-008).
    ///
    /// Falsification: make `redact_proxy_userinfo` return its input and the
    /// password appears → RED.
    #[test]
    fn redact_proxy_userinfo_strips_credentials() {
        assert_eq!(
            redact_proxy_userinfo("http://USERTOK:S3CRETPW@p.webshare.io:80"),
            "http://***@p.webshare.io:80"
        );
        // A refused scheme (issue #179) redacts to the placeholder, same
        // as any unparsable input — no credential can be echoed through it.
        assert_eq!(
            redact_proxy_userinfo("SOCKS5://USERTOK:S3CRETPW@1.2.3.4"),
            UNPARSABLE_PROXY
        );
        assert_eq!(
            redact_proxy_userinfo("http://[2001:db8::1]:3128/"),
            "http://[2001:db8::1]:3128"
        );
        assert_eq!(
            redact_proxy_userinfo("USERTOK:S3CRETPW@[bad"),
            UNPARSABLE_PROXY
        );
    }

    /// Proxy URLs the strict grammar refuses. Each carries a distinctive
    /// username and password (or none), and the url crate would otherwise
    /// read part of the credential as the host, port, path, query or
    /// fragment, or take the host from a trailing `://`.
    pub(crate) const SMUGGLED_PROXY_ROWS: &[&str] = &[
        // SEC-CR-021: '/', '?', '#' before the userinfo '@'.
        "http://USERTOK:12#S3CRETPW@127.0.0.1:3128",
        "http://USERTOK:/S3CRETPW@127.0.0.1:3128",
        "socks5://USERTOK:?S3CRETPW@127.0.0.1:1080",
        // SEC-CR-022: url accepts `http:` / `http:/` as the authority start;
        // the socks variant took its host from the trailing `://`.
        "http:/USERTOK:12#S3CRETPW@127.0.0.1:3128://x",
        "socks5:/USERTOK:12#S3CRETPW@127.0.0.1:1080://x",
        "http:USERTOK:S3CRETPW@127.0.0.1:3128",
        "HTTP:/USERTOK:S3CRETPW@127.0.0.1:3128",
        "https:/USERTOK:S3CRETPW@127.0.0.1:3128",
        "socks5:/USERTOK:S3CRETPW@127.0.0.1:1080",
        "http://USERTOK:S3CRETPW@127.0.0.1:3128://x",
        // SEC-CR-024: '\' ends a special-scheme authority.
        "http://USERTOK:12345\\S3CRETPW@127.0.0.1:3128",
        // SEC-CR-023: bare host:port that is not one.
        "http:/127.0.0.1:3128",
        "socks5:/127.0.0.1:1080",
        "127.0.0.1#x:3128",
        "127.0.0.1/x:3128",
        "127.0.0.1?x:3128",
        "USERTOK:S3CRETPW@127.0.0.1:3128",
        "USERTOK:12#S3CRETPW@127.0.0.1:3128",
        // SEC-CR-025: a "scheme" that is really the username.
        "USERTOK://S3CRETPW@127.0.0.1:3128",
        // SEC-CR-026: dot-segments collapse the path to "/" after parsing,
        // hiding the '/' that ended the authority before the userinfo '@'.
        "http://USERTOK:12/S3CRETPW@127.0.0.1:9/..",
        "http://USERTOK:12/S3CRETPW@127.0.0.1:9/%2e%2e",
        "socks5://USERTOK:12/S3CRETPW@127.0.0.1:9/..",
        "https://USERTOK:443/S3CRETPW@127.0.0.1:9/a/..",
        "http://USERTOK:12/./S3CRETPW@127.0.0.1:9/../..",
        "http://USERTOK:12\\S3CRETPW@127.0.0.1:9/",
    ];

    /// True when `text` carries either credential token, in any case (the
    /// url crate lowercases a host, so a username read as host is `usertok`).
    pub(crate) fn leaks_credentials(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        lower.contains("usertok") || lower.contains("s3cretpw")
    }

    /// SEC-CR-021..025: every smuggled form is refused by the canonicaliser
    /// with an error that names neither credential, and the redactor prints
    /// exactly the placeholder for it.
    ///
    /// Falsification (each RED):
    /// - drop the "no path, query or fragment" checks in
    ///   `canonicalise_proxy_url` → the '#'/'/'/'?' rows canonicalise to host
    ///   `usertok`;
    /// - drop only the raw-text authority check (keep the post-parse one) →
    ///   the SEC-CR-026 dot-segment rows canonicalise to host `usertok`;
    /// - drop `'@'` from the bare host:port refusal → the bare userinfo row
    ///   canonicalises;
    /// - interpolate the text before "://" into the unsupported-scheme error
    ///   (`format!("unsupported proxy scheme {s:?}")`) → the USERTOK:// row's
    ///   error carries the username;
    /// - make `redact_proxy_userinfo` re-serialise `url::Url::parse` output
    ///   instead of building on `canonicalise_proxy_url` → the redactor rows
    ///   are no longer the placeholder and leak.
    #[test]
    fn smuggled_proxy_urls_are_refused_and_never_echoed() {
        for raw in SMUGGLED_PROXY_ROWS {
            match canonicalise_proxy_url(raw) {
                Ok(c) => panic!("canonicalised {raw:?} to {}", c.url),
                Err(e) => assert!(!leaks_credentials(&e.to_string()), "{raw:?}: error {e}"),
            }
            assert_eq!(redact_proxy_userinfo(raw), UNPARSABLE_PROXY, "{raw:?}");
        }
    }

    /// A non-special scheme (a `socks*` URL) keeps its host opaque in
    /// WHATWG parsing — and since #179 it is refused outright, before the
    /// host is ever looked at. IPv4 shorthand under a special scheme is
    /// still canonicalised by the parse itself (`127.1` → `127.0.0.1`,
    /// which the private-host veto then blocks).
    ///
    /// Falsification: re-add `"socks5"` to `ALLOWED_PROXY_SCHEMES` and the
    /// public socks row validates → RED.
    #[test]
    fn validate_proxy_url_refuses_non_special_scheme_hosts() {
        assert!(validate_proxy_url("socks5://127.1:1080").is_err());
        assert!(validate_proxy_url("http://127.1:1080").is_err());
        assert!(validate_proxy_url("socks5://8.8.8.8:1080").is_err());
        assert!(validate_proxy_url("http://8.8.8.8:1080").is_ok());
    }

    /// SEC-CR-028: a trailing dot names the same host, and IDNA maps the
    /// ideographic / fullwidth full stops to '.', so none may slip past the
    /// localhost refusal.
    ///
    /// Falsification: drop the `strip_suffix('.')` in `validate_proxy_url`
    /// and the rows validate → RED.
    #[test]
    fn validate_proxy_url_refuses_trailing_dot_localhost() {
        for host in [
            "localhost.",
            "foo.localhost.",
            "localhost\u{3002}",
            "localhost\u{FF0E}",
        ] {
            for scheme in ["http", "https"] {
                let raw = format!("{scheme}://{host}:3128");
                assert!(validate_proxy_url(&raw).is_err(), "accepted {raw:?}");
            }
        }
    }
    /// SEC-CR-001: the url/wreq parser differential. A backslash or control
    /// character in the authority makes one parser read a different host
    /// than another. validate_proxy_url refuses the illegal byte, and the
    /// string it returns for a legitimate proxy canonicalises the host so
    /// the caller never dials the raw input. The `socks*` rows double as
    /// scheme refusals (issue #179).
    ///
    /// Falsification: drop the backslash/illegal-char guard and the http
    /// backslash row is accepted → RED.
    #[test]
    fn validate_proxy_url_refuses_parser_differential_forms() {
        for raw in [
            "socks5://1.1.1.1\\@127.0.0.1:6379",
            "socks5h://1.1.1.1\\@127.0.0.1:6379",
            "socks4://1.1.1.1\\@127.0.0.1:6379",
            "http://1.1.1.1\\@127.0.0.1:6379",
            "socks5://1.1.1.1\t@127.0.0.1:6379",
        ] {
            assert!(
                validate_proxy_url(raw).is_err(),
                "parser-differential proxy accepted: {raw:?}"
            );
        }
    }

    /// The returned dial string is canonical: original scheme, canonical
    /// host, preserved credentials — never the raw input.
    #[test]
    fn validate_proxy_url_returns_canonical_dial_string() {
        assert_eq!(
            validate_proxy_url("http://alice:pw@8.8.8.8:80").unwrap(),
            "http://alice:pw@8.8.8.8:80" // the dialled port is always explicit
        );
        // No port given: the scheme default is vetted and emitted
        // explicitly, so the vetted port is the dialled port.
        assert_eq!(
            validate_proxy_url("http://8.8.8.8").unwrap(),
            "http://8.8.8.8:80"
        );
        assert_eq!(
            validate_proxy_url("https://8.8.8.8").unwrap(),
            "https://8.8.8.8:443"
        );
    }

    /// SEC-CR-018: the dial string wreq gets has a lowercase scheme and an
    /// explicit port, whatever the input's case or an empty port.
    #[test]
    fn canonicalise_proxy_url_lowercases_scheme_and_fills_empty_port() {
        for (raw, want) in [
            ("HTTP://8.8.8.8:3128", "http://8.8.8.8:3128"),
            ("http://8.8.8.8:", "http://8.8.8.8:80"),
            ("HTTPS://u:p@8.8.8.8", "https://u:p@8.8.8.8:443"),
        ] {
            assert_eq!(canonicalise_proxy_url(raw).unwrap().url, want, "{raw}");
        }
    }

    /// SEC-CR-012: a scheme wreq has no intercept for would be ignored and the
    /// request sent direct. Only the allowlisted schemes validate — the
    /// `socks*` family included, since wreq is built without its `socks`
    /// feature (issue #179).
    ///
    /// Falsification: drop the ALLOWED_PROXY_SCHEMES check in
    /// canonicalise_proxy_url and the refused rows validate → RED.
    #[test]
    fn validate_proxy_url_refuses_unknown_schemes() {
        for raw in [
            "ftp://8.8.8.8:21",
            "socks://8.8.8.8:1080",
            "socks4://8.8.8.8:1080",
            "socks4a://8.8.8.8:1080",
            "socks5://8.8.8.8:1080",
            "socks5h://8.8.8.8:1080",
            "gopher://8.8.8.8:70",
            "file://8.8.8.8/x",
        ] {
            assert!(validate_proxy_url(raw).is_err(), "accepted {raw}");
        }
        for ok in ["http://8.8.8.8:3128", "https://8.8.8.8:443"] {
            assert!(validate_proxy_url(ok).is_ok(), "refused {ok}");
        }
    }

    /// #179: wreq is built WITHOUT its `socks` feature, so a SOCKS proxy URL
    /// is never a SOCKS dial — it would fall through to wreq's auto-proxy
    /// path and the request can go DIRECT from the real IP. Every `socks*`
    /// scheme, in any letter case, is refused with an error that names the
    /// scheme. `http` and `https` still validate.
    ///
    /// Falsification: re-add `"socks5"` to `ALLOWED_PROXY_SCHEMES` → the
    /// socks5 rows validate → RED.
    #[test]
    fn validate_proxy_url_refuses_socks_schemes() {
        for (raw, scheme) in [
            ("socks4://8.8.8.8:1080", "socks4"),
            ("socks4a://8.8.8.8:1080", "socks4a"),
            ("socks5://8.8.8.8:1080", "socks5"),
            ("socks5h://8.8.8.8:1080", "socks5h"),
            ("SOCKS5://8.8.8.8:1080", "socks5"),
            ("Socks5H://8.8.8.8:1080", "socks5h"),
        ] {
            let err = validate_proxy_url(raw).expect_err("a SOCKS proxy must be refused");
            let msg = err.to_string();
            assert!(
                msg.contains("unsupported proxy scheme"),
                "{raw}: expected the unsupported-scheme refusal, got {err}"
            );
            assert!(
                msg.contains(scheme),
                "{raw}: the refusal must name the scheme, got {err}"
            );
        }
        assert!(validate_proxy_url("http://8.8.8.8:3128").is_ok());
        assert!(validate_proxy_url("https://8.8.8.8:443").is_ok());
    }

    /// SEC-CR-013: an explicit non-default port must survive
    /// canonicalisation, and a port-less proxy must be VETTED at the port it
    /// is actually dialled at — the scheme default — not at whatever port an
    /// allowlist entry names.
    ///
    /// Falsification: vet a port-less URL against a port other than the
    /// scheme default → the :8080 allowlist row wrongly admits a :80 dial →
    /// RED.
    #[test]
    #[serial_test::serial]
    fn validate_proxy_url_ports_are_explicit_and_vetted() {
        assert_eq!(
            validate_proxy_url("http://8.8.8.8:81").unwrap(),
            "http://8.8.8.8:81"
        );
        unsafe { std::env::set_var(PROXY_ALLOWLIST_ENV, "10.9.9.9:8080") };
        let listed_default = validate_proxy_url("http://10.9.9.9");
        let listed_8080 = validate_proxy_url("http://10.9.9.9:8080");
        unsafe { std::env::remove_var(PROXY_ALLOWLIST_ENV) };
        assert_eq!(listed_8080.unwrap(), "http://10.9.9.9:8080");
        assert!(
            listed_default.is_err(),
            "a port-less proxy is vetted at :80 — the :8080 listing must not admit it"
        );
    }
}
