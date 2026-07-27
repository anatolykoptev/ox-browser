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
    Arc::new(move |next: Arc<dyn Handler>| {
        let handler: Arc<dyn Handler> = Arc::new(SsrfGuard { next });
        handler
    })
}

struct SsrfGuard {
    next: Arc<dyn Handler>,
}

#[async_trait]
impl Handler for SsrfGuard {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        validate_url(&req.url)?;
        self.next.handle(req).await
    }
}

/// Validate that a URL does not target a private/reserved IP.
///
/// Pre-resolve tier — see the module doc for why this alone is not
/// rebind-proof, and [`crate::ssrf_connect`] for the tier that is.
pub fn validate_url(url_str: &str) -> Result<()> {
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
    let addr = format!("{host}:{port}");
    if let Ok(addrs) = addr.to_socket_addrs() {
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
mod tests {
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
}
