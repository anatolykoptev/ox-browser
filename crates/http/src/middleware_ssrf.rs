//! SSRF protection middleware — blocks requests to private/reserved IPs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
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

    // Try parsing as IP directly first.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Err(HttpError::InvalidUrl(format!(
                "SSRF blocked: {host} is a private/reserved address"
            )));
        }
        return Ok(());
    }

    // Resolve hostname to IP addresses.
    let port = url.port_or_known_default().unwrap_or(80);
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

/// Returns `true` if the IP address is private, loopback, link-local, or reserved.
fn is_private_ip(ip: &IpAddr) -> bool {
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
        || is_shared_v4(ip)    // 100.64.0.0/10 (CGNAT)
        || is_documentation_v4(ip) // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
}

fn is_private_v6(ip: &Ipv6Addr) -> bool {
    ip.is_loopback()           // ::1
        || ip.is_unspecified() // ::
        || is_ula_v6(ip)       // fc00::/7 (unique local)
        || is_link_local_v6(ip) // fe80::/10
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
    fn allows_public_ips() {
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"93.184.215.14".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip(&"2606:4700::6810:85e5".parse().unwrap()));
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
}
