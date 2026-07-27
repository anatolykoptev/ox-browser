//! Shared URL utilities — single source of truth for host/domain extraction.
//!
//! All URL parsing in the workspace should use these helpers instead of
//! hand-rolled string manipulation, which fails on userinfo (`user:pass@host`),
//! non-default ports, IDN domains, and URLs without a scheme.

use url::Url;

/// Extract the host (without port) from a URL string.
///
/// Returns `None` for relative URLs, fragment-only strings, or unparseable
/// input. For valid URLs the host is returned as-is (no lowercasing —
/// `url::Url` already normalises IPv6 brackets away and returns the host in
/// its canonical form, including punycode for IDN domains).
///
/// ```
/// assert_eq!(ox_http::extract_domain("https://api.example.com/p"), Some("api.example.com".into()));
/// assert_eq!(ox_http::extract_domain("http://example.com:8080/x"), Some("example.com".into()));
/// assert_eq!(ox_http::extract_domain("not-a-url"), None);
/// ```
pub fn extract_domain(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
}

/// Alias for [`extract_domain`] — same semantics, clearer name when the
/// call site is interested in the "host" rather than the "domain".
pub fn extract_host(url: &str) -> Option<String> {
    extract_domain(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        assert_eq!(
            extract_domain("https://api.example.com/p"),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn with_port() {
        assert_eq!(
            extract_domain("http://example.com:8080/x"),
            Some("example.com".into())
        );
    }

    #[test]
    fn userinfo() {
        assert_eq!(
            extract_domain("https://user:pass@example.com/p"),
            Some("example.com".into())
        );
    }

    #[test]
    fn ip_address() {
        assert_eq!(
            extract_domain("http://192.168.1.1/page"),
            Some("192.168.1.1".into())
        );
    }

    #[test]
    fn idn_punycode() {
        // url::Url converts IDN hosts to punycode; www. is preserved as-is.
        assert_eq!(
            extract_domain("https://www.例え.jp/path"),
            Some("www.xn--r8jz45g.jp".into())
        );
    }

    #[test]
    fn invalid_returns_none() {
        assert_eq!(extract_domain("not-a-url"), None);
        assert_eq!(extract_domain(""), None);
        assert_eq!(extract_domain("/relative/path"), None);
    }

    #[test]
    fn extract_host_alias() {
        assert_eq!(
            extract_host("https://example.com/x"),
            Some("example.com".into())
        );
    }
}
