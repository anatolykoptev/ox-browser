use crate::profile::BrowserProfile;

/// Chrome-like default header order for anti-fingerprint consistency.
/// Used by HttpClient (Task 6) to reorder outgoing headers.
pub static DEFAULT_HEADER_ORDER: &[&str] = &[
    "accept",
    "accept-language",
    "accept-encoding",
    "referer",
    "cookie",
    "user-agent",
];

/// Returns `sec-ch-ua-*` client hint headers for Chromium-based user agents.
/// Returns empty vec for Firefox/Safari (they don't send Client Hints).
pub fn client_hints_headers(ua: &str) -> Vec<(String, String)> {
    if !ua.contains("Chrome/") {
        return Vec::new();
    }
    let version = extract_chrome_version(ua);
    let platform = extract_platform(ua);
    let mobile = if ua.contains("Mobile") { "?1" } else { "?0" };

    let mut hints = vec![
        (
            "sec-ch-ua".to_owned(),
            format!("\"Chromium\";v=\"{version}\", \"Not_A Brand\";v=\"24\""),
        ),
        ("sec-ch-ua-mobile".to_owned(), mobile.to_owned()),
        (
            "sec-ch-ua-platform".to_owned(),
            format!("\"{platform}\""),
        ),
    ];

    // Edge adds its own brand alongside Chromium.
    if ua.contains("Edg/") {
        let edge_ver = extract_edge_version(ua);
        hints[0].1 = format!(
            "\"Chromium\";v=\"{version}\", \"Microsoft Edge\";v=\"{edge_ver}\", \"Not_A Brand\";v=\"24\""
        );
    }

    hints
}

/// Builds common browser headers from a profile (UA + client hints).
/// Accept header varies by browser to match real fingerprints.
pub fn browser_headers(profile: &BrowserProfile) -> Vec<(String, String)> {
    let accept = match profile.browser {
        "chrome" | "edge" => "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "firefox" => "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
        _ => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", // Safari
    };
    let mut headers = vec![
        ("user-agent".to_owned(), profile.user_agent.to_owned()),
        ("accept".to_owned(), accept.to_owned()),
        ("accept-language".to_owned(), "en-US,en;q=0.9".to_owned()),
        ("accept-encoding".to_owned(), "gzip, deflate, br".to_owned()),
    ];
    headers.extend(client_hints_headers(profile.user_agent));
    headers
}

/// Extracts the major Chrome version number from a user-agent string.
fn extract_chrome_version(ua: &str) -> &str {
    let Some(idx) = ua.find("Chrome/") else { return "131" };
    let rest = &ua[idx + 7..];
    match rest.find('.') {
        Some(dot) => &rest[..dot],
        None => rest,
    }
}

/// Extracts the major Edge version number from a user-agent string.
fn extract_edge_version(ua: &str) -> &str {
    let Some(idx) = ua.find("Edg/") else { return "131" };
    let rest = &ua[idx + 4..];
    match rest.find('.') {
        Some(dot) => &rest[..dot],
        None => rest,
    }
}

/// Maps UA platform strings to Client Hints platform values.
fn extract_platform(ua: &str) -> &'static str {
    if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Macintosh") || ua.contains("Mac OS X") {
        "macOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "Windows"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::BUILTIN_PROFILES;

    #[test]
    fn chrome_hints() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
        let hints = client_hints_headers(ua);
        assert_eq!(hints.len(), 3);
        assert!(hints[0].1.contains("Chromium"));
        assert!(hints[0].1.contains("131"));
        assert_eq!(hints[1].1, "?0");
        assert_eq!(hints[2].1, "\"Windows\"");
    }

    #[test]
    fn edge_hints_include_brand() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0";
        let hints = client_hints_headers(ua);
        assert!(hints[0].1.contains("Microsoft Edge"));
        assert!(hints[0].1.contains("Chromium"));
    }

    #[test]
    fn firefox_no_hints() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0";
        assert!(client_hints_headers(ua).is_empty());
    }

    #[test]
    fn safari_no_hints() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15";
        assert!(client_hints_headers(ua).is_empty());
    }

    #[test]
    fn mobile_hint_flag() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36";
        let hints = client_hints_headers(ua);
        assert_eq!(hints[1].1, "?1");
        assert_eq!(hints[2].1, "\"Android\"");
    }

    #[test]
    fn browser_headers_include_ua_and_hints() {
        let chrome = &BUILTIN_PROFILES[0]; // Chrome Windows
        let hdrs = browser_headers(chrome);
        assert!(hdrs.iter().any(|(k, _)| k == "user-agent"));
        assert!(hdrs.iter().any(|(k, _)| k == "sec-ch-ua"));
    }

    #[test]
    fn browser_headers_safari_no_hints() {
        let safari = &BUILTIN_PROFILES[7]; // Safari macOS
        let hdrs = browser_headers(safari);
        assert!(hdrs.iter().any(|(k, _)| k == "user-agent"));
        assert!(!hdrs.iter().any(|(k, _)| k == "sec-ch-ua"));
    }

    #[test]
    fn default_header_order_defined() {
        assert!(DEFAULT_HEADER_ORDER.len() >= 6);
        assert!(DEFAULT_HEADER_ORDER.contains(&"user-agent"));
    }

    #[test]
    fn extract_chrome_version_works() {
        assert_eq!(extract_chrome_version("Chrome/133.0.0.0 Safari"), "133");
        assert_eq!(extract_chrome_version("Firefox/133.0"), "131");
    }

    #[test]
    fn extract_edge_version_works() {
        assert_eq!(extract_edge_version("Edg/131.0.0.0"), "131");
        assert_eq!(extract_edge_version("NoEdge"), "131");
    }

    #[test]
    fn platform_detection() {
        assert_eq!(extract_platform("Windows NT 10.0"), "Windows");
        assert_eq!(extract_platform("Macintosh; Intel"), "macOS");
        assert_eq!(extract_platform("Linux; Android 14"), "Android");
        assert_eq!(extract_platform("iPhone; CPU"), "iOS");
        assert_eq!(extract_platform("X11; Linux"), "Linux");
        assert_eq!(extract_platform("Unknown"), "Windows");
    }
}
