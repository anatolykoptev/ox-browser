use rand::seq::SliceRandom;

use crate::profile::BrowserProfile;

/// GREASE brands used by Chrome to detect servers that reject unknown brands.
/// Randomized per call to avoid static fingerprinting.
const GREASE_BRANDS: &[&str] = &[
    r#""Not_A Brand";v="8""#,
    r#""Not/A)Brand";v="8""#,
    r#""Not A(Brand";v="99""#,
    r#""Not:A-Brand";v="99""#,
];

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
/// GREASE brand is randomized per call to avoid static fingerprinting.
pub fn client_hints_headers(ua: &str) -> Vec<(String, String)> {
    if !ua.contains("Chrome/") {
        return Vec::new();
    }
    let version = extract_chrome_version(ua);
    let full_version = extract_chrome_full_version(ua);
    let platform = extract_platform(ua);
    let mobile = if ua.contains("Mobile") { "?1" } else { "?0" };

    let mut rng = rand::thread_rng();
    let grease = GREASE_BRANDS.choose(&mut rng).expect("GREASE_BRANDS non-empty");
    // Extract GREASE brand name and version for full-version-list (needs .0.0.0 suffix).
    let grease_full = grease_to_full_version(grease);

    let mut hints = vec![
        (
            "sec-ch-ua".to_owned(),
            format!("\"Chromium\";v=\"{version}\", \"Google Chrome\";v=\"{version}\", {grease}"),
        ),
        ("sec-ch-ua-mobile".to_owned(), mobile.to_owned()),
        (
            "sec-ch-ua-platform".to_owned(),
            format!("\"{platform}\""),
        ),
        (
            "sec-ch-ua-full-version-list".to_owned(),
            format!(
                "\"Chromium\";v=\"{full_version}\", \"Google Chrome\";v=\"{full_version}\", {grease_full}"
            ),
        ),
    ];

    // Edge adds its own brand alongside Chromium.
    if ua.contains("Edg/") {
        let edge_ver = extract_edge_version(ua);
        let edge_full = extract_edge_full_version(ua);
        hints[0].1 = format!(
            "\"Chromium\";v=\"{version}\", \"Microsoft Edge\";v=\"{edge_ver}\", {grease}"
        );
        hints[3].1 = format!(
            "\"Chromium\";v=\"{full_version}\", \"Microsoft Edge\";v=\"{edge_full}\", {grease_full}"
        );
    }

    hints
}

/// Converts a GREASE brand like `"Not_A Brand";v="8"` to full-version format
/// like `"Not_A Brand";v="8.0.0.0"`.
fn grease_to_full_version(grease: &str) -> String {
    // Find the version value between the last pair of quotes.
    if let Some(last_quote) = grease.rfind('"') {
        if let Some(second_last) = grease[..last_quote].rfind('"') {
            let ver = &grease[second_last + 1..last_quote];
            let prefix = &grease[..second_last + 1];
            return format!("{prefix}{ver}.0.0.0\"");
        }
    }
    grease.to_owned()
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
    let Some(idx) = ua.find("Chrome/") else { return "145" };
    let rest = &ua[idx + 7..];
    match rest.find('.') {
        Some(dot) => &rest[..dot],
        None => rest,
    }
}

/// Extracts the full Chrome version (e.g. "145.0.0.0") from a user-agent string.
fn extract_chrome_full_version(ua: &str) -> &str {
    let Some(idx) = ua.find("Chrome/") else { return "145.0.0.0" };
    let rest = &ua[idx + 7..];
    match rest.find(' ') {
        Some(sp) => &rest[..sp],
        None => rest,
    }
}

/// Extracts the major Edge version number from a user-agent string.
fn extract_edge_version(ua: &str) -> &str {
    let Some(idx) = ua.find("Edg/") else { return "145" };
    let rest = &ua[idx + 4..];
    match rest.find('.') {
        Some(dot) => &rest[..dot],
        None => rest,
    }
}

/// Extracts the full Edge version (e.g. "145.0.0.0") from a user-agent string.
fn extract_edge_full_version(ua: &str) -> &str {
    let Some(idx) = ua.find("Edg/") else { return "145.0.0.0" };
    let rest = &ua[idx + 4..];
    match rest.find(' ') {
        Some(sp) => &rest[..sp],
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
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";
        let hints = client_hints_headers(ua);
        assert_eq!(hints.len(), 4);
        assert!(hints[0].1.contains("Chromium"));
        assert!(hints[0].1.contains("145"));
        assert!(hints[0].1.contains("Google Chrome"));
        assert_eq!(hints[1].1, "?0");
        assert_eq!(hints[2].1, "\"Windows\"");
        // sec-ch-ua-full-version-list
        assert_eq!(hints[3].0, "sec-ch-ua-full-version-list");
        assert!(hints[3].1.contains("145.0.0.0"));
    }

    #[test]
    fn grease_brand_is_randomized() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let hints = client_hints_headers(ua);
            seen.insert(hints[0].1.clone());
        }
        // With 4 GREASE brands and 100 iterations, we should see at least 2 variants.
        assert!(seen.len() >= 2, "GREASE brand should be randomized, saw only {} variant(s)", seen.len());
    }

    #[test]
    fn edge_hints_include_brand() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0";
        let hints = client_hints_headers(ua);
        assert!(hints[0].1.contains("Microsoft Edge"));
        assert!(hints[0].1.contains("Chromium"));
        // Full version list should also have Edge
        assert!(hints[3].1.contains("Microsoft Edge"));
    }

    #[test]
    fn firefox_no_hints() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0";
        assert!(client_hints_headers(ua).is_empty());
    }

    #[test]
    fn safari_no_hints() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15";
        assert!(client_hints_headers(ua).is_empty());
    }

    #[test]
    fn mobile_hint_flag() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36";
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
        assert_eq!(extract_chrome_version("Chrome/145.0.0.0 Safari"), "145");
        assert_eq!(extract_chrome_version("Firefox/138.0"), "145");
    }

    #[test]
    fn extract_edge_version_works() {
        assert_eq!(extract_edge_version("Edg/145.0.0.0"), "145");
        assert_eq!(extract_edge_version("NoEdge"), "145");
    }

    #[test]
    fn extract_full_versions() {
        assert_eq!(extract_chrome_full_version("Chrome/145.0.7632.159 Safari"), "145.0.7632.159");
        assert_eq!(extract_edge_full_version("Edg/145.0.2903.70"), "145.0.2903.70");
    }

    #[test]
    fn grease_to_full_version_format() {
        assert_eq!(
            grease_to_full_version(r#""Not_A Brand";v="8""#),
            r#""Not_A Brand";v="8.0.0.0""#
        );
        assert_eq!(
            grease_to_full_version(r#""Not A(Brand";v="99""#),
            r#""Not A(Brand";v="99.0.0.0""#
        );
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
