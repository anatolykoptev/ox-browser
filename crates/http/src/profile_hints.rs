use crate::profile::BrowserProfile;

// ── sec-ch-ua brand list ───────────────────────────────────────────────
//
// Chromium derives the `sec-ch-ua` brand list from the Chromium major
// version alone (components/embedder_support/user_agent_utils.cc,
// `GetGreasedUserAgentBrandVersion` + `GenerateBrandVersionList`): the GREASE
// brand name, its version and the position of the three entries are all
// functions of the major, so one release always sends the same string. A
// per-request random choice therefore cannot equal what any real release
// sends.
//
// The derivation follows the algorithm implemented by go-stealth
// (`secChUa`, v1.29.0, Apache-2.0). See THIRD_PARTY_NOTICES.md.

/// Characters Chromium splices into the GREASE brand name `Not?A?Brand`.
const GREASE_CHARS: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];

/// GREASE brand versions Chromium cycles through.
const GREASE_VERSIONS: [&str; 3] = ["8", "99", "24"];

/// Entry permutations Chromium picks from (`seed % 6`). `ORDERS[i][k]` is the
/// output position of the k-th entry of `[GREASE, Chromium, product brand]`.
const ORDERS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

/// Renders the three-entry brand list (GREASE, Chromium, product brand) in
/// the order Chromium uses for `seed`. `grease_suffix` is appended to the
/// GREASE version (`""` for `sec-ch-ua`, `".0.0.0"` for the full version list).
fn brand_list(
    seed: usize,
    chromium: &str,
    brand: &str,
    brand_version: &str,
    grease_suffix: &str,
) -> String {
    let grease = format!(
        r#""Not{}A{}Brand";v="{}{}""#,
        GREASE_CHARS[seed % GREASE_CHARS.len()],
        GREASE_CHARS[(seed + 1) % GREASE_CHARS.len()],
        GREASE_VERSIONS[seed % GREASE_VERSIONS.len()],
        grease_suffix,
    );
    let entries = [
        grease,
        format!(r#""Chromium";v="{chromium}""#),
        format!(r#""{brand}";v="{brand_version}""#),
    ];
    let mut out: [Option<String>; 3] = [None, None, None];
    for (entry, pos) in entries.into_iter().zip(ORDERS[seed % ORDERS.len()]) {
        out[pos] = Some(entry);
    }
    out.into_iter().flatten().collect::<Vec<_>>().join(", ")
}

/// Chromium major used as the derivation seed; 0 when it is not a number.
fn seed_of(major: &str) -> usize {
    major.parse().unwrap_or(0)
}

/// The `sec-ch-ua` value a Chromium-based browser of `chromium_major` sends.
/// `brand` / `brand_version` name the product (`"Google Chrome"` with the same
/// major, or `"Microsoft Edge"` with the Edge major).
///
/// The single builder for this header: `tls::chrome_headers`,
/// `tls::edge_headers` and [`client_hints_headers`] all call it.
pub fn sec_ch_ua(chromium_major: &str, brand: &str, brand_version: &str) -> String {
    brand_list(
        seed_of(chromium_major),
        chromium_major,
        brand,
        brand_version,
        "",
    )
}

/// The `sec-ch-ua-full-version-list` value: same brands and order as
/// [`sec_ch_ua`], with full versions (the GREASE brand carries `X.0.0.0`).
pub fn sec_ch_ua_full_version_list(
    chromium_major: &str,
    chromium_full: &str,
    brand: &str,
    brand_full: &str,
) -> String {
    brand_list(
        seed_of(chromium_major),
        chromium_full,
        brand,
        brand_full,
        ".0.0.0",
    )
}

/// Chrome-like default header order for anti-fingerprint consistency.
/// Used by HttpClient (Task 6) to reorder outgoing headers.
///
/// Matches the wire order real Chrome emits (verified via the fingerprint
/// oracle against Chrome 148). The old order was wrong — it put accept
/// before sec-ch-ua and omitted sec-fetch-* and upgrade-insecure-requests.
/// See Issue #80.
pub static DEFAULT_HEADER_ORDER: &[&str] = &[
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "accept-language",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-encoding",
    "priority",
    "referer",
    "cookie",
];

/// Returns `sec-ch-ua-*` client hint headers for Chromium-based user agents.
/// Returns empty vec for Firefox/Safari (they don't send Client Hints).
/// The output is a pure function of the UA: see [`sec_ch_ua`].
pub fn client_hints_headers(ua: &str) -> Vec<(String, String)> {
    if !ua.contains("Chrome/") {
        return Vec::new();
    }
    let version = extract_chrome_version(ua);
    let full_version = extract_chrome_full_version(ua);
    let platform = extract_platform(ua);
    let mobile = if ua.contains("Mobile") { "?1" } else { "?0" };

    // Edge adds its own brand alongside Chromium; the GREASE seed stays the
    // Chromium major.
    let (brand, brand_ver, brand_full) = if ua.contains("Edg/") {
        (
            "Microsoft Edge",
            extract_edge_version(ua),
            extract_edge_full_version(ua),
        )
    } else {
        ("Google Chrome", version, full_version)
    };

    vec![
        ("sec-ch-ua".to_owned(), sec_ch_ua(version, brand, brand_ver)),
        ("sec-ch-ua-mobile".to_owned(), mobile.to_owned()),
        ("sec-ch-ua-platform".to_owned(), format!("\"{platform}\"")),
        (
            "sec-ch-ua-full-version-list".to_owned(),
            sec_ch_ua_full_version_list(version, full_version, brand, brand_full),
        ),
    ]
}

/// Builds common browser headers from a profile (UA + client hints).
/// Accept header varies by browser to match real fingerprints.
///
/// For Chrome and Edge, delegates to `tls::chrome_headers()` / `tls::edge_headers()`
/// which return the exact wire-order header set real Chrome emits (including
/// sec-fetch-*, upgrade-insecure-requests, priority, correct accept q-values,
/// and accept-encoding with deflate+zstd). The old generic set was missing
/// these headers and had wrong q-values — the fingerprint oracle caught this.
/// See Issue #80.
pub fn browser_headers(profile: &BrowserProfile) -> Vec<(String, String)> {
    match profile.browser {
        "chrome" => crate::tls::chrome_headers(profile),
        "edge" => crate::tls::edge_headers(profile),
        _ => {
            let accept = match profile.browser {
                "firefox" => {
                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"
                }
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
    }
}

/// Extracts the major Chrome version number from a user-agent string.
fn extract_chrome_version(ua: &str) -> &str {
    let Some(idx) = ua.find("Chrome/") else {
        return "145";
    };
    let rest = &ua[idx + 7..];
    match rest.find('.') {
        Some(dot) => &rest[..dot],
        None => rest,
    }
}

/// Extracts the full Chrome version (e.g. "145.0.0.0") from a user-agent string.
fn extract_chrome_full_version(ua: &str) -> &str {
    let Some(idx) = ua.find("Chrome/") else {
        return "145.0.0.0";
    };
    let rest = &ua[idx + 7..];
    match rest.find(' ') {
        Some(sp) => &rest[..sp],
        None => rest,
    }
}

/// Extracts the major Edge version number from a user-agent string.
fn extract_edge_version(ua: &str) -> &str {
    let Some(idx) = ua.find("Edg/") else {
        return "145";
    };
    let rest = &ua[idx + 4..];
    match rest.find('.') {
        Some(dot) => &rest[..dot],
        None => rest,
    }
}

/// Extracts the full Edge version (e.g. "145.0.0.0") from a user-agent string.
fn extract_edge_full_version(ua: &str) -> &str {
    let Some(idx) = ua.find("Edg/") else {
        return "145.0.0.0";
    };
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

    // Oracles that are not derived from the code under test: strings real
    // Google Chrome releases send. 156 is the branded capture in
    // tests/fixtures/wire/google_chrome_156_nav.json; 131, 133, 136 and 148 are
    // the values those stable releases are known to send.
    const CANONICAL: &[(&str, &str)] = &[
        (
            "131",
            r#""Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24""#,
        ),
        (
            "133",
            r#""Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133""#,
        ),
        (
            "136",
            r#""Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99""#,
        ),
        (
            "148",
            r#""Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99""#,
        ),
        (
            "156",
            r#""Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156""#,
        ),
    ];

    #[test]
    fn sec_ch_ua_equals_real_chrome_for_each_major() {
        for (major, want) in CANONICAL {
            assert_eq!(&sec_ch_ua(major, "Google Chrome", major), want, "{major}");
        }
    }

    #[test]
    fn sec_ch_ua_is_deterministic() {
        // The old builder drew the GREASE brand at random per call.
        let first = sec_ch_ua("148", "Google Chrome", "148");
        for _ in 0..200 {
            assert_eq!(sec_ch_ua("148", "Google Chrome", "148"), first);
        }
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";
        let a = client_hints_headers(ua);
        for _ in 0..200 {
            assert_eq!(client_hints_headers(ua), a);
        }
    }

    #[test]
    fn client_hints_headers_use_the_canonical_string() {
        for (major, want) in CANONICAL {
            let ua = format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
            );
            assert_eq!(client_hints_headers(&ua)[0].1, *want, "{major}");
        }
    }

    #[test]
    fn full_version_list_follows_the_same_order() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.7778.178 Safari/537.36";
        assert_eq!(
            client_hints_headers(ua)[3].1,
            r#""Chromium";v="148.0.7778.178", "Google Chrome";v="148.0.7778.178", "Not/A)Brand";v="99.0.0.0""#
        );
    }

    #[test]
    fn wire_path_and_middleware_path_send_the_same_sec_ch_ua() {
        // Two entry points used to build the value separately and disagreed
        // on brand order for the same UA.
        for p in BUILTIN_PROFILES
            .iter()
            .filter(|p| p.browser == "chrome" || p.browser == "edge")
        {
            let wire = browser_headers(p)
                .into_iter()
                .find(|(k, _)| k == "sec-ch-ua")
                .expect("wire path sends sec-ch-ua")
                .1;
            assert_eq!(
                wire,
                client_hints_headers(p.user_agent)[0].1,
                "{}",
                p.user_agent
            );
        }
    }

    #[test]
    fn edge_grease_is_seeded_by_the_chromium_major() {
        // Edge major differs from the Chromium major: the seed is Chromium's.
        assert_eq!(
            sec_ch_ua("148", "Microsoft Edge", "147"),
            r#""Chromium";v="148", "Microsoft Edge";v="147", "Not/A)Brand";v="99""#
        );
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
        assert_eq!(
            extract_chrome_full_version("Chrome/145.0.7632.159 Safari"),
            "145.0.7632.159"
        );
        assert_eq!(
            extract_edge_full_version("Edg/145.0.2903.70"),
            "145.0.2903.70"
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
