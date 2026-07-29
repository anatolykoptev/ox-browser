use std::sync::OnceLock;

use ox_http::{HttpClient, HttpConfig};

/// Header order for Twitter API requests (matches go-twitter/headers.go).
pub(crate) static TWITTER_HEADER_ORDER: &[&str] = &[
    "authorization",
    "content-type",
    "x-csrf-token",
    "x-twitter-active-user",
    "x-twitter-auth-type",
    "x-twitter-client-language",
    "x-client-transaction-id",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "cookie",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "referer",
    "origin",
];

static TWITTER_CLIENT: OnceLock<HttpClient> = OnceLock::new();

/// Shared HttpClient for all Twitter API requests.
///
/// Routes through the same TLS/HTTP2 identity seam as the rest of the
/// fleet: `tls::chrome_emulation()` (the hand-built Chrome 148 profile
/// with `trust_anchors` / 0xca34, issue #81) and the fleet Chrome 148
/// User-Agent from `BUILTIN_PROFILES`. The old path used
/// `wreq_util::Profile::Chrome136.into_emulation()` — internally coherent
/// (UA 136 + TLS 136 agreed) but twelve majors stale and missing the
/// `trust_anchors` extension the main path carries.
///
/// `cloudflare_detect: false` and `quality_check: false` are preserved:
/// Twitter has its own anti-bot layer, and a 403 from Twitter is a real
/// auth error, not a CF challenge.
pub(crate) fn twitter_http() -> &'static HttpClient {
    TWITTER_CLIENT.get_or_init(|| {
        let profile = ox_http::BUILTIN_PROFILES
            .iter()
            .find(|p| p.browser == "chrome" && p.os == "windows")
            .expect("builtin Chrome 148 Windows profile exists");
        let config = HttpConfig {
            timeout: std::time::Duration::from_secs(30),
            user_agent: profile.user_agent.to_string(),
            emulation: Some(ox_http::tls::chrome_emulation(profile)),
            cloudflare_detect: false,
            quality_check: false, // Twitter 403 = real auth error, not CF challenge
            ..HttpConfig::default()
        };
        HttpClient::new(config).expect("twitter http client")
    })
}

/// The Twitter client's User-Agent — the fleet Chrome 148 UA from
/// `BUILTIN_PROFILES`, exposed for request-level header construction.
/// Replaces the deleted `TWITTER_USER_AGENT` constant (was Chrome 136).
pub(crate) fn twitter_user_agent() -> &'static str {
    twitter_http().config().user_agent.as_str()
}

/// Build an ordered header Vec following TWITTER_HEADER_ORDER.
///
/// Headers not in the order list are appended at the end.
pub(crate) fn ordered_headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut result = Vec::with_capacity(pairs.len());
    // First pass: add headers in TWITTER_HEADER_ORDER
    for &key in TWITTER_HEADER_ORDER {
        for &(k, v) in pairs {
            if k.eq_ignore_ascii_case(key) {
                result.push((k.to_string(), v.to_string()));
            }
        }
    }
    // Second pass: append headers not in the order list
    for &(k, v) in pairs {
        if !TWITTER_HEADER_ORDER
            .iter()
            .any(|&o| k.eq_ignore_ascii_case(o))
        {
            result.push((k.to_string(), v.to_string()));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordered_headers_basic_ordering() {
        let pairs = &[
            ("accept", "*/*"),
            ("authorization", "Bearer token"),
            ("cookie", "ct0=abc"),
        ];
        let result = ordered_headers(pairs);
        // authorization comes before accept and cookie per TWITTER_HEADER_ORDER
        let keys: Vec<&str> = result.iter().map(|(k, _)| k.as_str()).collect();
        let auth_pos = keys.iter().position(|&k| k == "authorization").unwrap();
        let accept_pos = keys.iter().position(|&k| k == "accept").unwrap();
        let cookie_pos = keys.iter().position(|&k| k == "cookie").unwrap();
        assert!(auth_pos < cookie_pos, "authorization before cookie");
        assert!(cookie_pos < accept_pos, "cookie before accept");
    }

    #[test]
    fn test_ordered_headers_unknown_appended() {
        let pairs = &[
            ("x-custom-header", "value"),
            ("authorization", "Bearer token"),
        ];
        let result = ordered_headers(pairs);
        let keys: Vec<&str> = result.iter().map(|(k, _)| k.as_str()).collect();
        let auth_pos = keys.iter().position(|&k| k == "authorization").unwrap();
        let custom_pos = keys.iter().position(|&k| k == "x-custom-header").unwrap();
        assert!(auth_pos < custom_pos, "known header before unknown header");
    }

    #[test]
    fn test_ordered_headers_case_insensitive() {
        let pairs = &[("Authorization", "Bearer token"), ("ACCEPT", "*/*")];
        let result = ordered_headers(pairs);
        let keys: Vec<&str> = result.iter().map(|(k, _)| k.as_str()).collect();
        let auth_pos = keys.iter().position(|&k| k == "Authorization").unwrap();
        let accept_pos = keys.iter().position(|&k| k == "ACCEPT").unwrap();
        assert!(auth_pos < accept_pos, "Authorization before ACCEPT");
    }

    #[test]
    fn test_ordered_headers_preserves_values() {
        let pairs = &[
            ("authorization", "Bearer mytoken123"),
            ("cookie", "ct0=xyz"),
        ];
        let result = ordered_headers(pairs);
        let auth = result.iter().find(|(k, _)| k == "authorization").unwrap();
        assert_eq!(auth.1, "Bearer mytoken123");
    }

    #[test]
    fn test_ordered_headers_empty() {
        let result = ordered_headers(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_ordered_headers_all_twitter_fields() {
        // Provide all fields in reverse order — result must follow TWITTER_HEADER_ORDER
        let pairs: Vec<(&str, &str)> = TWITTER_HEADER_ORDER
            .iter()
            .rev()
            .map(|&k| (k, "v"))
            .collect();
        let result = ordered_headers(&pairs);
        let keys: Vec<&str> = result.iter().map(|(k, _)| k.as_str()).collect();
        for (i, &expected) in TWITTER_HEADER_ORDER.iter().enumerate() {
            assert_eq!(
                keys[i], expected,
                "position {i}: expected {expected}, got {}",
                keys[i]
            );
        }
    }

    /// The Twitter client's TLS/HTTP2 emulation must be the SAME VALUE the
    /// main path produces via `tls::chrome_emulation()` — not merely `Some`.
    /// An assertion that only checks non-`None` passes against any preset
    /// (including the old `wreq_util::Profile::Chrome136`) and is worthless.
    /// We compare the `tls_options` and `http2_options` Debug output, which
    /// are the fingerprint-relevant fields `chrome_emulation` sets. The old
    /// Chrome 136 preset lacks `trust_anchors` (0xca34) and has a different
    /// extension count, so its `tls_options` Debug output differs.
    #[test]
    fn twitter_emulation_matches_main_path() {
        let profile = ox_http::BUILTIN_PROFILES
            .iter()
            .find(|p| p.browser == "chrome" && p.os == "windows")
            .expect("builtin Chrome 148 Windows profile");
        let main_emu = ox_http::tls::chrome_emulation(profile);
        let twitter_emu = twitter_http()
            .config()
            .emulation
            .as_ref()
            .expect("twitter client has emulation set");

        assert_eq!(
            format!("{:?}", twitter_emu.tls_options),
            format!("{:?}", main_emu.tls_options),
            "Twitter TLS options must be byte-identical to the main path's chrome_emulation"
        );
        assert_eq!(
            format!("{:?}", twitter_emu.http2_options),
            format!("{:?}", main_emu.http2_options),
            "Twitter HTTP/2 options must be byte-identical to the main path's chrome_emulation"
        );
    }

    /// The Twitter UA major and the `sec-ch-ua` major must agree. The
    /// `client_hints_middleware` (active because `profile` is None) derives
    /// `sec-ch-ua` from the request's `user-agent` header via
    /// `client_hints_headers()`. A stale sec-ch-ua claiming 136 next to a
    /// UA claiming 148 recreates the mismatch class this issue closes.
    #[test]
    fn twitter_ua_major_matches_sec_ch_ua_major() {
        let ua = twitter_user_agent();
        let ua_major = ox_http::profile::extract_major_version_pub(ua)
            .expect("twitter UA has a parseable major version");

        let hints = ox_http::client_hints_headers(ua);
        let sec_ch_ua = hints
            .iter()
            .find(|(k, _)| k == "sec-ch-ua")
            .expect("sec-ch-ua hint generated for Chrome UA");

        // Extract the first brand's version: "Chromium";v="148", ...
        let v_start = sec_ch_ua.1.find("v=\"").expect("sec-ch-ua has v=") + 3;
        let rest = &sec_ch_ua.1[v_start..];
        let v_end = rest.find('"').expect("sec-ch-ua version terminates");
        let hint_major: u32 = rest[..v_end]
            .split('.')
            .next()
            .unwrap()
            .parse()
            .expect("sec-ch-ua version is numeric");

        assert_eq!(
            ua_major, hint_major,
            "Twitter UA major ({ua_major}) must match sec-ch-ua major ({hint_major})"
        );
    }
}
