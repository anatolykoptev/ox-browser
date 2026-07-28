use std::sync::OnceLock;

use ox_http::{HttpClient, HttpConfig};
use wreq::IntoEmulation;

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
/// Uses Chrome fingerprint emulation and no Cloudflare detection
/// (Twitter uses its own anti-bot layer).
pub(crate) fn twitter_http() -> &'static HttpClient {
    TWITTER_CLIENT.get_or_init(|| {
        let config = HttpConfig {
            timeout: std::time::Duration::from_secs(30),
            user_agent: crate::TWITTER_USER_AGENT.to_string(),
            emulation: Some(wreq_util::Profile::Chrome136.into_emulation()),
            cloudflare_detect: false,
            quality_check: false, // Twitter 403 = real auth error, not CF challenge
            ..HttpConfig::default()
        };
        HttpClient::new(config).expect("twitter http client")
    })
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
}
