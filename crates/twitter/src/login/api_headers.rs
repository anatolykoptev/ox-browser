//! Full browser-like headers for Twitter API login flow.
//!
//! Matches the header set Chrome sends when interacting with
//! Twitter's onboarding/task.json endpoint.

use wreq::header::{HeaderMap, HeaderValue};

const SEC_CH_UA: &str =
    r#""Chromium";v="136", "Not.A/Brand";v="99", "Google Chrome";v="136""#;

/// Build the full header set for Twitter login API requests.
///
/// Includes authorization, security headers, sec-fetch-*, sec-ch-ua-*,
/// and referer/origin — matching what Chrome actually sends.
pub(super) fn login_headers(
    guest_token: &str,
    csrf_token: Option<&str>,
) -> HeaderMap {
    let mut h = HeaderMap::with_capacity(16);

    // Auth headers
    h.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "Bearer {}",
            crate::graphql::BEARER_TOKEN
        ))
        .unwrap(),
    );
    h.insert("content-type", HeaderValue::from_static("application/json"));
    h.insert(
        "x-guest-token",
        HeaderValue::from_str(guest_token).unwrap(),
    );
    h.insert("x-twitter-active-user", HeaderValue::from_static("yes"));
    h.insert(
        "x-twitter-auth-type",
        HeaderValue::from_static("OAuth2Client"),
    );
    h.insert(
        "x-twitter-client-language",
        HeaderValue::from_static("en"),
    );

    // CSRF token (from ct0 cookie)
    if let Some(ct0) = csrf_token {
        if let Ok(v) = HeaderValue::from_str(ct0) {
            h.insert("x-csrf-token", v);
        }
    }

    // Security headers
    h.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    h.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
    h.insert("sec-fetch-site", HeaderValue::from_static("same-site"));
    h.insert(
        "sec-ch-ua",
        HeaderValue::from_static(SEC_CH_UA),
    );
    h.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    h.insert(
        "sec-ch-ua-platform",
        HeaderValue::from_static("\"Windows\""),
    );

    // Origin / referer
    h.insert("referer", HeaderValue::from_static("https://x.com/"));
    h.insert("origin", HeaderValue::from_static("https://x.com"));

    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_without_csrf() {
        let h = login_headers("guest123", None);
        assert!(h.get("authorization").is_some());
        assert!(h.get("x-guest-token").is_some());
        assert!(h.get("x-csrf-token").is_none());
        assert_eq!(
            h.get("x-twitter-active-user").unwrap().to_str().unwrap(),
            "yes"
        );
    }

    #[test]
    fn headers_with_csrf() {
        let h = login_headers("guest123", Some("abc123def"));
        let csrf = h.get("x-csrf-token").unwrap().to_str().unwrap();
        assert_eq!(csrf, "abc123def");
    }

    #[test]
    fn has_sec_ch_ua_headers() {
        let h = login_headers("guest123", None);
        let ua = h.get("sec-ch-ua").unwrap().to_str().unwrap();
        assert!(ua.contains("Chrome"));
        assert!(ua.contains("136"));
        assert_eq!(
            h.get("sec-ch-ua-mobile").unwrap().to_str().unwrap(),
            "?0"
        );
        assert_eq!(
            h.get("sec-ch-ua-platform").unwrap().to_str().unwrap(),
            "\"Windows\""
        );
    }

    #[test]
    fn has_sec_fetch_headers() {
        let h = login_headers("guest123", None);
        assert_eq!(
            h.get("sec-fetch-dest").unwrap().to_str().unwrap(),
            "empty"
        );
        assert_eq!(
            h.get("sec-fetch-mode").unwrap().to_str().unwrap(),
            "cors"
        );
        assert_eq!(
            h.get("sec-fetch-site").unwrap().to_str().unwrap(),
            "same-site"
        );
    }

    #[test]
    fn has_origin_and_referer() {
        let h = login_headers("guest123", None);
        assert_eq!(
            h.get("referer").unwrap().to_str().unwrap(),
            "https://x.com/"
        );
        assert_eq!(
            h.get("origin").unwrap().to_str().unwrap(),
            "https://x.com"
        );
    }

    #[test]
    fn has_auth_type() {
        let h = login_headers("guest123", None);
        assert_eq!(
            h.get("x-twitter-auth-type").unwrap().to_str().unwrap(),
            "OAuth2Client"
        );
    }

    #[test]
    fn total_header_count_without_csrf() {
        let h = login_headers("guest123", None);
        // 6 auth + 6 security + 2 origin = 14 (no csrf)
        assert_eq!(h.len(), 14);
    }

    #[test]
    fn total_header_count_with_csrf() {
        let h = login_headers("guest123", Some("token"));
        // 14 + csrf = 15
        assert_eq!(h.len(), 15);
    }
}
