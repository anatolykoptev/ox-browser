//! Header builders for Twitter API login flow.
//!
//! Matches twikit's exact header sets — onboarding/task.json uses a
//! minimal header dict, NOT the full browser header set.

use wreq::header::{HeaderMap, HeaderValue};

/// Headers for `POST /1.1/onboarding/task.json`.
///
/// Twikit uses a MINIMAL set: authorization + x-guest-token + x-csrf-token.
/// No sec-fetch-*, no sec-ch-ua-*, no X-Twitter-Active-User.
/// httpx auto-adds content-type when using json= parameter.
pub(super) fn onboarding_headers(
    guest_token: &str,
    csrf_token: Option<&str>,
) -> HeaderMap {
    let mut h = HeaderMap::with_capacity(6);

    h.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", crate::graphql::BEARER_TOKEN)).unwrap(),
    );
    h.insert(
        "x-guest-token",
        HeaderValue::from_str(guest_token).unwrap(),
    );

    // CSRF token + auth-type — only when ct0 cookie is available
    if let Some(ct0) = csrf_token {
        if let Ok(v) = HeaderValue::from_str(ct0) {
            h.insert("x-csrf-token", v);
            h.insert("x-twitter-auth-type", HeaderValue::from_static("OAuth2Session"));
        }
    }

    h
}

/// Headers for `POST /1.1/guest/activate.json`.
///
/// Twikit uses _base_headers MINUS X-Twitter-Active-User and X-Twitter-Auth-Type.
pub(super) fn guest_activate_headers() -> HeaderMap {
    let mut h = HeaderMap::with_capacity(6);

    h.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", crate::graphql::BEARER_TOKEN)).unwrap(),
    );
    h.insert("content-type", HeaderValue::from_static("application/json"));
    h.insert("referer", HeaderValue::from_static("https://x.com/"));
    h.insert("accept-language", HeaderValue::from_static("en-US"));
    h.insert("x-twitter-client-language", HeaderValue::from_static("en-US"));

    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onboarding_without_csrf() {
        let h = onboarding_headers("guest123", None);
        assert!(h.get("authorization").is_some());
        assert!(h.get("x-guest-token").is_some());
        assert!(h.get("x-csrf-token").is_none());
        assert!(h.get("x-twitter-auth-type").is_none());
        // No sec-fetch-*, no sec-ch-ua-*
        assert!(h.get("sec-fetch-dest").is_none());
        assert!(h.get("sec-ch-ua").is_none());
    }

    #[test]
    fn onboarding_with_csrf() {
        let h = onboarding_headers("guest123", Some("abc123"));
        assert_eq!(h.get("x-csrf-token").unwrap(), "abc123");
        assert_eq!(h.get("x-twitter-auth-type").unwrap(), "OAuth2Session");
    }

    #[test]
    fn guest_activate_no_auth_type() {
        let h = guest_activate_headers();
        assert!(h.get("authorization").is_some());
        assert!(h.get("x-twitter-auth-type").is_none());
        assert!(h.get("x-twitter-active-user").is_none());
        assert_eq!(h.get("referer").unwrap(), "https://x.com/");
    }
}
