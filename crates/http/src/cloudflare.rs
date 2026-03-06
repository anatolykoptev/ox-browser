//! Cloudflare challenge detection — port of go-stealth's `DetectCloudflare`.

use crate::HttpResponse;

/// Cloudflare challenge type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    /// 503 + JS computation challenge ("Just a moment...")
    JsChallenge,
    /// Turnstile/managed CAPTCHA (403 + turnstile widget)
    Turnstile,
    /// Managed challenge at HTTP 200 (interstitial page with JS or Turnstile)
    ManagedChallenge,
    /// IP or country block (403 + "you have been blocked")
    Block,
}

impl std::fmt::Display for ChallengeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsChallenge => write!(f, "js_challenge"),
            Self::Turnstile => write!(f, "managed_challenge"),
            Self::ManagedChallenge => write!(f, "managed_challenge_200"),
            Self::Block => write!(f, "block"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CloudflareChallenge {
    pub challenge_type: ChallengeType,
    pub status: u16,
    pub ray_id: String,
}

/// Inspect an HTTP response for Cloudflare challenge markers.
pub fn detect_cloudflare(resp: &HttpResponse) -> Option<CloudflareChallenge> {
    let server = resp
        .headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !server.to_ascii_lowercase().contains("cloudflare") {
        return None;
    }

    let body = resp.body.to_ascii_lowercase();
    let ray_id = resp
        .headers
        .get("cf-ray")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    // --- HTTP 403/503 detection (existing logic) ---
    if resp.status == 403 || resp.status == 503 {
        if resp.status == 503 && body.contains("challenge-platform") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::JsChallenge,
                status: resp.status,
                ray_id,
            });
        }
        if body.contains("turnstile-wrapper") || body.contains("cf-turnstile") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::Turnstile,
                status: resp.status,
                ray_id,
            });
        }
        if body.contains("you have been blocked") || body.contains("cf-error-details") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::Block,
                status: resp.status,
                ray_id,
            });
        }
        return None;
    }

    // --- HTTP 200 detection (new: interstitial challenges) ---
    if resp.status == 200 {
        let cf_mitigated = resp
            .headers
            .get("cf-mitigated")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if cf_mitigated.contains("challenge") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::ManagedChallenge,
                status: resp.status,
                ray_id,
            });
        }
        if body.contains("cf-turnstile") || body.contains("turnstile-wrapper") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::Turnstile,
                status: resp.status,
                ray_id,
            });
        }
        if body.contains("_cf_chl_opt") || body.contains("challenge-platform") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::ManagedChallenge,
                status: resp.status,
                ray_id,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use wreq::header::HeaderMap;

    fn cf_response(status: u16, body: &str, server: &str) -> HttpResponse {
        let mut headers = HeaderMap::new();
        headers.insert("server", server.parse().unwrap());
        HttpResponse {
            status,
            url: "https://example.com".into(),
            headers,
            body: body.to_owned(),
        }
    }

    fn cf_response_with_ray(status: u16, body: &str, ray: &str) -> HttpResponse {
        let mut headers = HeaderMap::new();
        headers.insert("server", "cloudflare".parse().unwrap());
        headers.insert("cf-ray", ray.parse().unwrap());
        HttpResponse {
            status,
            url: "https://example.com".into(),
            headers,
            body: body.to_owned(),
        }
    }

    #[test]
    fn detects_js_challenge() {
        let resp = cf_response(
            503,
            "<html><script src=\"/cdn-cgi/challenge-platform/x.js\"></script></html>",
            "cloudflare",
        );
        let cf = detect_cloudflare(&resp).unwrap();
        assert_eq!(cf.challenge_type, ChallengeType::JsChallenge);
        assert_eq!(cf.status, 503);
    }

    #[test]
    fn detects_turnstile() {
        let resp = cf_response(
            403,
            "<html><div id=\"turnstile-wrapper\"></div></html>",
            "cloudflare",
        );
        let cf = detect_cloudflare(&resp).unwrap();
        assert_eq!(cf.challenge_type, ChallengeType::Turnstile);
    }

    #[test]
    fn detects_block() {
        let resp = cf_response(403, "<html>you have been blocked</html>", "cloudflare");
        let cf = detect_cloudflare(&resp).unwrap();
        assert_eq!(cf.challenge_type, ChallengeType::Block);
    }

    #[test]
    fn ignores_clean_200() {
        let resp = cf_response(200, "<html>ok</html>", "cloudflare");
        assert!(detect_cloudflare(&resp).is_none());
    }

    #[test]
    fn ignores_non_cf_503() {
        let resp = cf_response(503, "challenge-platform", "nginx");
        assert!(detect_cloudflare(&resp).is_none());
    }

    #[test]
    fn ignores_cf_403_no_markers() {
        let resp = cf_response(403, "Access denied", "cloudflare");
        assert!(detect_cloudflare(&resp).is_none());
    }

    #[test]
    fn mixed_case_server() {
        let resp = cf_response(403, "you have been blocked", "Cloudflare");
        assert!(detect_cloudflare(&resp).is_some());
    }

    #[test]
    fn extracts_ray_id() {
        let resp = cf_response_with_ray(403, "you have been blocked", "8f3a2b1c-LAX");
        let cf = detect_cloudflare(&resp).unwrap();
        assert_eq!(cf.ray_id, "8f3a2b1c-LAX");
    }

    #[test]
    fn challenge_type_display() {
        assert_eq!(ChallengeType::JsChallenge.to_string(), "js_challenge");
        assert_eq!(ChallengeType::Turnstile.to_string(), "managed_challenge");
        assert_eq!(ChallengeType::ManagedChallenge.to_string(), "managed_challenge_200");
        assert_eq!(ChallengeType::Block.to_string(), "block");
    }

    #[test]
    fn cloudflare_error_is_retryable() {
        use crate::HttpError;
        let err = HttpError::Cloudflare(ChallengeType::Block, 403, "ray".into());
        assert!(err.is_retryable());
    }

    #[test]
    fn js_challenge_requires_503() {
        // 403 + challenge-platform should NOT be JsChallenge
        let resp = cf_response(
            403,
            "<html><script src=\"/cdn-cgi/challenge-platform/x.js\"></script></html>",
            "cloudflare",
        );
        assert!(detect_cloudflare(&resp).is_none());
    }

    #[test]
    fn detects_cf_mitigated_header_at_200() {
        let mut headers = HeaderMap::new();
        headers.insert("server", "cloudflare".parse().unwrap());
        headers.insert("cf-mitigated", "challenge".parse().unwrap());
        let resp = HttpResponse {
            status: 200,
            url: "https://example.com".into(),
            headers,
            body: "<html>Just a moment...</html>".into(),
        };
        let cf = detect_cloudflare(&resp).unwrap();
        assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
        assert_eq!(cf.status, 200);
    }

    #[test]
    fn detects_cf_chl_opt_at_200() {
        let mut headers = HeaderMap::new();
        headers.insert("server", "cloudflare".parse().unwrap());
        let resp = HttpResponse {
            status: 200,
            url: "https://example.com".into(),
            headers,
            body: "<html><script>window._cf_chl_opt={}</script></html>".into(),
        };
        let cf = detect_cloudflare(&resp).unwrap();
        assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
    }

    #[test]
    fn detects_challenge_platform_at_200() {
        let mut headers = HeaderMap::new();
        headers.insert("server", "cloudflare".parse().unwrap());
        let resp = HttpResponse {
            status: 200,
            url: "https://example.com".into(),
            headers,
            body: "<html><script src=\"/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1\"></script></html>".into(),
        };
        let cf = detect_cloudflare(&resp).unwrap();
        assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
    }

    #[test]
    fn ignores_normal_200_from_cloudflare() {
        let resp = cf_response(200, "<html><body>Normal page content</body></html>", "cloudflare");
        assert!(detect_cloudflare(&resp).is_none());
    }

    #[test]
    fn detects_turnstile_at_200() {
        let mut headers = HeaderMap::new();
        headers.insert("server", "cloudflare".parse().unwrap());
        let resp = HttpResponse {
            status: 200,
            url: "https://example.com".into(),
            headers,
            body: "<html><div class=\"cf-turnstile\"></div></html>".into(),
        };
        let cf = detect_cloudflare(&resp).unwrap();
        assert_eq!(cf.challenge_type, ChallengeType::Turnstile);
    }

    #[test]
    fn managed_challenge_display() {
        assert_eq!(ChallengeType::ManagedChallenge.to_string(), "managed_challenge_200");
    }
}
