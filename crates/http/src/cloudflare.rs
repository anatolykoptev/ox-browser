//! Cloudflare challenge detection.
//!
//! Port of go-stealth's `DetectCloudflare`. Inspects HTTP responses for
//! Cloudflare challenge pages (JS challenge, Turnstile, IP block).

use crate::HttpResponse;

/// Cloudflare challenge type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    /// 503 + JS computation challenge ("Just a moment...")
    JsChallenge,
    /// Turnstile/managed CAPTCHA (403 + turnstile widget)
    Turnstile,
    /// IP or country block (403 + "you have been blocked")
    Block,
}

impl std::fmt::Display for ChallengeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsChallenge => write!(f, "js_challenge"),
            Self::Turnstile => write!(f, "managed_challenge"),
            Self::Block => write!(f, "block"),
        }
    }
}

/// Cloudflare challenge details extracted from a response.
#[derive(Debug, Clone)]
pub struct CloudflareChallenge {
    pub challenge_type: ChallengeType,
    pub status: u16,
    pub ray_id: String,
}

/// Inspect an HTTP response for Cloudflare challenge markers.
///
/// Returns `None` if the response is not a Cloudflare challenge.
pub fn detect_cloudflare(resp: &HttpResponse) -> Option<CloudflareChallenge> {
    if resp.status != 403 && resp.status != 503 {
        return None;
    }

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

    // JS challenge: 503 + challenge-platform scripts
    if resp.status == 503 && body.contains("challenge-platform") {
        return Some(CloudflareChallenge {
            challenge_type: ChallengeType::JsChallenge,
            status: resp.status,
            ray_id,
        });
    }

    // Turnstile managed challenge
    if body.contains("turnstile-wrapper") || body.contains("cf-turnstile") {
        return Some(CloudflareChallenge {
            challenge_type: ChallengeType::Turnstile,
            status: resp.status,
            ray_id,
        });
    }

    // Block page
    if body.contains("you have been blocked") || body.contains("cf-error-details") {
        return Some(CloudflareChallenge {
            challenge_type: ChallengeType::Block,
            status: resp.status,
            ray_id,
        });
    }

    None
}
