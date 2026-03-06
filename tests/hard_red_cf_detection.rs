//! Hard red tests for Cloudflare detection — edge cases, false positives,
//! priority conflicts, header combinations, and boundary conditions.

use ox_http::{detect_cloudflare, ChallengeType, HttpResponse};
use wreq::header::HeaderMap;

// --- Helpers ---

fn resp(status: u16, body: &str, headers: Vec<(&str, &str)>) -> HttpResponse {
    let mut hm = HeaderMap::new();
    for (k, v) in headers {
        hm.insert(
            wreq::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    HttpResponse {
        status,
        url: "https://test.example.com".into(),
        headers: hm,
        body: body.to_owned(),
    }
}

fn cf(status: u16, body: &str) -> HttpResponse {
    resp(status, body, vec![("server", "cloudflare")])
}

// ==========================================================================
// FALSE POSITIVES — must NOT detect CF where there is none
// ==========================================================================

/// A blog post that mentions "challenge-platform" in article text should NOT trigger.
#[test]
fn false_positive_article_mentions_challenge_platform() {
    // At 200, body marker "challenge-platform" WILL trigger — this tests that
    // the server header gate prevents non-CF servers from triggering.
    let r = resp(
        200,
        "This article discusses cloudflare's challenge-platform architecture.",
        vec![("server", "nginx")],
    );
    assert!(detect_cloudflare(&r).is_none());
}

/// A page with "cf-turnstile" in a CSS class name from a non-CF server.
#[test]
fn false_positive_turnstile_class_non_cf_server() {
    let r = resp(
        200,
        "<div class=\"cf-turnstile-demo\">Widget preview</div>",
        vec![("server", "Apache/2.4")],
    );
    assert!(detect_cloudflare(&r).is_none());
}

/// A 200 page behind CF CDN with normal content — the most common case.
/// Must NOT be detected even though server=cloudflare.
#[test]
fn false_positive_normal_page_behind_cf_cdn() {
    let r = resp(
        200,
        "<html><head><title>My Blog</title></head><body><h1>Hello World</h1>\
         <p>Welcome to my blog. This page is served via Cloudflare CDN.</p></body></html>",
        vec![("server", "cloudflare"), ("cf-ray", "abc123-LAX")],
    );
    assert!(detect_cloudflare(&r).is_none());
}

/// JavaScript code that assigns `_cf_chl_opt`-like variable names in a 200 page
/// from a non-CF server — must not trigger.
#[test]
fn false_positive_js_variable_similar_name_non_cf() {
    let r = resp(
        200,
        "<script>var _cf_chl_opt_disabled = true;</script>",
        vec![("server", "nginx/1.25")],
    );
    assert!(detect_cloudflare(&r).is_none());
}

/// A CF-served page at 301/302 redirect — we only check 200/403/503.
#[test]
fn ignores_redirect_status() {
    let r = cf(301, "challenge-platform _cf_chl_opt cf-turnstile");
    assert!(detect_cloudflare(&r).is_none());
}

/// A CF-served page at 500 (internal error) — not a challenge.
#[test]
fn ignores_500_server_error() {
    let r = cf(500, "challenge-platform you have been blocked");
    assert!(detect_cloudflare(&r).is_none());
}

/// A CF-served page at 429 (rate limit) — not a challenge.
#[test]
fn ignores_429_rate_limit() {
    let r = cf(429, "cf-turnstile _cf_chl_opt challenge-platform");
    assert!(detect_cloudflare(&r).is_none());
}

// ==========================================================================
// TRUE POSITIVES — edge cases that MUST be detected
// ==========================================================================

/// cf-mitigated header with extra value text: "challenge; expires=300".
#[test]
fn cf_mitigated_header_with_extra_params() {
    let r = resp(
        200,
        "<html>loading...</html>",
        vec![
            ("server", "cloudflare"),
            ("cf-mitigated", "challenge; expires=300"),
        ],
    );
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
}

/// Turnstile widget embedded deep in minified HTML at 200.
#[test]
fn turnstile_in_minified_html_200() {
    let r = cf(
        200,
        "<html><body><div><div><div class=\"cf-turnstile\" data-sitekey=\"0x4AAA\"></div></div></div></body></html>",
    );
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Turnstile);
}

/// Mixed-case body with challenge markers — lowercased comparison.
#[test]
fn case_insensitive_body_markers() {
    let r = cf(200, "<html><script>window._CF_CHL_OPT={}</script></html>");
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
}

/// Body contains both turnstile AND _cf_chl_opt — turnstile wins (checked first).
#[test]
fn turnstile_takes_priority_over_chl_opt_at_200() {
    let r = cf(
        200,
        "<html><div class=\"cf-turnstile\"></div><script>window._cf_chl_opt={}</script></html>",
    );
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Turnstile);
}

/// cf-mitigated header takes priority over all body markers.
#[test]
fn cf_mitigated_header_takes_priority_over_body() {
    let r = resp(
        200,
        "<html><div class=\"cf-turnstile\"></div></html>",
        vec![
            ("server", "cloudflare"),
            ("cf-mitigated", "challenge"),
        ],
    );
    let cf = detect_cloudflare(&r).unwrap();
    // Header check comes first → ManagedChallenge, not Turnstile
    assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
}

/// 503 with both challenge-platform and turnstile — JsChallenge wins.
#[test]
fn js_challenge_priority_over_turnstile_at_503() {
    let r = cf(
        503,
        "<html>challenge-platform<div class=\"cf-turnstile\"></div></html>",
    );
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::JsChallenge);
}

/// 403 with both turnstile and block markers — turnstile wins (checked first).
#[test]
fn turnstile_priority_over_block_at_403() {
    let r = cf(
        403,
        "<html><div class=\"turnstile-wrapper\"></div>you have been blocked</html>",
    );
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Turnstile);
}

// ==========================================================================
// HEADER EDGE CASES
// ==========================================================================

/// Server header "cloudflare-nginx" still contains "cloudflare".
#[test]
fn server_header_cloudflare_nginx_composite() {
    let r = resp(
        403,
        "you have been blocked",
        vec![("server", "cloudflare-nginx")],
    );
    assert!(detect_cloudflare(&r).is_some());
}

/// No server header at all.
#[test]
fn no_server_header() {
    let r = resp(403, "you have been blocked challenge-platform", vec![]);
    assert!(detect_cloudflare(&r).is_none());
}

/// Empty server header.
#[test]
fn empty_server_header() {
    let r = resp(200, "_cf_chl_opt", vec![("server", "")]);
    assert!(detect_cloudflare(&r).is_none());
}

/// cf-mitigated without "challenge" value — should NOT trigger.
#[test]
fn cf_mitigated_non_challenge_value() {
    let r = resp(
        200,
        "<html>ok</html>",
        vec![
            ("server", "cloudflare"),
            ("cf-mitigated", "captcha"),
        ],
    );
    assert!(detect_cloudflare(&r).is_none());
}

/// cf-ray present but no challenge markers — extracts ray but returns None.
#[test]
fn cf_ray_without_challenge_markers() {
    let r = resp(
        200,
        "<html>clean page</html>",
        vec![("server", "cloudflare"), ("cf-ray", "abc-LAX")],
    );
    assert!(detect_cloudflare(&r).is_none());
}

// ==========================================================================
// BODY EDGE CASES
// ==========================================================================

/// Empty body at 200.
#[test]
fn empty_body_200() {
    let r = cf(200, "");
    assert!(detect_cloudflare(&r).is_none());
}

/// Empty body at 403.
#[test]
fn empty_body_403() {
    let r = cf(403, "");
    assert!(detect_cloudflare(&r).is_none());
}

/// Very long body — markers near the end (1MB+ page).
#[test]
fn marker_at_end_of_large_body() {
    let mut body = "x".repeat(1_000_000);
    body.push_str("<div class=\"cf-turnstile\"></div>");
    let r = cf(200, &body);
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Turnstile);
}

/// Body with null bytes — should not crash.
#[test]
fn body_with_null_bytes() {
    let r = cf(200, "before\0_cf_chl_opt\0after");
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
}

/// Body with unicode — markers still detectable after lowercasing.
#[test]
fn body_with_unicode_around_markers() {
    let r = cf(200, "Привет мир <div class=\"cf-turnstile\">挑战</div>");
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Turnstile);
}

/// Partial marker: "_cf_chl" (without "_opt") should NOT trigger.
#[test]
fn partial_marker_cf_chl_without_opt() {
    let r = cf(200, "<script>var _cf_chl = true;</script>");
    assert!(detect_cloudflare(&r).is_none());
}

/// Marker in HTML comment — still triggers (we do substring match, not DOM parse).
#[test]
fn marker_in_html_comment_still_triggers() {
    let r = cf(200, "<!-- _cf_chl_opt debug data -->");
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
}

// ==========================================================================
// STATUS CODE BOUNDARY — only 200, 403, 503
// ==========================================================================

#[test]
fn status_199_ignored() {
    let r = cf(199, "_cf_chl_opt cf-turnstile challenge-platform");
    assert!(detect_cloudflare(&r).is_none());
}

#[test]
fn status_201_ignored() {
    let r = cf(201, "_cf_chl_opt cf-turnstile challenge-platform");
    assert!(detect_cloudflare(&r).is_none());
}

#[test]
fn status_404_ignored() {
    let r = cf(404, "_cf_chl_opt you have been blocked");
    assert!(detect_cloudflare(&r).is_none());
}

#[test]
fn status_502_ignored() {
    let r = cf(502, "challenge-platform cf-turnstile");
    assert!(detect_cloudflare(&r).is_none());
}

#[test]
fn status_504_ignored() {
    let r = cf(504, "challenge-platform");
    assert!(detect_cloudflare(&r).is_none());
}

// ==========================================================================
// MANAGED CHALLENGE (200) — retryable and solvable
// ==========================================================================

/// ManagedChallenge should be retryable (same as other CF errors).
#[test]
fn managed_challenge_is_retryable() {
    use ox_http::HttpError;
    let err = HttpError::Cloudflare(ChallengeType::ManagedChallenge, 200, "ray".into());
    assert!(err.is_retryable());
}

/// All challenge types should be retryable.
#[test]
fn all_challenge_types_retryable() {
    use ox_http::HttpError;
    for ct in [
        ChallengeType::JsChallenge,
        ChallengeType::Turnstile,
        ChallengeType::ManagedChallenge,
        ChallengeType::Block,
    ] {
        let err = HttpError::Cloudflare(ct, 403, "ray".into());
        assert!(err.is_retryable(), "{ct} should be retryable");
    }
}

/// CloudflareChallenge preserves exact status and ray_id.
#[test]
fn challenge_preserves_metadata() {
    let r = resp(
        200,
        "_cf_chl_opt",
        vec![("server", "cloudflare"), ("cf-ray", "deadbeef-SIN")],
    );
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.status, 200);
    assert_eq!(cf.ray_id, "deadbeef-SIN");
    assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
}

/// Missing cf-ray header → empty ray_id (not panic).
#[test]
fn missing_ray_id_defaults_to_empty() {
    let r = cf(403, "you have been blocked");
    let cf = detect_cloudflare(&r).unwrap();
    assert_eq!(cf.ray_id, "");
}
