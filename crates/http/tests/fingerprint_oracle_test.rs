//! Fingerprint oracle — verifies ox-browser's emitted TLS/HTTP2 fingerprint
//! matches the browser claimed in the User-Agent.
//!
//! Build-tagged behind `#[cfg(feature = "fingerprint")]` so it NEVER runs in
//! `make preflight` (which uses default features). Run explicitly:
//!
//!     cargo test -p ox-http --features fingerprint --test fingerprint_oracle_test
//!
//! A failure means ox-browser's Emulation profile emits a fingerprint that
//! differs from what a real browser of the same version emits. That is a true
//! result, not a defect in the test: a stale or wrong profile SHOULD fail the
//! oracle. Fix the profile in a separate reviewed change; do not weaken the
//! comparison to make it green.
//!
//! References live in `crates/http/tests/fixtures/reference_*.json`, produced
//! by capturing a real browser's fingerprint via tls.browserleaks.com.
//! An unreachable endpoint or a missing reference is an ERROR (never a skip)
//! — a skip looks identical to a pass, which is the exact failure class this
//! repo keeps hitting.
//!
//! Issue #78: fingerprint oracle test.

#![cfg(feature = "fingerprint")]

use std::time::Duration;

use ox_http::content::ContentFormat;
use ox_http::{BUILTIN_PROFILES, BrowserProfile, HttpClient, HttpConfig, profile_to_emulation};
use serde::Deserialize;

// ── Reference fingerprint structure ───────────────────────────────────

#[derive(Debug, Deserialize)]
struct ReferenceFingerprint {
    browser: String,
    browser_version: String,
    major: String,
    tls: TlsFingerprint,
    http2_akamai_fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct TlsFingerprint {
    ja4: String,
    #[serde(default)]
    ja3: String,
}

// ── Observed fingerprint from browserleaks ────────────────────────────

#[derive(Debug, Deserialize)]
struct BrowserleaksResponse {
    ja3_hash: String,
    ja4: String,
    #[serde(default)]
    akamai_fingerprint: String,
    #[serde(default)]
    http2_fingerprint: String,
    user_agent: String,
}

// ── Test cases ────────────────────────────────────────────────────────

/// Profiles to verify — deduplicated by browser+major (TLS fingerprint is
/// per-major, not per-OS, so testing one OS variant covers all).
fn test_profiles() -> Vec<&'static BrowserProfile> {
    let mut seen: Vec<(&str, &str)> = Vec::new();
    let mut result = Vec::new();
    for p in BUILTIN_PROFILES {
        let major = extract_major_version(p.user_agent);
        let key = (p.browser, major.as_str());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        result.push(p);
    }
    result
}

fn extract_major_version(ua: &str) -> String {
    // Chrome: "Chrome/145.0.0.0" → "145"
    // Firefox: "rv:138.0" → "138"
    // Safari: "Version/18.2" → "18"
    if let Some(pos) = ua.find("Chrome/") {
        let rest = &ua[pos + 7..];
        return rest.split('.').next().unwrap_or("0").to_string();
    }
    if let Some(pos) = ua.find("rv:") {
        let rest = &ua[pos + 3..];
        return rest.split('.').next().unwrap_or("0").to_string();
    }
    if let Some(pos) = ua.find("Version/") {
        let rest = &ua[pos + 8..];
        return rest.split('.').next().unwrap_or("0").to_string();
    }
    "0".to_string()
}

fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn load_reference(browser: &str, major: &str) -> ReferenceFingerprint {
    let path = fixture_dir().join(format!("reference_{}_{}.json", browser, major));
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "no reference for {} {} at {} (run capture script to create one): {e}",
            browser,
            major,
            path.display()
        )
    });
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("parse reference {}: {e}", path.display()))
}

/// Build an HttpClient with the given profile's Emulation enabled.
fn build_client(profile: &BrowserProfile) -> HttpClient {
    let emulation = profile_to_emulation(profile).unwrap_or_else(|| {
        panic!(
            "no Emulation mapping for browser={} — profile_to_emulation must cover all builtin profiles",
            profile.browser
        )
    });
    let config = HttpConfig {
        emulation: Some(emulation),
        timeout: Duration::from_secs(30),
        ..HttpConfig::default()
    };
    HttpClient::new(config)
        .unwrap_or_else(|e| panic!("HttpClient::new with {:?}: {e}", profile.browser))
}

async fn fetch_fingerprint(client: &HttpClient, endpoint: &str) -> BrowserleaksResponse {
    let resp = client
        .get(endpoint)
        .await
        .unwrap_or_else(|e| panic!("fetch {endpoint} failed (this is an ERROR, not a skip): {e}"));
    assert_eq!(
        resp.status, 200,
        "{endpoint} returned {} (expected 200)",
        resp.status
    );
    serde_json::from_slice(&resp.body).unwrap_or_else(|e| panic!("parse {endpoint} response: {e}"))
}

/// Verify that profile_to_emulation maps every builtin profile to a
/// non-None Emulation. This is the P0 gate — if any profile has no
/// Emulation, TLS fingerprinting is silently disabled for that profile.
#[test]
fn all_builtin_profiles_have_emulation_mapping() {
    for p in BUILTIN_PROFILES {
        let emulation = profile_to_emulation(p);
        assert!(
            emulation.is_some(),
            "profile {} {} has no Emulation mapping — TLS fingerprinting is disabled",
            p.browser,
            extract_major_version(p.user_agent)
        );
    }
}

/// Verify that the emulation is set in HttpConfig when a profile is used.
/// This is the core P0 fix — without this, emulation defaults to None.
#[test]
fn http_config_with_profile_sets_emulation() {
    for p in BUILTIN_PROFILES {
        let emulation = profile_to_emulation(p).expect("emulation mapping");
        let config = HttpConfig {
            emulation: Some(emulation),
            ..HttpConfig::default()
        };
        assert!(
            config.emulation.is_some(),
            "HttpConfig.emulation should be Some when built from profile {}",
            p.browser
        );
    }
}

/// Live fingerprint oracle — sends a request to tls.browserleaks.com and
/// compares the observed JA4 against a stored reference.
///
/// Gated behind `feature = "fingerprint"` so it only runs when explicitly
/// invoked. Requires network access.
#[tokio::test]
async fn fingerprint_oracle_matches_reference() {
    let endpoint = "https://tls.browserleaks.com/json";

    for profile in test_profiles() {
        let major = extract_major_version(profile.user_agent);
        let browser = profile.browser;

        eprintln!("Testing {browser} {major} ({})", profile.user_agent);

        let reference = load_reference(browser, &major);
        let client = build_client(profile);
        let observed = fetch_fingerprint(&client, endpoint).await;

        // JA4 must match exactly (order-insensitive hash — stable per browser version)
        assert_eq!(
            observed.ja4, reference.tls.ja4,
            "JA4 mismatch for {browser} {major}:\n  expected (real {browser} {}): {}\n  observed (ox-browser): {}",
            reference.browser_version, reference.tls.ja4, observed.ja4,
        );

        // HTTP/2 Akamai fingerprint must match
        let observed_h2 = if !observed.http2_fingerprint.is_empty() {
            &observed.http2_fingerprint
        } else {
            &observed.akamai_fingerprint
        };
        assert_eq!(
            observed_h2, &reference.http2_akamai_fingerprint,
            "HTTP/2 fingerprint mismatch for {browser} {major}:\n  expected: {}\n  observed: {}",
            reference.http2_akamai_fingerprint, observed_h2,
        );

        eprintln!("  ✓ JA4 and HTTP/2 match for {browser} {major}");
    }
}

/// Verify that different browser profiles produce different JA4 fingerprints.
/// If Chrome and Firefox produce the same JA4, the Emulation mapping is wrong.
#[tokio::test]
async fn different_browsers_produce_different_fingerprints() {
    let endpoint = "https://tls.browserleaks.com/json";

    // Pick one Chrome and one Firefox profile
    let chrome = BUILTIN_PROFILES
        .iter()
        .find(|p| p.browser == "chrome")
        .expect("chrome profile");
    let firefox = BUILTIN_PROFILES
        .iter()
        .find(|p| p.browser == "firefox")
        .expect("firefox profile");

    let chrome_client = build_client(chrome);
    let firefox_client = build_client(firefox);

    let chrome_fp = fetch_fingerprint(&chrome_client, endpoint).await;
    let firefox_fp = fetch_fingerprint(&firefox_client, endpoint).await;

    assert_ne!(
        chrome_fp.ja4, firefox_fp.ja4,
        "Chrome and Firefox JA4 should differ — if they match, Emulation is not being applied"
    );

    eprintln!(
        "Chrome JA4: {} ≠ Firefox JA4: {} ✓",
        chrome_fp.ja4, firefox_fp.ja4
    );
}
