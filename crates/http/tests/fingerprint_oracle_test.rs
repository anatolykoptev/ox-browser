//! Fingerprint oracle — LIVE network tests.
//!
//! These tests hit real echo endpoints (tls.peet.ws, tls.browserleaks.com)
//! and require `--features fingerprint`. They are gated per-test (not
//! file-level) so that future offline tests added to this file are NOT
//! silently swallowed by a `#![cfg(feature = "fingerprint")]` gate — that
//! class of silent swallow is precisely why findings A and B survived a
//! full review round.
//!
//! Run explicitly:
//!     cargo test -p ox-http --features fingerprint --test fingerprint_oracle_test
//!
//! # Architecture (ported from go-stealth)
//!
//! Two echo services are used because no single service is spec-faithful for
//! every metric:
//!
//!   - **peet** (`tls.peet.ws/api/all`): JA3, peetprint, HTTP/2 Akamai
//!     fingerprint, header order, sec-ch-ua. Spec-faithful JA3 (legacy_version
//!     = 771). NOT FoxIO-compliant for JA4 (strips padding extension 0x0015).
//!   - **browserleaks** (`tls.browserleaks.com/json`): JA3, JA3n, JA4, JA4_o,
//!     HTTP/2 Akamai. FoxIO-faithful JA4 (keeps 0x0015). Does NOT expose
//!     peetprint, header order, or sec-ch-ua.
//!
//! Each metric in the reference and the observed carries its source service in
//! `Sources`. `Compare` FAILs if a reference and a measurement for the same
//! metric come from different services — a cross-service comparison reports a
//! tooling artefact as a fingerprint defect.
//!
//! References live in `tests/fixtures/reference_chrome_<major>.json`, produced
//! by go-stealth's `cmd/fingerprint-capture` tool (downloads a Chrome-for-Testing
//! build of the given major, runs it against both endpoints, writes the
//! reference JSON with full provenance). The references are browser-level, not
//! library-level — they describe what a real Chrome emits, not what go-stealth
//! or ox-browser emits — so they are reusable across HTTP client libraries.
//!
//! A failure means ox-browser's Emulation profile emits a fingerprint that
//! differs from what a real browser of the same version emits. That is a true
//! result, not a defect in the test: a stale or wrong profile SHOULD fail the
//! oracle. Fix the profile in a separate reviewed change; do not weaken the
//! comparison to make it green.
//!
//! An unreachable endpoint or a missing reference is an ERROR (never a skip)
//! — a skip looks identical to a pass, which is the exact failure class this
//! repo keeps hitting.

// All tests in this file are #[cfg(feature = "fingerprint")]. Every helper
// below is used ONLY by those gated tests. Cfg-gating the helpers alongside
// the tests (rather than a file-level #![allow(dead_code)]) ensures that
// `cargo clippy --all-targets` WITHOUT --features fingerprint compiles this
// target as an empty shell — zero warnings, zero blindness. The
// `--features fingerprint` check in `make preflight` type-checks the gated
// code so a signature change on any API it consumes is caught in CI.
#[cfg(feature = "fingerprint")]
mod common;

#[cfg(feature = "fingerprint")]
use std::time::Duration;

#[cfg(feature = "fingerprint")]
use common::*;
#[cfg(feature = "fingerprint")]
use ox_http::{BUILTIN_PROFILES, BrowserProfile, HttpClient, HttpConfig};

// ── Echo service endpoints ─────────────────────────────────────────────

#[cfg(feature = "fingerprint")]
const PEET_ENDPOINT: &str = "https://tls.peet.ws/api/all";
#[cfg(feature = "fingerprint")]
const BROWSERLEAKS_ENDPOINT: &str = "https://tls.browserleaks.com/json";

// ── Peet response parsing ──────────────────────────────────────────────
//
// peet.ws /api/all returns a JSON object with `tls`, `http2`, `user_agent`
// top-level keys. The `http2` object contains `akamai_fingerprint` and
// `sent_frames` (an array of HEADERS frames with `headers` arrays of
// "name: value" strings).

#[cfg(feature = "fingerprint")]
fn extract_peet(raw: &serde_json::Value) -> Observed {
    let mut o = Observed::default();

    let tls = &raw["tls"];
    o.tls.ja3 = tls["ja3"].as_str().unwrap_or("").to_string();
    o.tls.ja3_hash = tls["ja3_hash"].as_str().unwrap_or("").to_string();
    o.tls.peetprint = tls["peetprint"].as_str().unwrap_or("").to_string();
    o.tls.peetprint_hash = tls["peetprint_hash"].as_str().unwrap_or("").to_string();

    o.user_agent = raw["user_agent"].as_str().unwrap_or("").to_string();

    let h2 = &raw["http2"];
    o.http2_akamai_fingerprint = h2["akamai_fingerprint"].as_str().unwrap_or("").to_string();

    // Extract header order from the first HEADERS frame.
    if let Some(frames) = h2["sent_frames"].as_array() {
        for frame in frames {
            if frame["frame_type"].as_str() != Some("HEADERS") {
                continue;
            }
            if let Some(headers) = frame["headers"].as_array() {
                for h in headers {
                    if let Some(hs) = h.as_str() {
                        // Skip pseudo-headers (:method, :path, etc.) — their
                        // order is encoded in the akamai fingerprint, not the
                        // regular header order.
                        if hs.starts_with(':') {
                            continue;
                        }
                        let (name, val) = split_header(hs);
                        o.header_order.push(name.clone());
                        match name.as_str() {
                            "sec-ch-ua" => o.sec_ch_ua = val,
                            "sec-ch-ua-mobile" => o.sec_ch_ua_mobile = val,
                            "sec-ch-ua-platform" => o.sec_ch_ua_platform = val,
                            "accept" => o.accept = val,
                            "accept-language" => o.accept_language = val,
                            "accept-encoding" => o.accept_encoding = val,
                            _ => {}
                        }
                    }
                }
            }
            break; // first HEADERS frame is the request
        }
    }

    o.sources = Sources {
        ja3: SERVICE_PEET.to_string(),
        peetprint: SERVICE_PEET.to_string(),
        http2: SERVICE_PEET.to_string(),
        headers: SERVICE_PEET.to_string(),
        ..Default::default()
    };
    o
}

// ── Browserleaks response parsing ──────────────────────────────────────
//
// tls.browserleaks.com/json returns a flat JSON object with ja3_hash, ja3n_hash,
// ja4, ja4_o, akamai_text (HTTP/2 Akamai fingerprint), and user_agent.

#[cfg(feature = "fingerprint")]
fn extract_browserleaks(raw: &serde_json::Value) -> Observed {
    let mut o = Observed::default();

    o.tls.ja3_hash = raw["ja3_hash"].as_str().unwrap_or("").to_string();
    o.tls.ja3n_hash = raw["ja3n_hash"].as_str().unwrap_or("").to_string();
    o.tls.ja4 = raw["ja4"].as_str().unwrap_or("").to_string();
    o.tls.ja4_o = raw["ja4_o"].as_str().unwrap_or("").to_string();
    o.http2_akamai_fingerprint = raw["akamai_text"].as_str().unwrap_or("").to_string();

    o.sources = Sources {
        ja3: SERVICE_BROWSERLEAKS.to_string(),
        ja3n: SERVICE_BROWSERLEAKS.to_string(),
        ja4: SERVICE_BROWSERLEAKS.to_string(),
        ja4_o: SERVICE_BROWSERLEAKS.to_string(),
        http2: SERVICE_BROWSERLEAKS.to_string(),
        ..Default::default()
    };
    o
}

// ── Merge peet + browserleaks observations ─────────────────────────────

/// Combine a peet-sourced and a browserleaks-sourced Observed into one.
/// browserleaks takes precedence for JA4, JA3n, JA4_o (FoxIO-faithful);
/// peet takes precedence for peetprint, header order, sec-ch-ua (browserleaks
/// does not expose them). JA3 hash and HTTP/2 Akamai come from browserleaks.
#[cfg(feature = "fingerprint")]
fn merge_observed(peet: Observed, bl: Observed) -> Observed {
    let mut merged = peet; // start with peet (peetprint, headers, sec-ch-ua, accept*)

    // Overwrite / fill in browserleaks-sourced metrics.
    merged.tls.ja3_hash = bl.tls.ja3_hash;
    merged.tls.ja3n_hash = bl.tls.ja3n_hash;
    merged.tls.ja4 = bl.tls.ja4;
    merged.tls.ja4_o = bl.tls.ja4_o;
    merged.http2_akamai_fingerprint = bl.http2_akamai_fingerprint;

    merged.sources = Sources {
        ja3: bl.sources.ja3.clone(),
        ja3n: bl.sources.ja3n.clone(),
        ja4: bl.sources.ja4.clone(),
        ja4_o: bl.sources.ja4_o.clone(),
        peetprint: merged.sources.peetprint.clone(),
        http2: bl.sources.http2.clone(),
        headers: merged.sources.headers.clone(),
    };
    merged
}

// ── Test helpers ───────────────────────────────────────────────────────

/// Chrome/linux profiles deduplicated by major version. The TLS/HTTP2
/// fingerprint is per-major, not per-OS, so testing the linux variant of each
/// major covers every Chrome profile without redundant requests.
#[cfg(feature = "fingerprint")]
fn chrome_linux_profiles() -> Vec<&'static BrowserProfile> {
    let mut seen: Vec<String> = Vec::new();
    let mut result = Vec::new();
    for p in BUILTIN_PROFILES {
        if p.browser != "chrome" || p.os != "linux" {
            continue;
        }
        let major = extract_major_version(p.user_agent);
        if seen.contains(&major) {
            continue;
        }
        seen.push(major);
        result.push(p);
    }
    result
}

/// Build an HttpClient through the SAME public entry point the service uses
/// (HttpConfig { profile: Some(..), .. }). HttpClient::new derives the
/// TLS/HTTP2 Emulation from the profile internally — so the thing under test
/// and the thing shipped cannot diverge. (Issue #81: oracle measures shipped
/// construction.)
#[cfg(feature = "fingerprint")]
fn build_client(profile: &'static BrowserProfile) -> HttpClient {
    let config = HttpConfig {
        profile: Some(profile),
        timeout: Duration::from_secs(30),
        ..HttpConfig::default()
    };
    HttpClient::new(config)
        .unwrap_or_else(|e| panic!("HttpClient::new with {:?}: {e}", profile.browser))
}

/// Fetch JSON from an echo endpoint using the given client.
/// An unreachable endpoint is a fatal error (not a skip).
#[cfg(feature = "fingerprint")]
async fn fetch_json(client: &HttpClient, endpoint: &str, label: &str) -> serde_json::Value {
    let resp = client.get(endpoint).await.unwrap_or_else(|e| {
        panic!(
            "{} endpoint unreachable (this is an ERROR, not a skip): {e}",
            label
        )
    });
    assert_eq!(
        resp.status, 200,
        "{} returned status {} (expected 200)",
        label, resp.status
    );
    serde_json::from_str(&resp.body).unwrap_or_else(|e| panic!("parse {} response: {e}", label))
}

/// Capture the observed fingerprint from both echo endpoints using a client
/// built with the given profile.
#[cfg(feature = "fingerprint")]
async fn capture_with_client(profile: &'static BrowserProfile) -> Observed {
    let client = build_client(profile);

    // peet: JA3, peetprint, HTTP/2 akamai, header order, sec-ch-ua.
    let peet_raw = fetch_json(&client, PEET_ENDPOINT, "peet").await;
    let peet_obs = extract_peet(&peet_raw);

    // browserleaks: JA3, JA3n, JA4, JA4_o, HTTP/2 akamai (FoxIO-faithful JA4).
    let bl_raw = fetch_json(&client, BROWSERLEAKS_ENDPOINT, "browserleaks").await;
    let bl_obs = extract_browserleaks(&bl_raw);

    let obs = merge_observed(peet_obs, bl_obs);

    // Sanity: confirm the request actually went out as h2 with a JA4, so a
    // silent downgrade (e.g. http/1.1 with no akamai fingerprint) doesn't pass
    // as "all fields matched because none were extracted".
    assert!(
        !obs.http2_akamai_fingerprint.is_empty(),
        "no HTTP/2 akamai fingerprint in merged response — peet body: {}, browserleaks body: {}",
        preview_json(&peet_raw),
        preview_json(&bl_raw)
    );
    assert!(
        !obs.tls.ja4.is_empty(),
        "no JA4 in browserleaks response — body: {}",
        preview_json(&bl_raw)
    );

    obs
}

#[cfg(feature = "fingerprint")]
fn preview_json(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| format!("{:?}", v))
}

// ── Tests ──────────────────────────────────────────────────────────────

/// The fingerprint oracle: for each Chrome/linux profile, build an ox-browser
/// client, hit both echo endpoints, and compare the observed fingerprint
/// against the stored reference for the same major.
#[cfg(feature = "fingerprint")]
#[tokio::test]
async fn test_fingerprint_oracle() {
    let profiles = chrome_linux_profiles();
    assert!(!profiles.is_empty(), "no Chrome/linux profiles found");

    for &profile in &profiles {
        let major = extract_major_version(profile.user_agent);
        eprintln!("\n=== Chrome {} ({}) ===", major, profile.user_agent);

        let ref_path = reference_path(&major);
        assert!(
            ref_path.exists(),
            "no reference for Chrome major {} at {} (this is an ERROR, not a skip)\n\
             Run go-stealth's capture tool to create one:\n\
             cd ~/src/go-stealth && go run ./cmd/fingerprint-capture -major {}",
            major,
            ref_path.display(),
            major,
        );

        let reference = load_reference(&major);
        assert_eq!(
            reference.major, major,
            "reference major mismatch: reference is {}, profile is {} — wrong reference file",
            reference.major, major
        );

        let observed = capture_with_client(profile).await;
        let (diffs, skipped) = compare(&observed, &reference);

        for s in &skipped {
            eprintln!("  SKIP {}", s);
        }

        // Classify diffs against the two suppression buckets (see
        // `classify_fingerprint_diffs` in tls.rs). Bucket A = structurally
        // non-comparable (permanent policy: ja3_hash, ja4_o are
        // order-sensitive, Chrome permutes extensions per handshake). Bucket
        // B = the trust_anchors gap (issue #81, temporary — self-expiring:
        // if a bucket-B field now matches, the test FAILS so the suppression
        // list does not go stale).
        let diff_tuples: Vec<(String, String, String)> = diffs
            .iter()
            .map(|d| (d.field.clone(), d.expected.clone(), d.observed.clone()))
            .collect();
        // Fix B: the branch selection (gap_exhibited → comparable_b;
        // else → empty bucket B) lives in `classify_for_reference` in
        // common/mod.rs — the SAME function the offline tests exercise
        // with both committed fixtures (Chrome 131 + Chrome 148), not a
        // re-typed copy. Deleting the `else` branch inside it breaks
        // `classify_for_reference_chrome131_bucket_b_diff_is_hard_failure`.
        let verdict = classify_for_reference(&reference, &diff_tuples);

        for f in &verdict.tolerated_a {
            eprintln!(
                "  KNOWN-POLICY {} (bucket A: order-sensitive, permanent)",
                f
            );
        }
        for f in &verdict.tolerated_b {
            eprintln!("  KNOWN-GAP {} (bucket B: trust_anchors gap, issue #81)", f);
        }

        // F1: print each failure class independently. No `else if` may mask a
        // non-empty list. `FingerprintVerdict::is_ok()` is
        // `hard_failures.is_empty() && gap_closed.is_empty()`, so when BOTH
        // are non-empty the old `else if !verdict.gap_closed.is_empty()` arm
        // swallowed the `else` printing hard_failures — a genuine profile
        // regression printed as "fingerprint gap CLOSED … remove them from
        // FP_BUCKET_B", instructing the operator to DELETE suppression
        // entries in response to a defect the report never showed. Now both
        // classes print unconditionally, and exactly ONE panic at the end
        // names BOTH counts.
        if !verdict.hard_failures.is_empty() {
            for d in &verdict.hard_failures {
                eprintln!(
                    "  FIELD {}\n    expected (real Chrome {}): {}\n    observed (ox-browser): {}",
                    d.0, reference.browser_version, d.1, d.2
                );
            }
        }
        if !verdict.gap_closed.is_empty() {
            for f in &verdict.gap_closed {
                eprintln!(
                    "  GAP-CLOSED {} — bucket-B field now matches the reference; \
                     remove it from FP_BUCKET_B in tls.rs",
                    f
                );
            }
        }

        if verdict.is_ok() && diffs.is_empty() {
            eprintln!("  ✓ all fields match for Chrome {}", major);
        } else if verdict.is_ok() {
            eprintln!(
                "  ✓ all fixable fields match for Chrome {} ({} bucket-A policy {}, {} bucket-B gap {} remain)",
                major,
                verdict.tolerated_a.len(),
                if verdict.tolerated_a.len() == 1 {
                    "field"
                } else {
                    "fields"
                },
                verdict.tolerated_b.len(),
                if verdict.tolerated_b.len() == 1 {
                    "field"
                } else {
                    "fields"
                },
            );
        } else {
            panic!("{}", fingerprint_fail_message(&verdict, &major));
        }
    }
}

/// Verify that different browser profiles produce different JA4 fingerprints.
/// If Chrome and Firefox produce the same JA4, the Emulation mapping is wrong.
#[cfg(feature = "fingerprint")]
#[tokio::test]
async fn different_browsers_produce_different_fingerprints() {
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

    let chrome_raw = fetch_json(&chrome_client, BROWSERLEAKS_ENDPOINT, "browserleaks").await;
    let firefox_raw = fetch_json(&firefox_client, BROWSERLEAKS_ENDPOINT, "browserleaks").await;

    let chrome_ja4 = chrome_raw["ja4"].as_str().unwrap_or("");
    let firefox_ja4 = firefox_raw["ja4"].as_str().unwrap_or("");

    assert_ne!(
        chrome_ja4, firefox_ja4,
        "Chrome and Firefox JA4 should differ — if they match, Emulation is not being applied"
    );

    eprintln!(
        "Chrome JA4: {} ≠ Firefox JA4: {} ✓",
        chrome_ja4, firefox_ja4
    );
}
