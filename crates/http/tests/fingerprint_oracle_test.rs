//! Fingerprint oracle — verifies ox-browser's emitted TLS/HTTP2/header
//! fingerprint matches a real browser's, using the same dual-service
//! architecture as go-stealth's oracle.
//!
//! Build-tagged behind `#[cfg(feature = "fingerprint")]` so it NEVER runs in
//! `make preflight` (which uses default features). Run explicitly:
//!
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

#![cfg(feature = "fingerprint")]

use std::time::Duration;

use ox_http::{BUILTIN_PROFILES, BrowserProfile, HttpClient, HttpConfig, profile_to_emulation};
use serde::{Deserialize, Serialize};

// ── Echo service endpoints ─────────────────────────────────────────────

const PEET_ENDPOINT: &str = "https://tls.peet.ws/api/all";
const BROWSERLEAKS_ENDPOINT: &str = "https://tls.browserleaks.com/json";

const SERVICE_PEET: &str = "peet";
const SERVICE_BROWSERLEAKS: &str = "browserleaks";

// ── Reference (captured real-browser fingerprint) ──────────────────────

/// A captured browser fingerprint used as the oracle's ground truth.
/// A reference without provenance is unfalsifiable later.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Reference {
    browser: String,
    browser_version: String,
    major: String,
    capture_time: String,
    endpoint: String,
    mode: String,
    arch: String,
    browser_source: String,

    /// Per-metric source services. A reference and a measurement for the same
    /// metric MUST come from the same service.
    #[serde(default)]
    sources: Sources,

    tls: TlsFingerprint,
    http2_akamai_fingerprint: String,

    #[serde(default)]
    header_order: Vec<String>,
    #[serde(default)]
    sec_ch_ua: String,
    #[serde(default)]
    sec_ch_ua_mobile: String,
    #[serde(default)]
    sec_ch_ua_platform: String,
    #[serde(default)]
    accept: String,
    #[serde(default)]
    accept_language: String,
    #[serde(default)]
    accept_encoding: String,
    #[serde(default)]
    user_agent: String,

    /// Caveats that make a field non-comparable (e.g. headless mode excludes
    /// UA/sec-ch-ua). The oracle reads Notes to skip fields with a reason.
    #[serde(default)]
    notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Sources {
    #[serde(default)]
    ja3: String,
    #[serde(default)]
    ja3n: String,
    #[serde(default)]
    ja4: String,
    #[serde(default)]
    ja4_o: String,
    #[serde(default)]
    peetprint: String,
    #[serde(default)]
    http2: String,
    #[serde(default)]
    headers: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TlsFingerprint {
    #[serde(default)]
    ja3: String,
    #[serde(default)]
    ja3_hash: String,
    #[serde(default)]
    ja3n_hash: String,
    #[serde(default)]
    ja4: String,
    #[serde(default)]
    ja4_o: String,
    #[serde(default)]
    peetprint: String,
    #[serde(default)]
    peetprint_hash: String,
}

// ── Observed (live measurement from echo services) ─────────────────────

/// The fingerprint extracted from echo-service responses for a single request.
/// Mirrors the comparable subset of Reference. Built by merging a peet
/// extraction and a browserleaks extraction.
#[derive(Debug, Default)]
struct Observed {
    sources: Sources,
    tls: TlsFingerprint,
    http2_akamai_fingerprint: String,
    header_order: Vec<String>,
    sec_ch_ua: String,
    sec_ch_ua_mobile: String,
    sec_ch_ua_platform: String,
    accept: String,
    accept_language: String,
    accept_encoding: String,
    user_agent: String,
}

// ── Field diff ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct FieldDiff {
    field: String,
    expected: String,
    observed: String,
}

// ── Reference loading ──────────────────────────────────────────────────

fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn reference_path(major: &str) -> std::path::PathBuf {
    fixture_dir().join(format!("reference_chrome_{}.json", major))
}

fn load_reference(major: &str) -> Reference {
    let path = reference_path(major);
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "no reference for Chrome major {} at {} (this is an ERROR, not a skip): {e}\n\
             Run go-stealth's capture tool to create one:\n\
             cd ~/src/go-stealth && go run ./cmd/fingerprint-capture -major {}",
            major,
            path.display(),
            major,
        )
    });
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("parse reference {}: {e}", path.display()))
}

// ── Peet response parsing ──────────────────────────────────────────────
//
// peet.ws /api/all returns a JSON object with `tls`, `http2`, `user_agent`
// top-level keys. The `http2` object contains `akamai_fingerprint` and
// `sent_frames` (an array of HEADERS frames with `headers` arrays of
// "name: value" strings).

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

fn split_header(h: &str) -> (String, String) {
    if let Some(idx) = h.find(':') {
        let name = h[..idx].trim().to_lowercase();
        let val = h[idx + 1..].trim().to_string();
        (name, val)
    } else {
        (h.trim().to_string(), String::new())
    }
}

// ── Browserleaks response parsing ──────────────────────────────────────
//
// tls.browserleaks.com/json returns a flat JSON object with ja3_hash, ja3n_hash,
// ja4, ja4_o, akamai_text (HTTP/2 Akamai fingerprint), and user_agent.

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

// ── Compare observed vs reference ──────────────────────────────────────

/// Report per-field differences between an Observed (ox-browser client) and a
/// Reference (real browser). Fields the reference excludes (listed in Notes)
/// are skipped with a reason returned in `skipped`.
///
/// For each metric, checks that the reference and observed Sources agree before
/// comparing values. If they disagree, the metric is reported as a
/// source-violation FieldDiff (field name prefixed "source:") and the values
/// are NOT compared — a cross-service comparison reports a tooling artefact as
/// a fingerprint defect.
fn compare(o: &Observed, r: &Reference) -> (Vec<FieldDiff>, Vec<String>) {
    let mut diffs = Vec::new();
    let mut skipped = Vec::new();

    let skip_ua = r.note_excludes("user-agent");
    let skip_sec_ch_ua = r.note_excludes("sec-ch-ua");

    // --- JA3 (hash) ---
    if let Some(d) = check_source("ja3", &r.sources.ja3, &o.sources.ja3) {
        diffs.push(d);
    } else if o.tls.ja3_hash != r.tls.ja3_hash {
        diffs.push(FieldDiff {
            field: "ja3_hash".into(),
            expected: r.tls.ja3_hash.clone(),
            observed: o.tls.ja3_hash.clone(),
        });
    }

    // --- JA3n (order-insensitive, browserleaks) ---
    if !r.tls.ja3n_hash.is_empty() || !r.sources.ja3n.is_empty() {
        if let Some(d) = check_source("ja3n", &r.sources.ja3n, &o.sources.ja3n) {
            diffs.push(d);
        } else if o.tls.ja3n_hash != r.tls.ja3n_hash {
            diffs.push(FieldDiff {
                field: "ja3n_hash".into(),
                expected: r.tls.ja3n_hash.clone(),
                observed: o.tls.ja3n_hash.clone(),
            });
        }
    }

    // --- JA4 (browserleaks, FoxIO-faithful) ---
    if let Some(d) = check_source("ja4", &r.sources.ja4, &o.sources.ja4) {
        diffs.push(d);
    } else if o.tls.ja4 != r.tls.ja4 {
        diffs.push(FieldDiff {
            field: "ja4".into(),
            expected: r.tls.ja4.clone(),
            observed: o.tls.ja4.clone(),
        });
    }

    // --- JA4_o (original order, browserleaks) ---
    if !r.tls.ja4_o.is_empty() || !r.sources.ja4_o.is_empty() {
        if let Some(d) = check_source("ja4_o", &r.sources.ja4_o, &o.sources.ja4_o) {
            diffs.push(d);
        } else if o.tls.ja4_o != r.tls.ja4_o {
            diffs.push(FieldDiff {
                field: "ja4_o".into(),
                expected: r.tls.ja4_o.clone(),
                observed: o.tls.ja4_o.clone(),
            });
        }
    }

    // --- peetprint (peet only) ---
    if !r.tls.peetprint_hash.is_empty() || !r.sources.peetprint.is_empty() {
        if let Some(d) = check_source("peetprint", &r.sources.peetprint, &o.sources.peetprint) {
            diffs.push(d);
        } else if o.tls.peetprint_hash != r.tls.peetprint_hash {
            diffs.push(FieldDiff {
                field: "peetprint_hash".into(),
                expected: r.tls.peetprint_hash.clone(),
                observed: o.tls.peetprint_hash.clone(),
            });
        }
    }

    // --- HTTP/2 Akamai fingerprint ---
    if let Some(d) = check_source("http2_akamai", &r.sources.http2, &o.sources.http2) {
        diffs.push(d);
    } else if o.http2_akamai_fingerprint != r.http2_akamai_fingerprint {
        diffs.push(FieldDiff {
            field: "http2_akamai".into(),
            expected: r.http2_akamai_fingerprint.clone(),
            observed: o.http2_akamai_fingerprint.clone(),
        });
    }

    // --- header order + sec-ch-ua + accept* (peet only) ---
    if !r.sources.headers.is_empty() || !o.sources.headers.is_empty() {
        if let Some(d) = check_source("header_order", &r.sources.headers, &o.sources.headers) {
            diffs.push(d);
        } else {
            if o.header_order != r.header_order {
                diffs.push(FieldDiff {
                    field: "header_order".into(),
                    expected: r.header_order.join(","),
                    observed: o.header_order.join(","),
                });
            }
            if !skip_sec_ch_ua {
                if normalize_sec_ch_ua(&o.sec_ch_ua) != normalize_sec_ch_ua(&r.sec_ch_ua)
                    && !r.sec_ch_ua.is_empty()
                {
                    diffs.push(FieldDiff {
                        field: "sec_ch_ua".into(),
                        expected: r.sec_ch_ua.clone(),
                        observed: o.sec_ch_ua.clone(),
                    });
                }
            } else {
                skipped.push("sec-ch-ua: excluded by reference note (headless mode)".into());
            }
            if o.sec_ch_ua_mobile != r.sec_ch_ua_mobile && !r.sec_ch_ua_mobile.is_empty() {
                diffs.push(FieldDiff {
                    field: "sec_ch_ua_mobile".into(),
                    expected: r.sec_ch_ua_mobile.clone(),
                    observed: o.sec_ch_ua_mobile.clone(),
                });
            }
            if o.sec_ch_ua_platform != r.sec_ch_ua_platform && !r.sec_ch_ua_platform.is_empty() {
                diffs.push(FieldDiff {
                    field: "sec_ch_ua_platform".into(),
                    expected: r.sec_ch_ua_platform.clone(),
                    observed: o.sec_ch_ua_platform.clone(),
                });
            }
            if o.accept != r.accept && !r.accept.is_empty() {
                diffs.push(FieldDiff {
                    field: "accept".into(),
                    expected: r.accept.clone(),
                    observed: o.accept.clone(),
                });
            }
            if o.accept_language != r.accept_language && !r.accept_language.is_empty() {
                diffs.push(FieldDiff {
                    field: "accept_language".into(),
                    expected: r.accept_language.clone(),
                    observed: o.accept_language.clone(),
                });
            }
            if o.accept_encoding != r.accept_encoding && !r.accept_encoding.is_empty() {
                diffs.push(FieldDiff {
                    field: "accept_encoding".into(),
                    expected: r.accept_encoding.clone(),
                    observed: o.accept_encoding.clone(),
                });
            }
        }
    }

    // --- user-agent ---
    if !skip_ua {
        if o.user_agent != r.user_agent && !r.user_agent.is_empty() {
            diffs.push(FieldDiff {
                field: "user_agent".into(),
                expected: r.user_agent.clone(),
                observed: o.user_agent.clone(),
            });
        }
    } else {
        skipped.push("user-agent: excluded by reference note (headless mode)".into());
    }

    (diffs, skipped)
}

/// Returns a non-nil FieldDiff if the reference and observed sources for a
/// metric disagree. A cross-service comparison is a hard FAIL.
fn check_source(metric: &str, ref_src: &str, obs_src: &str) -> Option<FieldDiff> {
    if ref_src.is_empty() || obs_src.is_empty() {
        return None; // metric not present on one side; value comparison handles it
    }
    if ref_src == obs_src {
        return None;
    }
    Some(FieldDiff {
        field: format!("source:{}", metric),
        expected: format!("reference source={}", ref_src),
        observed: format!(
            "observed source={} — cross-service comparison is a tooling artefact, not a fingerprint defect",
            obs_src
        ),
    })
}

impl Reference {
    fn note_excludes(&self, field: &str) -> bool {
        self.notes.iter().any(|n| {
            n.contains(&format!("excludes {}", field))
                || n.contains(&format!("{}: excluded", field))
        })
    }
}

/// Replace the GREASE brand in a sec-ch-ua header value with a placeholder.
/// The GREASE brand is seed-permuted by Chrome per connection, so a raw
/// compare flaps. The Chromium and Google Chrome brands (with version) are
/// compared exactly.
fn normalize_sec_ch_ua(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    s.split(", ")
        .map(|p| {
            let brand = p.split(';').next().unwrap_or("").trim().trim_matches('"');
            if brand != "Chromium" && brand != "Google Chrome" && brand != "Microsoft Edge" {
                "GREASE".to_string()
            } else {
                p.trim().to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// ── Test helpers ───────────────────────────────────────────────────────

fn extract_major_version(ua: &str) -> String {
    if let Some(pos) = ua.find("Chrome/") {
        return ua[pos + 7..].split('.').next().unwrap_or("0").to_string();
    }
    if let Some(pos) = ua.find("rv:") {
        return ua[pos + 3..].split('.').next().unwrap_or("0").to_string();
    }
    if let Some(pos) = ua.find("Version/") {
        return ua[pos + 8..].split('.').next().unwrap_or("0").to_string();
    }
    "0".to_string()
}

/// Chrome/linux profiles deduplicated by major version. The TLS/HTTP2
/// fingerprint is per-major, not per-OS, so testing the linux variant of each
/// major covers every Chrome profile without redundant requests.
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

/// Fetch JSON from an echo endpoint using the given client.
/// An unreachable endpoint is a fatal error (not a skip).
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
async fn capture_with_client(profile: &BrowserProfile) -> Observed {
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

fn preview_json(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| format!("{:?}", v))
}

// ── Tests ──────────────────────────────────────────────────────────────

/// The fingerprint oracle: for each Chrome/linux profile, build an ox-browser
/// client, hit both echo endpoints, and compare the observed fingerprint
/// against the stored reference for the same major.
#[tokio::test]
async fn test_fingerprint_oracle() {
    let profiles = chrome_linux_profiles();
    assert!(!profiles.is_empty(), "no Chrome/linux profiles found");

    for profile in &profiles {
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

        if diffs.is_empty() {
            eprintln!("  ✓ all fields match for Chrome {}", major);
        } else {
            for d in &diffs {
                eprintln!(
                    "  FIELD {}\n    expected (real Chrome {}): {}\n    observed (ox-browser): {}",
                    d.field, reference.browser_version, d.expected, d.observed
                );
            }
            panic!(
                "fingerprint mismatch for Chrome {}: {} field(s) differ",
                major,
                diffs.len()
            );
        }
    }
}

/// Verify that every committed reference file carries the provenance fields
/// that make it falsifiable later — including per-metric Sources. A reference
/// without provenance is a reference that can silently rot.
#[test]
fn test_reference_provenance() {
    let dir = fixture_dir();
    let mut any = false;
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read fixtures dir {}: {e}", dir.display()));

    for entry in entries {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("reference_chrome_") || !name.ends_with(".json") {
            continue;
        }
        any = true;
        let path = entry.path();
        let r: Reference = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display())),
        )
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

        // Provenance fields
        if r.browser_version.is_empty()
            || r.major.is_empty()
            || r.capture_time.is_empty()
            || r.endpoint.is_empty()
            || r.mode.is_empty()
            || r.browser_source.is_empty()
        {
            panic!(
                "{}: missing provenance (browser={}, version={}, major={}, captured={}, endpoint={}, mode={}, source={})",
                name,
                r.browser,
                r.browser_version,
                r.major,
                r.capture_time,
                r.endpoint,
                r.mode,
                r.browser_source
            );
        }

        // Per-metric sources: JA4 MUST be sourced from browserleaks (FoxIO-faithful),
        // not peet (which strips padding 0x0015).
        if r.sources.ja4.is_empty() {
            panic!(
                "{}: missing sources.ja4 — JA4 source must be recorded",
                name
            );
        } else if r.sources.ja4 == SERVICE_PEET {
            panic!(
                "{}: sources.ja4={} — peet is NOT FoxIO-compliant for JA4; use browserleaks",
                name, r.sources.ja4
            );
        }
        if r.sources.ja3.is_empty() {
            panic!(
                "{}: missing sources.ja3 — JA3 source must be recorded",
                name
            );
        }
        if r.sources.http2.is_empty() {
            panic!(
                "{}: missing sources.http2 — HTTP/2 Akamai source must be recorded",
                name
            );
        }

        // Core fingerprint fields
        if r.tls.ja3_hash.is_empty()
            || r.tls.ja4.is_empty()
            || r.http2_akamai_fingerprint.is_empty()
        {
            panic!(
                "{}: missing fingerprint fields (ja3_hash={}, ja4={}, akamai={})",
                name, r.tls.ja3_hash, r.tls.ja4, r.http2_akamai_fingerprint
            );
        }
    }

    assert!(
        any,
        "no reference_chrome_*.json files in {} — run go-stealth's capture tool to create one",
        dir.display()
    );
}

/// Verify that profile_to_emulation maps every builtin profile to a non-None
/// Emulation. This is the P0 gate — if any profile has no Emulation, TLS
/// fingerprinting is silently disabled for that profile.
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

/// Verify that different browser profiles produce different JA4 fingerprints.
/// If Chrome and Firefox produce the same JA4, the Emulation mapping is wrong.
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
