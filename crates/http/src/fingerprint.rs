//! Fingerprint oracle — shared logic used by the live network test
//! (`tests/fingerprint_oracle_test.rs`), the offline classification tests
//! (`tests/fingerprint_offline_test.rs`), and the `ox-browser doctor`
//! subcommand.
//!
//! This module is the single home of the oracle's comparison + classification
//! logic. It used to live in `tests/common/mod.rs`, which only test targets
//! could compile — so `doctor` (a shipped binary surface) could not reuse it
//! without copying. Moving it here means the test targets and the binary
//! exercise the SAME code path (issue #109).
//!
//! The test-side filesystem loader (`fixture_dir` / `reference_path` /
//! `load_reference` in `tests/common/mod.rs`) stays as it is — it reads the
//! fixtures via `env!("CARGO_MANIFEST_DIR")` and panics on a missing file,
//! which is correct for a test but wrong for a shipped binary. `doctor` loads
//! the references from the embedded bytes below ([`embedded_reference`]).
//!
//! Nothing here is feature-gated. The live network calls stay behind
//! `#[cfg(feature = "fingerprint")]` in the test file; the echo-service
//! response parsers ([`extract_peet`] / [`extract_browserleaks`] /
//! [`merge_observed`]) are pure functions over JSON and are needed by `doctor`
//! (which is not feature-gated), so they live here ungated.

use crate::tls::{
    FP_BUCKET_A, FP_BUCKET_B, FingerprintVerdict, classify_fingerprint_diffs, classify_with,
    reference_exhibits_gap,
};
use serde::{Deserialize, Serialize};

// ── Echo service constants ─────────────────────────────────────────────

pub const SERVICE_PEET: &str = "peet";
pub const SERVICE_BROWSERLEAKS: &str = "browserleaks";

pub const PEET_ENDPOINT: &str = "https://tls.peet.ws/api/all";
pub const BROWSERLEAKS_ENDPOINT: &str = "https://tls.browserleaks.com/json";

// ── Reference (captured real-browser fingerprint) ──────────────────────

/// A captured browser fingerprint used as the oracle's ground truth.
/// A reference without provenance is unfalsifiable later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub browser: String,
    pub browser_version: String,
    pub major: String,
    pub capture_time: String,
    pub endpoint: String,
    pub mode: String,
    pub arch: String,
    pub browser_source: String,

    /// Per-metric source services. A reference and a measurement for the same
    /// metric MUST come from the same service.
    #[serde(default)]
    pub sources: Sources,

    pub tls: TlsFingerprint,
    pub http2_akamai_fingerprint: String,

    #[serde(default)]
    pub header_order: Vec<String>,
    #[serde(default)]
    pub sec_ch_ua: String,
    #[serde(default)]
    pub sec_ch_ua_mobile: String,
    #[serde(default)]
    pub sec_ch_ua_platform: String,
    #[serde(default)]
    pub accept: String,
    #[serde(default)]
    pub accept_language: String,
    #[serde(default)]
    pub accept_encoding: String,
    #[serde(default)]
    pub user_agent: String,

    /// Caveats that make a field non-comparable (e.g. headless mode excludes
    /// UA/sec-ch-ua). The oracle reads Notes to skip fields with a reason.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl Reference {
    /// Used by `compare` and by the gated live test file. Marked
    /// `allow(dead_code)` because not every consumer calls it.
    #[allow(dead_code)]
    pub fn note_excludes(&self, field: &str) -> bool {
        self.notes.iter().any(|n| {
            n.contains(&format!("excludes {}", field))
                || n.contains(&format!("{}: excluded", field))
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sources {
    #[serde(default)]
    pub ja3: String,
    #[serde(default)]
    pub ja3n: String,
    #[serde(default)]
    pub ja4: String,
    #[serde(default)]
    pub ja4_o: String,
    #[serde(default)]
    pub peetprint: String,
    #[serde(default)]
    pub http2: String,
    #[serde(default)]
    pub headers: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsFingerprint {
    #[serde(default)]
    pub ja3: String,
    #[serde(default)]
    pub ja3_hash: String,
    #[serde(default)]
    pub ja3n_hash: String,
    #[serde(default)]
    pub ja4: String,
    #[serde(default)]
    pub ja4_o: String,
    #[serde(default)]
    pub peetprint: String,
    #[serde(default)]
    pub peetprint_hash: String,
}

// ── Field diff ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FieldDiff {
    pub field: String,
    pub expected: String,
    pub observed: String,
}

// ── Observed (live measurement from echo services) ─────────────────────

/// The fingerprint extracted from echo-service responses for a single request.
/// Mirrors the comparable subset of [`Reference`]. Built by merging a peet
/// extraction and a browserleaks extraction.
#[derive(Debug, Default)]
pub struct Observed {
    pub sources: Sources,
    pub tls: TlsFingerprint,
    pub http2_akamai_fingerprint: String,
    pub header_order: Vec<String>,
    pub sec_ch_ua: String,
    pub sec_ch_ua_mobile: String,
    pub sec_ch_ua_platform: String,
    pub accept: String,
    pub accept_language: String,
    pub accept_encoding: String,
    pub user_agent: String,
}

// ── Header / sec-ch-ua helpers ─────────────────────────────────────────

pub fn split_header(h: &str) -> (String, String) {
    if let Some(idx) = h.find(':') {
        let name = h[..idx].trim().to_lowercase();
        let val = h[idx + 1..].trim().to_string();
        (name, val)
    } else {
        (h.trim().to_string(), String::new())
    }
}

/// Replace the GREASE brand in a sec-ch-ua header value with a placeholder.
/// The GREASE brand is seed-permuted by Chrome per connection, so a raw
/// compare flaps. The Chromium and Google Chrome brands (with version) are
/// compared exactly.
pub fn normalize_sec_ch_ua(s: &str) -> String {
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

// ── Echo-service response parsing ──────────────────────────────────────
//
// peet.ws /api/all returns a JSON object with `tls`, `http2`, `user_agent`
// top-level keys. The `http2` object contains `akamai_fingerprint` and
// `sent_frames` (an array of HEADERS frames with `headers` arrays of
// "name: value" strings).

pub fn extract_peet(raw: &serde_json::Value) -> Observed {
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

// tls.browserleaks.com/json returns a flat JSON object with ja3_hash, ja3n_hash,
// ja4, ja4_o, akamai_text (HTTP/2 Akamai fingerprint), and user_agent.

pub fn extract_browserleaks(raw: &serde_json::Value) -> Observed {
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

/// Combine a peet-sourced and a browserleaks-sourced Observed into one.
/// browserleaks takes precedence for JA4, JA3n, JA4_o (FoxIO-faithful);
/// peet takes precedence for peetprint, header order, sec-ch-ua (browserleaks
/// does not expose them). JA3 hash and HTTP/2 Akamai come from browserleaks.
pub fn merge_observed(peet: Observed, bl: Observed) -> Observed {
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

// ── Source-consistency check ───────────────────────────────────────────
//
// Returns a non-nil FieldDiff if the reference and observed sources for a
// metric disagree. A cross-service comparison is a hard FAIL.
//
// The `field` argument is the BUCKET FIELD NAME (e.g. "ja3n_hash", not the
// short metric "ja3n"). The emitted diff is `source:<field>`, which is what
// `classify_with` strips and compares against FP_BUCKET_B names. Using the
// field name here — NOT the short metric — is the fix for the naming drift
// where `source:ja3n` failed to exclude `ja3n_hash` from gap_closed.

pub fn check_source(field: &str, ref_src: &str, obs_src: &str) -> Option<FieldDiff> {
    if ref_src.is_empty() || obs_src.is_empty() {
        return None; // metric not present on one side; value comparison handles it
    }
    if ref_src == obs_src {
        return None;
    }
    Some(FieldDiff {
        field: format!("source:{}", field),
        expected: format!("reference source={}", ref_src),
        observed: format!(
            "observed source={} — cross-service comparison is a tooling artefact, not a fingerprint defect",
            obs_src
        ),
    })
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
pub fn compare(o: &Observed, r: &Reference) -> (Vec<FieldDiff>, Vec<String>) {
    let mut diffs = Vec::new();
    let mut skipped = Vec::new();

    let skip_ua = r.note_excludes("user-agent");
    let skip_sec_ch_ua = r.note_excludes("sec-ch-ua");

    // --- JA3 (hash) ---
    if let Some(d) = check_source("ja3_hash", &r.sources.ja3, &o.sources.ja3) {
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
        if let Some(d) = check_source("ja3n_hash", &r.sources.ja3n, &o.sources.ja3n) {
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
        if let Some(d) = check_source("peetprint_hash", &r.sources.peetprint, &o.sources.peetprint)
        {
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

    // --- coherence invariant: sec-ch-ua major version == User-Agent major version ---
    //
    // This is the one check that would have caught the original bug (issue
    // #81): the service sent sec-ch-ua with v="136" (from a wreq-util
    // preset) while the User-Agent was "ox-browser/0.8.0" (a fallback). It
    // operates on the OBSERVED side alone — it does not need the reference,
    // so it works even for headless references that exclude UA/sec-ch-ua
    // from the per-field comparison.
    if !o.sec_ch_ua.is_empty() && !o.user_agent.is_empty() {
        let ua_major = extract_major_from_ua(&o.user_agent);
        let hint_major = extract_major_from_sec_ch_ua(&o.sec_ch_ua);
        if let (Some(ua_maj), Some(hint_maj)) = (ua_major, hint_major)
            && ua_maj != hint_maj
        {
            diffs.push(FieldDiff {
                field: "coherence:sec_ch_ua_vs_ua_major".into(),
                expected: format!("sec-ch-ua major == UA major == {ua_maj}"),
                observed: format!("sec-ch-ua major={hint_maj}, UA major={ua_maj} — INCOHERENT"),
            });
        }
    }

    (diffs, skipped)
}

/// Extract the major version number from a User-Agent string.
/// Returns None if no version is found.
fn extract_major_from_ua(ua: &str) -> Option<u32> {
    if let Some(pos) = ua.find("Chrome/") {
        return ua[pos + 7..].split('.').next()?.parse().ok();
    }
    if let Some(pos) = ua.find("Edg/") {
        return ua[pos + 4..].split('.').next()?.parse().ok();
    }
    if let Some(pos) = ua.find("rv:") {
        return ua[pos + 3..].split('.').next()?.parse().ok();
    }
    if let Some(pos) = ua.find("Version/") {
        return ua[pos + 8..].split('.').next()?.parse().ok();
    }
    None
}

/// Extract the Chromium major version from a sec-ch-ua header value.
/// Looks for `"Chromium";v="<major>"` or `"Google Chrome";v="<major>"`.
/// Returns None if no Chromium/Chrome brand is found.
fn extract_major_from_sec_ch_ua(sec_ch_ua: &str) -> Option<u32> {
    for brand in &["Chromium", "Google Chrome"] {
        let needle = format!(r#""{brand}";v=""#);
        if let Some(pos) = sec_ch_ua.find(&needle) {
            let rest = &sec_ch_ua[pos + needle.len()..];
            let ver = rest.split('"').next().unwrap_or("");
            // The version may be "148" or "148.0.0.0" — take the major.
            if let Some(major) = ver.split('.').next()
                && let Ok(m) = major.parse::<u32>()
            {
                return Some(m);
            }
        }
    }
    None
}

// ── Bucket-B comparability helpers ─────────────────────────────────────

/// Reference value for a bucket-B field. Exhaustive over [`FP_BUCKET_B`]:
/// the `_` arm PANICS naming the offending field — a desync between
/// `FP_BUCKET_B` (in `crates/http/src/tls.rs`) and this match cannot be
/// silent. Adding a field to `FP_BUCKET_B` without an arm here fails loudly,
/// never green. Do NOT "fix" this with a comment telling contributors to keep
/// the lists in sync; the panic IS the sync guard.
pub fn reference_value_for<'a>(field: &str, reference: &'a Reference) -> &'a str {
    match field {
        "ja3n_hash" => &reference.tls.ja3n_hash,
        "ja4" => &reference.tls.ja4,
        "peetprint_hash" => &reference.tls.peetprint_hash,
        _ => panic!(
            "reference_value_for: unknown bucket-B field {:?} — FP_BUCKET_B in \
             crates/http/src/tls.rs lists a field with no matching arm in \
             crates/http/src/fingerprint.rs. Add the arm; this \
             panic is the desync guard required by F2.",
            field
        ),
    }
}

/// Reference provenance source for a bucket-B field. Exhaustive over
/// [`FP_BUCKET_B`] with the same panic-on-desync contract as
/// [`reference_value_for`].
pub fn reference_source_for<'a>(field: &str, reference: &'a Reference) -> &'a str {
    match field {
        "ja3n_hash" => &reference.sources.ja3n,
        "ja4" => &reference.sources.ja4,
        "peetprint_hash" => &reference.sources.peetprint,
        _ => panic!(
            "reference_source_for: unknown bucket-B field {:?} — FP_BUCKET_B in \
             crates/http/src/tls.rs lists a field with no matching arm in \
             crates/http/src/fingerprint.rs. Add the arm; this \
             panic is the desync guard required by F2.",
            field
        ),
    }
}

/// F2b: every bucket-B field must have a non-empty reference value AND a
/// non-empty provenance source, so its self-expiry stays armed and its
/// cross-service consistency is falsifiable.
///
/// `bucket_b` is an explicit parameter (not the production `FP_BUCKET_B`)
/// so the `should_panic` provenance tests can pass a literal non-empty
/// bucket and keep the guard mechanism exercised even when `FP_BUCKET_B` is
/// empty. Production callers pass `FP_BUCKET_B` directly.
pub fn assert_bucket_b_provenance(r: &Reference, name: &str, bucket_b: &[&str]) {
    for field in bucket_b {
        let val = reference_value_for(field, r);
        assert!(
            !val.is_empty(),
            "{}: bucket-B field {} has an empty reference value — its self-expiry is \
             silently disabled. Re-capture the reference with the field populated.",
            name,
            field
        );
        let src = reference_source_for(field, r);
        assert!(
            !src.is_empty(),
            "{}: bucket-B field {} has an empty provenance source — check_source \
             silently downgrades to a raw value comparison of unknown provenance. \
             Re-capture the reference with the source recorded.",
            name,
            field
        );
    }
}

/// Fix C: `r.tls.ja3` must be non-empty. The oracle calls
/// `reference_exhibits_gap(&reference.tls.ja3)`, which returns `false` on
/// `""` by design — so a reference missing `ja3` silently makes
/// `comparable_b` empty → `gap_closed` can never fire → the self-expiry is
/// entirely vacuous, with a green run.
pub fn assert_ja3_provenance(r: &Reference, name: &str) {
    assert!(
        !r.tls.ja3.is_empty(),
        "{}: missing tls.ja3 — the oracle's gap-exhibited gate depends on it; \
         an empty ja3 silently disables all bucket-B self-expiry",
        name
    );
}

/// The shared comparable_bucket_b gate. Called by the live oracle, `doctor`,
/// AND the F3 version-scoping tests — the tests exercise the SAME function,
/// not a re-typed copy. Deleting the `gap_exhibited` gate here breaks
/// `f3_chrome131_reference_yields_no_comparable_b`.
///
/// `gap_exhibited` is pre-computed by the caller via
/// `reference_exhibits_gap(&reference.tls.ja3)` so the caller can emit the
/// top-level NOTE diagnostic once (not once per field).
pub fn comparable_bucket_b(reference: &Reference, gap_exhibited: bool) -> Vec<&'static str> {
    FP_BUCKET_B
        .iter()
        .copied()
        .filter(|f| {
            let val = reference_value_for(f, reference);
            if val.is_empty() {
                eprintln!(
                    "  NOTE bucket-B field {} self-expiry disabled — no reference \
                     value (field cannot match, so it cannot signal a closed gap)",
                    f
                );
                return false;
            }
            if !gap_exhibited {
                eprintln!(
                    "  NOTE bucket-B field {} self-expiry disabled — reference does \
                     not exhibit the trust_anchors gap (no 51764 in JA3)",
                    f
                );
                return false;
            }
            true
        })
        .collect()
}

/// The branch SELECTION itself — gap_exhibited → classify with
/// `comparable_b`; else → classify with an empty bucket B so a bucket-B
/// diff against a 16-extension reference is a hard failure, not the
/// tolerated gap. Extracted here so the live oracle, `doctor`, AND the
/// offline tests call the SAME function, not a re-typed copy. Deleting the
/// `else` branch breaks
/// `classify_for_reference_chrome131_bucket_b_diff_is_hard_failure`.
pub fn classify_for_reference(
    reference: &Reference,
    diffs: &[(String, String, String)],
) -> FingerprintVerdict {
    let gap_exhibited = reference_exhibits_gap(&reference.tls.ja3);
    if !gap_exhibited {
        eprintln!(
            "  NOTE reference does not exhibit the trust_anchors gap \
             (no extension 51764 in JA3) — bucket-B tolerance DISABLED; \
             bucket-B diffs are hard failures"
        );
    }
    let comparable_b = comparable_bucket_b(reference, gap_exhibited);
    if gap_exhibited {
        classify_fingerprint_diffs(diffs, &comparable_b)
    } else {
        classify_with(FP_BUCKET_A, &[], diffs, &[])
    }
}

// ── F1: failure message helper ─────────────────────────────────────────

/// F1: build the failure message naming BOTH the hard-failure count and the
/// closed-gap count — neither class may mask the other.
pub fn fingerprint_fail_message(verdict: &FingerprintVerdict, major: &str) -> String {
    format!(
        "fingerprint mismatch for Chrome {}: {} hard failure(s), {} closed gap(s). \
         See FIELD lines above for hard failures (profile is wrong) and GAP-CLOSED \
         lines for bucket-B fields that now match (remove them from FP_BUCKET_B).",
        major,
        verdict.hard_failures.len(),
        verdict.gap_closed.len(),
    )
}

// ── UA version extraction ──────────────────────────────────────────────

/// D1: delegate to the crate's own `extract_major_version_pub` rather than
/// re-implementing it. The local copy dropped the `Edg/` branch, so an Edge
/// profile without `Chrome/` in the UA would print `major="0"`. The public
/// function handles Chrome, Edge, Firefox, and Safari.
pub fn extract_major_version(ua: &str) -> String {
    crate::profile::extract_major_version_pub(ua)
        .map(|v| v.to_string())
        .unwrap_or_else(|| "0".to_string())
}

// ── Embedded references ────────────────────────────────────────────────
//
// The oracle used to load fixtures via `env!("CARGO_MANIFEST_DIR")` + a
// filesystem read — a path that does not exist in a shipped binary (issue
// #109). Embedding the references with `include_str!` means `doctor` (and
// any shipped binary) carries the ground truth at compile time. The pattern
// mirrors `crates/security/src/fingerprint.rs` (`include_str!` of a JSON
// asset beside the source).
//
// The test-side filesystem loader in `tests/common/mod.rs` stays as it is —
// the offline tests still read the files from disk so a contributor editing
// a fixture sees the change without a rebuild. Both loaders deserialize the
// SAME bytes (the files under `tests/fixtures/`).

const EMBEDDED_REFERENCE_CHROME_131: &str =
    include_str!("../tests/fixtures/reference_chrome_131.json");
const EMBEDDED_REFERENCE_CHROME_133: &str =
    include_str!("../tests/fixtures/reference_chrome_133.json");
const EMBEDDED_REFERENCE_CHROME_144: &str =
    include_str!("../tests/fixtures/reference_chrome_144.json");
const EMBEDDED_REFERENCE_CHROME_146: &str =
    include_str!("../tests/fixtures/reference_chrome_146.json");
const EMBEDDED_REFERENCE_CHROME_148: &str =
    include_str!("../tests/fixtures/reference_chrome_148.json");

/// `(major, embedded JSON)` for every committed Chrome reference, ordered by
/// major ascending. `doctor` iterates this to know which profiles to measure.
pub const EMBEDDED_REFERENCES: &[(&str, &str)] = &[
    ("131", EMBEDDED_REFERENCE_CHROME_131),
    ("133", EMBEDDED_REFERENCE_CHROME_133),
    ("144", EMBEDDED_REFERENCE_CHROME_144),
    ("146", EMBEDDED_REFERENCE_CHROME_146),
    ("148", EMBEDDED_REFERENCE_CHROME_148),
];

/// Load an embedded reference by Chrome major. Returns `None` if no reference
/// is embedded for that major. Panics if the embedded JSON is unparseable —
/// the bytes are a compile-time asset, so a parse failure is a corrupt
/// commit, not a runtime condition.
pub fn embedded_reference(major: &str) -> Option<Reference> {
    let raw = EMBEDDED_REFERENCES.iter().find(|(m, _)| *m == major)?.1;
    Some(serde_json::from_str(raw).expect("embedded reference is valid JSON"))
}

/// `(major, Reference)` for every embedded reference, ordered by major
/// ascending. `doctor` iterates this.
pub fn embedded_reference_pairs() -> Vec<(String, Reference)> {
    EMBEDDED_REFERENCES
        .iter()
        .map(|(m, raw)| {
            let r: Reference = serde_json::from_str(raw).expect("embedded reference is valid JSON");
            (m.to_string(), r)
        })
        .collect()
}
