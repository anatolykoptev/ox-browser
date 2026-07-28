//! Shared types and helpers for the fingerprint oracle test targets.
//!
//! Both `fingerprint_oracle_test.rs` (gated, live network) and
//! `fingerprint_offline_test.rs` (ungated, CI-default) include this module
//! via `mod common;`. Sharing — not copying — is the discipline: the
//! `check_source` naming fix (A), the `comparable_bucket_b` extraction (B),
//! and the `ja3` provenance guard (C) all live here so both targets exercise
//! the SAME code path, never a re-typed copy.

use ox_http::tls::{
    FP_BUCKET_A, FP_BUCKET_B, FingerprintVerdict, classify_fingerprint_diffs, classify_with,
    reference_exhibits_gap,
};
use serde::{Deserialize, Serialize};

// ── Echo service constants ─────────────────────────────────────────────

pub const SERVICE_PEET: &str = "peet";
pub const SERVICE_BROWSERLEAKS: &str = "browserleaks";

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
    /// Used by `compare` in the gated live test file. Marked `allow(dead_code)`
    /// because each test target compiles `common` independently — the offline
    /// target does not call `compare`, so without this the method appears
    /// unused when only the offline target is built.
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
/// Mirrors the comparable subset of Reference. Built by merging a peet
/// extraction and a browserleaks extraction. Lives in common so the offline
/// tests can call `compare` with a hand-built `Observed` to verify the
/// `source:` field naming (Fix A) without network access.
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

#[allow(dead_code)] // used by extract_peet in the gated live test target
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

// ── Reference loading ──────────────────────────────────────────────────

pub fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

pub fn reference_path(major: &str) -> std::path::PathBuf {
    fixture_dir().join(format!("reference_chrome_{}.json", major))
}

pub fn load_reference(major: &str) -> Reference {
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

// ── Source-consistency check (Fix A) ───────────────────────────────────
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
///
/// Fix A: `check_source` is called with the BUCKET FIELD NAME (e.g.
/// "ja3n_hash", not the short metric "ja3n"). The emitted diff is
/// `source:<field>`, which `classify_with` strips and compares against
/// FP_BUCKET_B names. Using the field name — NOT the short metric — is the
/// fix for the naming drift where `source:ja3n` failed to exclude
/// `ja3n_hash` from gap_closed.
#[allow(dead_code)] // used by the gated live test; offline tests call it for Fix A
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

    (diffs, skipped)
}

// ── Bucket-B comparability helpers (F2/F3, Fix B) ─────────────────────

/// Reference value for a bucket-B field. Exhaustive over [`FP_BUCKET_B`]:
/// the `_` arm PANICS naming the offending field — a desync between
/// `FP_BUCKET_B` (in `crates/http/src/tls.rs`) and this match cannot be
/// silent (F2). Adding a field to `FP_BUCKET_B` without an arm here fails
/// loudly, never green. Do NOT "fix" this with a comment telling
/// contributors to keep the lists in sync; the panic IS the sync guard.
pub fn reference_value_for<'a>(field: &str, reference: &'a Reference) -> &'a str {
    match field {
        "ja3n_hash" => &reference.tls.ja3n_hash,
        "ja4" => &reference.tls.ja4,
        "peetprint_hash" => &reference.tls.peetprint_hash,
        _ => panic!(
            "reference_value_for: unknown bucket-B field {:?} — FP_BUCKET_B in \
             crates/http/src/tls.rs lists a field with no matching arm in \
             crates/http/tests/common/mod.rs. Add the arm; this \
             panic is the desync guard required by F2.",
            field
        ),
    }
}

/// F2b: every bucket-B field must have a non-empty reference value, so its
/// self-expiry stays armed. A reference capture that drops a bucket-B field
/// silently disables that field's expiry while the run stays green.
#[allow(dead_code)] // only called from the offline test target
pub fn assert_bucket_b_provenance(r: &Reference, name: &str) {
    for field in FP_BUCKET_B {
        let val = reference_value_for(field, r);
        assert!(
            !val.is_empty(),
            "{}: bucket-B field {} has an empty reference value — its self-expiry is \
             silently disabled. Re-capture the reference with the field populated.",
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
#[allow(dead_code)] // only called from the offline test target
pub fn assert_ja3_provenance(r: &Reference, name: &str) {
    assert!(
        !r.tls.ja3.is_empty(),
        "{}: missing tls.ja3 — the oracle's gap-exhibited gate depends on it; \
         an empty ja3 silently disables all bucket-B self-expiry",
        name
    );
}

/// Fix B: the shared comparable_bucket_b gate. Called by the live oracle
/// AND by the F3 version-scoping tests — the tests exercise the SAME
/// function, not a re-typed copy. Deleting the `gap_exhibited` gate here
/// breaks `f3_chrome131_reference_yields_no_comparable_b`.
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

/// Fix B: the branch SELECTION itself — gap_exhibited → classify with
/// `comparable_b`; else → classify with an empty bucket B so a bucket-B
/// diff against a 16-extension reference is a hard failure, not the
/// tolerated gap. Extracted here so the live oracle AND the offline tests
/// call the SAME function, not a re-typed copy. Deleting the `else` branch
/// breaks `classify_for_reference_chrome131_bucket_b_diff_is_hard_failure`.
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

/// F1: build the failure panic message naming BOTH the hard-failure count
/// and the closed-gap count — neither class may mask the other. When both
/// lists are non-empty, both counts appear so the operator sees the full
/// picture (the old `else if` chain let the gap_closed arm swallow the
/// hard_failures arm, printing a "gap CLOSED" instruction for a defect the
/// report never showed).
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
    ox_http::profile::extract_major_version_pub(ua)
        .map(|v| v.to_string())
        .unwrap_or_else(|| "0".to_string())
}
