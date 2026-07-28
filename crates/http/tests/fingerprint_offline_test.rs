//! Fingerprint oracle — OFFLINE tests (no network).
//!
//! These tests read local JSON fixtures or build a `FingerprintVerdict` by
//! hand. They run in `make preflight` (default features, no `--features
//! fingerprint`) so the oracle's classification, comparability, provenance,
//! and reporting guards are CI-gated, not just human-gated.
//!
//! The live network oracle stays in `fingerprint_oracle_test.rs` behind
//! `#[cfg(feature = "fingerprint")]`.

mod common;

use common::*;
use ox_http::tls::{
    FP_BUCKET_A, FP_BUCKET_B, FingerprintVerdict, classify_with, reference_exhibits_gap,
};
use ox_http::{BUILTIN_PROFILES, profile_to_emulation};

// ── Provenance ─────────────────────────────────────────────────────────

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

        // Fix C: ja3 must be non-empty — the oracle's gap-exhibited gate
        // depends on it. An empty ja3 silently disables ALL bucket-B
        // self-expiry while the run stays green.
        assert_ja3_provenance(&r, &name);

        // F2b: every bucket-B field must have a non-empty reference value.
        assert_bucket_b_provenance(&r, &name);
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

// ── F1: failure message naming both counts ────────────────────────────
//
// When BOTH hard_failures and gap_closed are non-empty, the failure message
// must name BOTH counts — neither class may mask the other. The message
// helper encodes the "name both counts" contract; the reporting block in
// the live oracle calls it for the single panic.

#[test]
fn f1_fail_message_names_both_counts_when_both_nonempty() {
    let v = FingerprintVerdict {
        hard_failures: vec![("http2_akamai".to_string(), "x".to_string(), "y".to_string())],
        gap_closed: vec!["ja4".to_string()],
        ..Default::default()
    };
    let msg = fingerprint_fail_message(&v, "148");
    assert!(
        msg.contains("1 hard failure(s)"),
        "message must name the hard-failure count: {msg}"
    );
    assert!(
        msg.contains("1 closed gap(s)"),
        "message must name the closed-gap count: {msg}"
    );
}

#[test]
fn f1_fail_message_names_hard_only() {
    let v = FingerprintVerdict {
        hard_failures: vec![("http2_akamai".to_string(), "x".to_string(), "y".to_string())],
        ..Default::default()
    };
    let msg = fingerprint_fail_message(&v, "148");
    assert!(msg.contains("1 hard failure(s)"), "{msg}");
    assert!(msg.contains("0 closed gap(s)"), "{msg}");
}

#[test]
fn f1_fail_message_names_gap_only() {
    let v = FingerprintVerdict {
        gap_closed: vec!["ja4".to_string()],
        ..Default::default()
    };
    let msg = fingerprint_fail_message(&v, "148");
    assert!(msg.contains("0 hard failure(s)"), "{msg}");
    assert!(msg.contains("1 closed gap(s)"), "{msg}");
}

// ── F2: desync + provenance guards ─────────────────────────────────────

// F2a: an unknown bucket-B field must PANIC, not silently return a default.
// This is the desync guard — adding a field to FP_BUCKET_B without an arm in
// reference_value_for fails loudly, never green.
#[test]
#[should_panic(expected = "reference_value_for: unknown bucket-B field")]
fn f2a_unknown_bucket_b_field_panics() {
    let r = load_reference("148");
    reference_value_for("bogus_field", &r);
}

// F2b: a reference with an empty bucket-B field must FAIL provenance, so a
// future capture that drops a field cannot silently disable its expiry.
#[test]
#[should_panic(expected = "bucket-B field ja3n_hash has an empty reference value")]
fn f2b_empty_bucket_b_field_fails_provenance() {
    let mut r = load_reference("148");
    r.tls.ja3n_hash.clear();
    assert_bucket_b_provenance(&r, "reference_chrome_148.json");
}

// F2b (positive): every committed reference passes the bucket-B provenance
// guard — all bucket-B fields are populated.
#[test]
fn f2b_all_references_pass_bucket_b_provenance() {
    let dir = fixture_dir();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read fixtures dir {}: {e}", dir.display()));
    let mut count = 0;
    for entry in entries {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("reference_chrome_") || !name.ends_with(".json") {
            continue;
        }
        count += 1;
        let r: Reference = serde_json::from_str(
            &std::fs::read_to_string(entry.path())
                .unwrap_or_else(|e| panic!("read {}: {e}", entry.path().display())),
        )
        .unwrap_or_else(|e| panic!("parse {}: {e}", entry.path().display()));
        assert_bucket_b_provenance(&r, &name);
    }
    assert!(count > 0, "no reference fixtures found");
}

// Fix C falsification: a reference with an empty ja3 must FAIL the ja3
// provenance guard. Mutation: remove the assert! from assert_ja3_provenance
// and this test fails (no panic → should_panic test fails).
#[test]
#[should_panic(expected = "missing tls.ja3")]
fn f2c_empty_ja3_fails_provenance() {
    let mut r = load_reference("148");
    r.tls.ja3.clear();
    assert_ja3_provenance(&r, "reference_chrome_148.json");
}

// ── F3: version-scoping gate (Fix B — calls the shared function) ───────

// F3: the version-scoping gate is wired into the oracle's comparable_b
// construction. A reference that does NOT exhibit the gap (no 51764 in JA3)
// must yield an empty comparable_b, so no bucket-B field can be reported as
// gap_closed. Uses a real Chrome 131 fixture (16 extensions, no 51764).
//
// Fix B: this test calls `comparable_bucket_b` — the SAME function the live
// oracle uses — not a re-typed copy of the filter. Deleting the
// gap_exhibited gate from `comparable_bucket_b` breaks this test.
#[test]
fn f3_chrome131_reference_yields_no_comparable_b() {
    let reference = load_reference("131");
    assert!(
        !reference_exhibits_gap(&reference.tls.ja3),
        "Chrome 131 JA3 must NOT contain 51764"
    );
    let gap_exhibited = reference_exhibits_gap(&reference.tls.ja3);
    let comparable_b = comparable_bucket_b(&reference, gap_exhibited);
    assert!(
        comparable_b.is_empty(),
        "Chrome 131 (no 51764) must yield NO comparable bucket-B fields, got: {:?}",
        comparable_b
    );
}

// F3: a reference that DOES exhibit the gap (51764 in JA3) yields all
// populated bucket-B fields as comparable. Uses a real Chrome 148 fixture.
#[test]
fn f3_chrome148_reference_yields_all_comparable_b() {
    let reference = load_reference("148");
    assert!(
        reference_exhibits_gap(&reference.tls.ja3),
        "Chrome 148 JA3 must contain 51764"
    );
    let gap_exhibited = reference_exhibits_gap(&reference.tls.ja3);
    let comparable_b = comparable_bucket_b(&reference, gap_exhibited);
    assert_eq!(
        comparable_b.len(),
        FP_BUCKET_B.len(),
        "Chrome 148 (has 51764, all fields populated) must yield ALL bucket-B fields comparable"
    );
}

// ── Fix A: parameterized source-prefix exclusion ───────────────────────
//
// For EVERY field in FP_BUCKET_B, a `source:<field>` diff (emitted by
// `check_source` when reference and observed disagree on the source service)
// must exclude that field from gap_closed. The previous single-field test
// used `source:ja4` — the one field where the short metric name and the
// bucket field name coincide — so a naming drift on ja3n_hash or
// peetprint_hash was invisible.
//
// This test goes through `check_source` (the real emitter) and feeds the
// resulting diff to `classify_with`, exercising the full path. Mutation:
// revert `check_source` to emit `source:ja3n` (short metric) for the ja3n
// call site and this test FAILS for the ja3n_hash iteration.
#[test]
fn source_prefix_diff_excludes_every_bucket_b_field() {
    for field in FP_BUCKET_B {
        // check_source emits `source:<field>` — the bucket field name.
        // For the exclusion to work, this must match the FP_BUCKET_B entry.
        let diff = check_source(field, SERVICE_BROWSERLEAKS, SERVICE_PEET);
        assert!(
            diff.is_some(),
            "check_source must emit a diff for field {} when sources disagree",
            field
        );
        let fd = diff.unwrap();
        assert_eq!(
            fd.field,
            format!("source:{}", field),
            "check_source must emit source:<field> using the bucket field name, not a short metric"
        );
        let tuple = (fd.field.clone(), fd.expected.clone(), fd.observed.clone());
        let v = classify_with(FP_BUCKET_A, FP_BUCKET_B, &[tuple], &[*field]);
        assert!(
            v.gap_closed.is_empty(),
            "source:{} diff must exclude {} from gap_closed, but got: {:?}",
            field,
            field,
            v.gap_closed
        );
    }
}

// ── Fix E: bucket-B diff is a hard failure when gap not exhibited ──────
//
// When the reference does not exhibit the trust_anchors gap (no 51764 in
// JA3), a bucket-B diff is a real mismatch — it cannot be explained by the
// missing extension. The call site passes an empty bucket B to
// `classify_with` so the diff is NOT suppressed into tolerated_b.
#[test]
fn bucket_b_diff_is_hard_failure_when_gap_not_exhibited() {
    let v = classify_with(
        FP_BUCKET_A,
        &[],
        &[(
            "ja4".to_string(),
            "t13d1517h2".to_string(),
            "t13d1516h2".to_string(),
        )],
        &[],
    );
    assert!(
        !v.is_ok(),
        "bucket-B diff must be a hard failure when gap not exhibited"
    );
    assert_eq!(v.hard_failures.len(), 1);
    assert_eq!(v.hard_failures[0].0, "ja4");
    assert!(
        v.tolerated_b.is_empty(),
        "bucket-B diff must NOT be tolerated when gap not exhibited"
    );
}

// ── Fix A: compare emits source:<bucket_field> for every bucket-B metric ─
//
// Integration test: `compare` (the production code path) must pass the BUCKET
// FIELD NAME to `check_source`, not the short metric name. A cross-service
// disagreement on ja3n must emit `source:ja3n_hash` (not `source:ja3n`), so
// `classify_with` can strip the prefix and match it against FP_BUCKET_B.
//
// Mutation: revert `check_source("ja3n_hash", ...)` to `check_source("ja3n",
// ...)` in `compare` and this test FAILS — the emitted field will be
// `source:ja3n`, not `source:ja3n_hash`.
#[test]
fn compare_emits_source_diff_with_bucket_field_name() {
    // Build a reference with ja3n sourced from browserleaks and a non-empty
    // ja3n_hash (so the ja3n branch is entered).
    let mut reference = load_reference("148");
    reference.sources.ja3n = SERVICE_BROWSERLEAKS.to_string();
    reference.tls.ja3n_hash = "abc123".to_string();

    // Build an observed with ja3n sourced from peet — a cross-service
    // disagreement.
    let mut observed = Observed::default();
    observed.sources.ja3n = SERVICE_PEET.to_string();
    observed.tls.ja3n_hash = "abc123".to_string(); // same value, but sources differ

    let (diffs, _skipped) = compare(&observed, &reference);

    // Find the source: diff for ja3n_hash.
    let source_diff = diffs.iter().find(|d| d.field.starts_with("source:ja3n"));
    assert!(
        source_diff.is_some(),
        "compare must emit a source: diff for ja3n when sources disagree, got diffs: {:?}",
        diffs.iter().map(|d| &d.field).collect::<Vec<_>>()
    );
    assert_eq!(
        source_diff.unwrap().field,
        "source:ja3n_hash",
        "compare must emit source:ja3n_hash (bucket field name), not source:ja3n (short metric)"
    );

    // Verify the same for peetprint_hash.
    reference.sources.peetprint = SERVICE_PEET.to_string();
    reference.tls.peetprint_hash = "def456".to_string();
    observed.sources.peetprint = SERVICE_BROWSERLEAKS.to_string();
    observed.tls.peetprint_hash = "def456".to_string();

    let (diffs2, _) = compare(&observed, &reference);
    let pp_diff = diffs2
        .iter()
        .find(|d| d.field.starts_with("source:peetprint"));
    assert!(
        pp_diff.is_some(),
        "compare must emit a source: diff for peetprint when sources disagree"
    );
    assert_eq!(
        pp_diff.unwrap().field,
        "source:peetprint_hash",
        "compare must emit source:peetprint_hash (bucket field name), not source:peetprint"
    );
}
