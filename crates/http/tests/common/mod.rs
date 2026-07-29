//! Shared types and helpers for the fingerprint oracle test targets.
//!
//! The oracle's comparison + classification logic now lives in
//! `crates/http/src/fingerprint.rs` (a non-test module) so that the
//! `ox-browser doctor` subcommand can reuse it without copying (issue #109).
//! This file re-exports that module and keeps ONLY the test-side filesystem
//! loader (`fixture_dir` / `reference_path` / `load_reference`), which reads
//! fixtures via `env!("CARGO_MANIFEST_DIR")` and panics on a missing file —
//! correct for a test, wrong for a shipped binary. `doctor` loads the
//! references from the embedded bytes in `fingerprint::embedded_reference`.
//!
//! Both `fingerprint_oracle_test.rs` (gated, live network) and
//! `fingerprint_offline_test.rs` (ungated, CI-default) include this module
//! via `mod common;`. Sharing — not copying — is the discipline.

// Re-export the shared oracle surface so existing `use common::*;` imports
// in both test files keep working unchanged.
pub use ox_http::fingerprint::*;

// ── Test-side filesystem loader (NOT shipped) ──────────────────────────

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
