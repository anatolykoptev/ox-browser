//! Guard test: every `*::Client::builder()` construction site in the
//! workspace must be either the shared transport+identity constructor
//! (`wreq_transport_core` in `crates/http/src/client.rs`, exposed as
//! `ox_http::build_profiled_wreq_client`) or on the allowlist below.
//!
//! Issue #101: a second bare `wreq::Client::builder()` in the media path
//! survived a full identity refactor because nothing flagged it. This test
//! enumerates every construction site and fails `make preflight` RED when a
//! new one appears without an explicit identity decision — naming the file
//! and what to do.
//!
//! ## The allowlist is the design
//!
//! These sites target our OWN services (CF solvers, the chrome-render
//! endpoint, the go-twitter/hully tweet API, the Webshare provider API) or
//! are test/example fixtures. A browser identity there would be WRONG, not
//! missing — they are not browser-facing fetches. A new site that is neither
//! on this allowlist nor routed through `ox_http::build_profiled_wreq_client`
//! must trip this test.
//!
//! ## Adding a site
//!
//! If the new site faces an EXTERNAL host, route it through
//! `ox_http::build_profiled_wreq_client` (do NOT add it here — duplication is
//! the bug class this guard exists to prevent). If it targets our own
//! infrastructure, add it here with a one-line justification and bump the
//! expected count.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// `(path_suffix, expected_count, justification)` — every `Client::builder`
/// site in the workspace that is NOT the shared constructor.
///
/// `path_suffix` is the path relative to the workspace root.
const ALLOWLIST: &[(&str, usize, &str)] = &[
    // The shared transport+identity constructor itself — the ONE site
    // `build_wreq_client` / `build_direct_wreq_client` / the media seam all
    // delegate to. This is the "routed through the shared constructor" site.
    (
        "crates/http/src/client.rs",
        1,
        "shared wreq_transport_core — the ONE transport+identity construction site",
    ),
    // Internal-facing: our own services / provider APIs. A browser identity
    // here would be wrong, not missing.
    (
        "crates/http/src/proxy_webshare.rs",
        1,
        "Webshare provider API (internal-facing)",
    ),
    (
        "crates/http/src/read_pipeline.rs",
        1,
        "chrome-render endpoint client (internal service)",
    ),
    (
        "crates/http/src/solver_byparr.rs",
        1,
        "Byparr CF solver client (internal service)",
    ),
    (
        "crates/http/src/solver_gobrowser.rs",
        1,
        "go-browser solver client (internal service)",
    ),
    (
        "crates/js/src/gobrowser_proxy.rs",
        1,
        "go-browser proxy client (internal service)",
    ),
    (
        "crates/twitter/src/client.rs",
        2,
        "hully tweet API client (internal service) + test fixture mock server (127.0.0.1)",
    ),
    (
        "crates/twitter/src/social.rs",
        1,
        "go-twitter social API client (internal service)",
    ),
    // Test / example fixtures — not shipped, target local/dead hosts.
    (
        "crates/http/src/proxy_fallback.rs",
        1,
        "cfg(test) dead-proxy error generator (targets 127.0.0.1)",
    ),
    (
        "crates/http/examples/ssrf_sample_check.rs",
        1,
        "example, not shipped",
    ),
    ("crates/http/tests/ssrf_redirect_test.rs", 1, "test fixture"),
    (
        "crates/media/tests/media_identity.rs",
        1,
        "test fixture — bare-client contrast for the #101 identity falsification",
    ),
    (
        "crates/http/src/body_cap.rs",
        5,
        "test fixtures — raw TCP server clients for body-cap tests (target 127.0.0.1)",
    ),
    (
        "crates/media/src/innertube.rs",
        1,
        "test fixture — mock server for innertube body-cap test (target 127.0.0.1)",
    ),
];

/// Lines matching this substring (case-sensitive) count as a construction
/// site. Matches `wreq::Client::builder`, `reqwest::Client::builder`, and
/// `Client::builder` (after `use wreq::Client`).
const BUILDER_PATTERN: &str = "Client::builder";

fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    // crates/http -> workspace root is two levels up.
    manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("CARGO_MANIFEST_DIR is crates/http; workspace root is two levels up")
        .to_path_buf()
}

/// Recursively collect `.rs` files under `dir`, skipping `target/`.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            // Skip build artifacts and VCS dirs.
            if name == "target" || name == ".git" {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Count non-comment lines in `content` containing `BUILDER_PATTERN`.
fn count_builder_sites(content: &str) -> usize {
    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            // Skip line comments (// ...) — a pattern in a comment is not a
            // construction site. (Block comments are not handled; none of the
            // allowlisted files have `Client::builder` inside one.)
            !trimmed.starts_with("//")
        })
        .filter(|line| line.contains(BUILDER_PATTERN))
        .count()
}

#[test]
fn every_client_builder_site_is_allowlisted_or_shared() {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);

    // Build the actual map: path_suffix -> count.
    // Skip this guard test's own file — it mentions `Client::builder` in its
    // constant and message strings, which are not construction sites.
    let self_path = "crates/http/tests/client_builder_allowlist.rs";
    let mut actual: BTreeMap<String, usize> = BTreeMap::new();
    for file in &files {
        let suffix = file
            .strip_prefix(&root)
            .expect("file is under workspace root")
            .to_string_lossy()
            .replace('\\', "/");
        if suffix == self_path {
            continue;
        }
        let Ok(content) = fs::read_to_string(file) else {
            continue;
        };
        let count = count_builder_sites(&content);
        if count == 0 {
            continue;
        }
        actual.insert(suffix, count);
    }

    // Build the allowlist map.
    let mut expected: BTreeMap<&str, usize> = BTreeMap::new();
    for &(path, count, _just) in ALLOWLIST {
        expected.insert(path, count);
    }

    // Files with builders that are NOT in the allowlist at all.
    let unlisted: Vec<&String> = actual
        .keys()
        .filter(|k| !expected.contains_key(k.as_str()))
        .collect();
    // Files whose count differs from the allowlist.
    let wrong_count: Vec<(&str, usize, usize)> = expected
        .iter()
        .filter_map(|(&path, &exp)| actual.get(path).map(|&act| (path, exp, act)))
        .filter(|&(_, exp, act)| exp != act)
        .collect();
    // Allowlisted files that no longer have any builder (stale allowlist).
    let stale: Vec<&&str> = expected
        .keys()
        .filter(|p| !actual.contains_key(**p))
        .collect();

    if unlisted.is_empty() && wrong_count.is_empty() && stale.is_empty() {
        return;
    }

    let mut msg = String::from(
        "client_builder_allowlist: unauthorized `Client::builder()` site(s) found.\n\
         This guard (issue #101) fails when a wreq/reqwest client is constructed\n\
         outside the shared `ox_http::build_profiled_wreq_client` seam without an\n\
         explicit identity decision.\n\n",
    );

    if !unlisted.is_empty() {
        msg.push_str("NEW site(s) not on the allowlist:\n");
        for path in unlisted {
            msg.push_str(&format!(
                "  {path}\n\
                 \tIf this client faces an EXTERNAL host, route it through\n\
                 \t`ox_http::build_profiled_wreq_client` (do NOT copy the\n\
                 \tconstruction logic — duplication is the bug class this guard\n\
                 \tprevents). If it targets our own infrastructure, add it to\n\
                 \tthe ALLOWLIST in crates/http/tests/client_builder_allowlist.rs\n\
                 \twith a one-line justification.\n"
            ));
        }
    }
    if !wrong_count.is_empty() {
        msg.push_str("\nAllowlist count mismatch (expected vs actual):\n");
        for (path, exp, act) in wrong_count {
            msg.push_str(&format!(
                "  {path}: expected {exp}, found {act}\n\
                 \tA new `Client::builder()` appeared in an allowlisted file.\n\
                 \tEither route the new site through the shared constructor or\n\
                 \tbump the expected count in the ALLOWLIST with a justification.\n"
            ));
        }
    }
    if !stale.is_empty() {
        msg.push_str("\nStale allowlist entry (no builder found — remove it):\n");
        for path in stale {
            msg.push_str(&format!("  {path}\n"));
        }
    }

    panic!("{msg}");
}

/// Sanity: the shared constructor site itself is present and counted. This
/// guards against the allowlist silently passing if the constructor is
/// accidentally removed or renamed.
#[test]
fn shared_constructor_site_exists() {
    let root = workspace_root();
    let path = root.join("crates/http/src/client.rs");
    let content = fs::read_to_string(&path).expect("client.rs exists");
    let count = count_builder_sites(&content);
    assert_eq!(
        count, 1,
        "crates/http/src/client.rs must contain exactly one `Client::builder()` site \
         (the shared wreq_transport_core). Found {count}. If you split the constructor, \
         update the ALLOWLIST in client_builder_allowlist.rs."
    );
}
