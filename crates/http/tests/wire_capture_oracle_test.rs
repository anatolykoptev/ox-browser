//! Header-layer oracle against branded Google Chrome captures (offline).
//!
//! The `reference_chrome_*.json` references are Chrome for Testing in
//! headless mode, so their `user-agent` and `sec-ch-ua` are excluded from the
//! live comparison (the headless build advertises a different brand list). The
//! captures under `tests/fixtures/wire/` are branded, headed Google Chrome:
//! every request header they record is what a real browser sent, so the
//! headers `browser_headers` builds for the same User-Agent must equal them
//! name for name, value for value and in the same order.
//!
//! No network: the captures are read from disk. TLS and HTTP/2 are not
//! covered here; those need the live oracle (`fingerprint_oracle_test.rs`).

use std::path::PathBuf;

use ox_http::{BrowserProfile, browser_headers};

fn wire_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("wire")
}

fn load(name: &str) -> serde_json::Value {
    let path = wire_dir().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {} (an error, not a skip): {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Every capture must say what it is: a capture without provenance cannot be
/// checked or refreshed later.
fn assert_provenance(name: &str, v: &serde_json::Value) {
    let p = &v["provenance"];
    for key in [
        "browser",
        "version",
        "build",
        "platform",
        "mode",
        "captured_at",
        "endpoint",
    ] {
        assert!(
            p[key].as_str().is_some_and(|s| !s.is_empty()),
            "{name}: provenance.{key} missing"
        );
    }
    assert!(
        p["headless"].is_boolean(),
        "{name}: provenance.headless missing"
    );
}

/// A profile whose User-Agent is the one the capture recorded.
fn profile_for(ua: &str) -> BrowserProfile {
    BrowserProfile {
        user_agent: Box::leak(ua.to_owned().into_boxed_str()),
        browser: "chrome",
        os: "macos",
        mobile: false,
        accept_language: "en-US,en;q=0.9",
    }
}

fn captured_headers(v: &serde_json::Value) -> Vec<(String, String)> {
    let names = v["http2"]["request_header_names"]
        .as_array()
        .expect("request_header_names");
    let values = v["http2"]["request_headers"]
        .as_object()
        .expect("request_headers");
    names
        .iter()
        .map(|n| {
            let n = n.as_str().expect("header name");
            let val = values
                .get(n)
                .and_then(|x| x.as_str())
                .unwrap_or_else(|| panic!("no value recorded for {n}"));
            (n.to_owned(), val.to_owned())
        })
        .collect()
}

#[test]
fn branded_chrome_156_navigation_headers_match_the_capture() {
    let capture = load("google_chrome_156_nav.json");
    assert_provenance("google_chrome_156_nav.json", &capture);
    assert_eq!(capture["provenance"]["headless"], false);
    assert_eq!(capture["provenance"]["build"], "stable, branded");

    let want = captured_headers(&capture);
    let ua = &want
        .iter()
        .find(|(n, _)| n == "user-agent")
        .expect("capture has a user-agent")
        .1;

    let got = browser_headers(&profile_for(ua));

    // Names and order first, so an order regression reads as an order
    // regression and not as a pile of value mismatches.
    let want_names: Vec<&str> = want.iter().map(|(n, _)| n.as_str()).collect();
    let got_names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        got_names, want_names,
        "header order differs from branded Chrome 156"
    );
    assert_eq!(got, want, "header values differ from branded Chrome 156");
}

#[test]
fn branded_chrome_156_sec_ch_ua_is_the_captured_string() {
    // Spelled out so the oracle for this one header does not depend on the
    // capture being parsed the same way by the test and the builder.
    let capture = load("google_chrome_156_nav.json");
    assert_eq!(
        capture["http2"]["request_headers"]["sec-ch-ua"],
        r#""Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156""#
    );
}

#[test]
fn fetch_capture_is_the_same_browser_identity() {
    // The fetch-mode capture is information only (its header set is the
    // page's own fetch(), not a navigation), but it must describe the same
    // browser as the navigation capture.
    let nav = load("google_chrome_156_nav.json");
    let fetch = load("google_chrome_156_fetch.json");
    assert_provenance("google_chrome_156_fetch.json", &fetch);
    assert_eq!(nav["provenance"]["version"], fetch["provenance"]["version"]);
    for h in [
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "user-agent",
    ] {
        assert_eq!(
            nav["http2"]["request_headers"][h], fetch["http2"]["request_headers"][h],
            "{h}"
        );
    }
}
