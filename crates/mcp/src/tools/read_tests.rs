use ox_http::content::{ReadOutput, ReadParams};
use ox_http::deadline::resolve_timeout;
use std::time::Duration;

use super::ReadInput;

#[test]
fn read_params_defaults() {
    let json = r#"{"url": "https://example.com"}"#;
    let p: ReadParams = serde_json::from_str(json).unwrap();
    assert_eq!(p.format, "text");
    assert_eq!(p.max_length, 0);
}

#[test]
fn read_output_skips_none_error() {
    let out = ReadOutput {
        title: "T".into(),
        content: "C".into(),
        author: String::new(),
        excerpt: String::new(),
        url: "https://x.com".into(),
        format: "text".into(),
        length: 1,
        method: "direct".into(),
        elapsed_ms: 50,
        json_ld: Vec::new(),
        og_image: String::new(),
        published_at: String::new(),
        modified_at: String::new(),
        section: String::new(),
        site_name: String::new(),
        tags: Vec::new(),
        language: String::new(),
        error: None,
        extraction_note: None,
    };
    let json = serde_json::to_value(&out).unwrap();
    assert!(!json.as_object().unwrap().contains_key("error"));
    assert!(!json.as_object().unwrap().contains_key("json_ld"));
}

#[test]
fn read_output_includes_error() {
    let out = ReadOutput {
        title: String::new(),
        content: String::new(),
        author: String::new(),
        excerpt: String::new(),
        url: "https://fail.com".into(),
        format: "text".into(),
        length: 0,
        method: "direct".into(),
        elapsed_ms: 10,
        json_ld: Vec::new(),
        og_image: String::new(),
        published_at: String::new(),
        modified_at: String::new(),
        section: String::new(),
        site_name: String::new(),
        tags: Vec::new(),
        language: String::new(),
        error: Some("fail".into()),
        extraction_note: None,
    };
    let json = serde_json::to_value(&out).unwrap();
    assert_eq!(json["error"], "fail");
}

// ── WIRE-NAME PARITY (issue #139 follow-up) ───────────────────────────────────
//
// The MCP `read` tool's `ReadInput` shares the unified `timeout` field name
// with `/fetch`, `/read`, and the CLI `--timeout` flag, and accepts the
// legacy `timeout_secs` spelling via a serde alias. These assert the RESOLVED
// deadline after the `From<ReadInput> for ReadParams` mapping — not merely
// that deserialization succeeded (an unknown field deserializes fine and is
// dropped, so an Ok(_) assertion would pass on the pre-rename code).

/// MCP `read` accepts the canonical `{"timeout": 5}` and maps it through to
/// a 5 s resolved deadline. RED on the pre-rename code: `timeout` is an
/// unknown field on `ReadInput` (whose field was `timeout_secs`) → dropped
/// → `resolve_timeout(None)` = 8 s ≠ 5 s.
#[test]
fn read_input_timeout_canonical_name_resolves() {
    let input: ReadInput = serde_json::from_str(r#"{"url":"https://x.com","timeout":5}"#).unwrap();
    let params: ReadParams = input.into();
    assert_eq!(
        resolve_timeout(params.timeout),
        Duration::from_secs(5),
        "canonical `timeout` must resolve to 5s, not the 8s default"
    );
}

/// MCP `read` still accepts the legacy `{"timeout_secs": 5}` via the alias
/// and maps it to a 5 s resolved deadline. Regression guard for the alias.
#[test]
fn read_input_timeout_secs_alias_resolves() {
    let input: ReadInput =
        serde_json::from_str(r#"{"url":"https://x.com","timeout_secs":5}"#).unwrap();
    let params: ReadParams = input.into();
    assert_eq!(
        resolve_timeout(params.timeout),
        Duration::from_secs(5),
        "alias `timeout_secs` must resolve to 5s"
    );
}
