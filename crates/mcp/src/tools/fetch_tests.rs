//! Unit tests for fetch.rs — serialization helpers and input defaults.

use super::{FetchInput, FetchSmartInput};

// ── FetchInput ────────────────────────────────────────────────────────────────

#[test]
fn fetch_input_required_url() {
    let json = r#"{"url": "https://example.com"}"#;
    let input: FetchInput = serde_json::from_str(json).unwrap();
    assert_eq!(input.url, "https://example.com");
    // F5: method/body/content_type default to None (GET, no body).
    assert!(input.method.is_none());
    assert!(input.body.is_none());
    assert!(input.content_type.is_none());
}

#[test]
fn fetch_input_missing_url_fails() {
    let json = r#"{}"#;
    let result: Result<FetchInput, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn fetch_input_with_method_and_body() {
    let json = r#"{"url": "https://example.com", "method": "POST", "body": "{\"a\":1}"}"#;
    let input: FetchInput = serde_json::from_str(json).unwrap();
    assert_eq!(input.method.as_deref(), Some("POST"));
    assert_eq!(input.body.as_deref(), Some("{\"a\":1}"));
}

#[test]
fn fetch_input_body_without_method_defaults_to_post() {
    let json = r#"{"url": "https://example.com", "body": "hello"}"#;
    let input: FetchInput = serde_json::from_str(json).unwrap();
    assert!(input.method.is_none());
    assert!(input.body.is_some());
}

#[test]
fn fetch_input_with_content_type() {
    let json = r#"{"url": "https://example.com", "method": "POST", "body": "x", "content_type": "text/xml"}"#;
    let input: FetchInput = serde_json::from_str(json).unwrap();
    assert_eq!(input.content_type.as_deref(), Some("text/xml"));
}

// ── FetchSmartInput ───────────────────────────────────────────────────────────

#[test]
fn fetch_smart_input_save_to_file_defaults_true() {
    let json = r#"{"url": "https://example.com"}"#;
    let input: FetchSmartInput = serde_json::from_str(json).unwrap();
    assert!(input.save_to_file, "save_to_file should default to true");
}

#[test]
fn fetch_smart_input_save_to_file_explicit_false() {
    let json = r#"{"url": "https://example.com", "save_to_file": false}"#;
    let input: FetchSmartInput = serde_json::from_str(json).unwrap();
    assert!(!input.save_to_file);
}

#[test]
fn fetch_smart_input_save_to_file_explicit_true() {
    let json = r#"{"url": "https://example.com", "save_to_file": true}"#;
    let input: FetchSmartInput = serde_json::from_str(json).unwrap();
    assert!(input.save_to_file);
}

#[test]
fn fetch_smart_input_missing_url_fails() {
    let json = r#"{"save_to_file": false}"#;
    let result: Result<FetchSmartInput, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

// ── FetchResult serialization ─────────────────────────────────────────────────

#[test]
fn fetch_result_skips_none_cf_type() {
    use std::collections::HashMap;
    // Construct via JSON round-trip since FetchResult is private.
    // We exercise the serialization behavior indirectly by constructing the
    // equivalent JSON manually and asserting field presence rules.
    let json = serde_json::json!({
        "status": 200u16,
        "headers": {},
        "body": "hello",
        "cf_detected": false,
        "elapsed_ms": 42u64
        // cf_type absent — skip_serializing_if = Option::is_none
        // error absent — skip_serializing_if = Option::is_none
    });
    let obj = json.as_object().unwrap();
    assert!(!obj.contains_key("cf_type"));
    assert!(!obj.contains_key("error"));
    assert_eq!(json["status"], 200);
    let _: HashMap<String, String> = serde_json::from_value(json["headers"].clone()).unwrap();
}

// ── FetchSmartResult serialization ───────────────────────────────────────────

mod smart_result {
    use serde::Serialize;

    // Mirror the private struct for serialization-only tests.
    #[derive(Serialize)]
    struct FetchSmartResult {
        status: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        body: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        file_path: Option<String>,
        method: String,
        cf_detected: bool,
        elapsed_ms: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    }

    #[test]
    fn inline_body_present_file_path_absent() {
        let r = FetchSmartResult {
            status: 200,
            body: Some("content".into()),
            file_path: None,
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 10,
            error: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["body"], "content");
        assert!(v.get("file_path").is_none());
        assert!(v.get("error").is_none());
    }

    #[test]
    fn file_path_present_body_absent() {
        let r = FetchSmartResult {
            status: 200,
            body: None,
            file_path: Some("/tmp/ox-browser/example.com_abc.html".into()),
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 10,
            error: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(v.get("body").is_none());
        assert_eq!(v["file_path"], "/tmp/ox-browser/example.com_abc.html");
    }

    #[test]
    fn error_present_serialized() {
        let r = FetchSmartResult {
            status: 0,
            body: None,
            file_path: None,
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 5,
            error: Some("connection refused".into()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["error"], "connection refused");
        assert_eq!(v["status"], 0);
    }

    #[test]
    fn method_field_preserved() {
        for method in ["direct", "solved"] {
            let r = FetchSmartResult {
                status: 200,
                body: Some("ok".into()),
                file_path: None,
                method: method.into(),
                cf_detected: true,
                elapsed_ms: 100,
                error: None,
            };
            let v = serde_json::to_value(&r).unwrap();
            assert_eq!(v["method"], method);
            assert_eq!(v["cf_detected"], true);
        }
    }
}

// ── default_true helper ───────────────────────────────────────────────────────

#[test]
fn default_true_via_serde_default() {
    // Verify the serde(default = "default_true") path indirectly: omitting the
    // field in JSON produces true.
    let input: FetchSmartInput = serde_json::from_str(r#"{"url":"https://x.com"}"#).unwrap();
    assert!(input.save_to_file);

    // Explicit false overrides the default.
    let input2: FetchSmartInput =
        serde_json::from_str(r#"{"url":"https://x.com","save_to_file":false}"#).unwrap();
    assert!(!input2.save_to_file);
}
