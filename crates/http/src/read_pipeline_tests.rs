use super::*;
use crate::content::ReadParams;

#[test]
fn build_output_populates_all_fields() {
    let ext = crate::content::ExtractedContent {
        title: "T".into(),
        content: "C".into(),
        author: "A".into(),
        excerpt: "E".into(),
        length: 1,
        json_ld: vec![],
        og_image: String::new(),
    };
    let params = ReadParams { url: "https://x.com".into(), format: "text".into(), max_length: 0 };
    let out = build_output(ext, &params, "direct", 42);
    assert_eq!(out.title, "T");
    assert_eq!(out.url, "https://x.com");
    assert_eq!(out.method, "direct");
    assert_eq!(out.elapsed_ms, 42);
    assert!(out.error.is_none());
}

#[test]
fn build_error_output_has_error() {
    let params = ReadParams {
        url: "https://fail.com".into(),
        format: "text".into(),
        max_length: 0,
    };
    let out = build_error_output(&params, "direct", 10, "connection refused");
    assert_eq!(out.error.as_deref(), Some("connection refused"));
    assert!(out.content.is_empty());
}

#[test]
fn truncation_applied_when_max_length_set() {
    let ext = crate::content::ExtractedContent {
        title: "T".into(),
        content: "A".repeat(500),
        author: String::new(),
        excerpt: String::new(),
        length: 500,
        json_ld: vec![],
        og_image: String::new(),
    };
    let params = ReadParams { url: "https://x.com".into(), format: "text".into(), max_length: 50 };
    let out = build_output(ext, &params, "direct", 0);
    assert!(out.content.len() <= 55);
}
