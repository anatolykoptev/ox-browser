use ox_http::content::ReadParams;

#[test]
fn read_params_deserializes_with_defaults() {
    let json = r#"{"url": "https://example.com"}"#;
    let p: ReadParams = serde_json::from_str(json).unwrap();
    assert_eq!(p.url, "https://example.com");
    assert_eq!(p.format, "text");
    assert_eq!(p.max_length, 0);
}

#[test]
fn read_params_with_markdown() {
    let json = r#"{"url": "https://x.com", "format": "markdown", "max_length": 1000}"#;
    let p: ReadParams = serde_json::from_str(json).unwrap();
    assert_eq!(p.format, "markdown");
    assert_eq!(p.max_length, 1000);
}
