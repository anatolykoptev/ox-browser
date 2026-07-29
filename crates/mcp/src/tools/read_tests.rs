use ox_http::content::{ReadOutput, ReadParams};

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
