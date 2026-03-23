use super::*;

#[test]
fn format_from_param() {
    assert_eq!(ContentFormat::from_param("text"), ContentFormat::Text);
    assert_eq!(ContentFormat::from_param("markdown"), ContentFormat::Markdown);
    assert_eq!(ContentFormat::from_param("md"), ContentFormat::Markdown);
    assert_eq!(ContentFormat::from_param("html"), ContentFormat::Html);
    assert_eq!(ContentFormat::from_param("unknown"), ContentFormat::Text);
}

#[test]
fn extracts_article_as_text() {
    let html = r#"<html><head><title>Test Article</title></head>
    <body><article><h1>Hello</h1><p>World paragraph.</p></article></body></html>"#;
    let result = extract_content(html, "https://example.com", ContentFormat::Text);
    assert!(!result.content.is_empty());
    assert_eq!(result.title, "Test Article");
    assert!(!result.content.contains('<'));
}

#[test]
fn extracts_article_as_markdown() {
    let html = r#"<html><head><title>MD Test</title></head>
    <body><article><h1>Hello</h1><p>World <a href="/link">click</a></p></article>
    <nav><a href="/">Home</a></nav></body></html>"#;
    let result = extract_content(html, "https://example.com", ContentFormat::Markdown);
    assert!(result.content.contains("Hello"), "got: {}", result.content);
    assert!(!result.content.contains("Home"), "nav should be stripped");
}

#[test]
fn extracts_article_as_html() {
    let html = r#"<html><head><title>HTML Test</title></head>
    <body><article><p>Content here</p></article></body></html>"#;
    let result = extract_content(html, "https://example.com", ContentFormat::Html);
    assert!(result.content.contains("<p>"));
}

#[test]
fn detects_low_quality_content() {
    let filler = "x".repeat(10_000);
    let html = format!(
        "<html><head><title>Block</title></head><body><script>{filler}</script><p>Please wait</p></body></html>"
    );
    assert!(is_low_quality(&html, "Please wait"));
}

#[test]
fn normal_content_is_not_low_quality() {
    let content = "A".repeat(500);
    let html = format!("<html><body><p>{content}</p></body></html>");
    assert!(!is_low_quality(&html, &content));
}

#[test]
fn truncates_with_utf8_safety() {
    let truncated = truncate_utf8("Привет мир!", 10);
    assert!(truncated.len() <= 14);
    assert!(truncated.ends_with('…'));
}

#[test]
fn empty_html_returns_empty() {
    let result = extract_content("", "https://example.com", ContentFormat::Text);
    assert!(result.content.is_empty());
}

#[test]
fn should_fallback_codes() {
    assert!(should_fallback(401));
    assert!(should_fallback(403));
    assert!(should_fallback(429));
    assert!(should_fallback(503));
    assert!(!should_fallback(200));
    assert!(!should_fallback(404));
    assert!(!should_fallback(500));
}

#[test]
fn test_extract_og_image() {
    let html = r#"<html><head><meta property="og:image" content="https://example.com/hero.jpg"></head><body>Hello</body></html>"#;
    assert_eq!(extract_og_image(html), "https://example.com/hero.jpg");
}

#[test]
fn test_extract_og_image_missing() {
    let html = "<html><head><title>Test</title></head><body>Hello</body></html>";
    assert_eq!(extract_og_image(html), "");
}

#[test]
fn test_extract_og_image_single_quotes() {
    let html = r#"<html><head><meta property='og:image' content='https://example.com/img.png'></head></html>"#;
    assert_eq!(extract_og_image(html), "https://example.com/img.png");
}
