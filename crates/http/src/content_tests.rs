use super::*;

#[test]
fn format_from_param() {
    assert_eq!(ContentFormat::from_param("text"), ContentFormat::Text);
    assert_eq!(
        ContentFormat::from_param("markdown"),
        ContentFormat::Markdown
    );
    assert_eq!(ContentFormat::from_param("md"), ContentFormat::Markdown);
    assert_eq!(ContentFormat::from_param("html"), ContentFormat::Html);
    assert_eq!(ContentFormat::from_param("llm"), ContentFormat::Llm);
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

#[cfg(all(feature = "quickjs", not(target_arch = "wasm32")))]
#[test]
fn recovers_spa_content_from_data_island() {
    // A sparse SPA page where the visible DOM has almost no content,
    // but a <script type="application/json"> data island contains the
    // real page content. extract_content should recover it.
    let html = r##"<html><head><title>Test SPA</title></head>
    <body>
        <div id="root">Loading...</div>
        <script type="application/json" data-target="app-data">
        {"page":{"heading":"Understanding Rust Ownership","body":"Rust ownership is a set of rules that governs how a Rust program manages memory. All programs have to manage the way they use a computer's memory while running. Some languages have garbage collection that constantly looks for no-longer-used memory as the program runs."}}
        </script>
    </body></html>"##;

    let result = extract_content(html, "https://example.com", ContentFormat::Markdown);
    assert!(
        result.content.contains("Understanding Rust Ownership"),
        "should recover heading from data island. Got: {}",
        result.content
    );
    assert!(
        result.content.contains("Rust ownership is a set of rules"),
        "should recover body text from data island"
    );
}

#[cfg(all(feature = "quickjs", not(target_arch = "wasm32")))]
#[test]
fn recovers_spa_content_from_js_eval() {
    // A sparse SPA page where content is assigned to window.__PRELOADED_STATE__
    // via an inline <script> tag. QuickJS should execute it and recover the text.
    let html = r#"<html><head><title>JS SPA</title></head>
    <body>
        <div id="root">Loading...</div>
        <script>
        window.__PRELOADED_STATE__ = {
            "article": {
                "title": "Understanding Rust Ownership and Borrowing",
                "body": "Rust ownership is a set of rules that governs how a Rust program manages memory. All programs have to manage the way they use a computer's memory while running. Some languages have garbage collection that constantly looks for no-longer-used memory as the program runs."
            }
        };
        </script>
    </body></html>"#;

    let result = extract_content(html, "https://example.com", ContentFormat::Markdown);
    assert!(
        result
            .content
            .contains("Understanding Rust Ownership and Borrowing"),
        "should recover title from JS eval. Got: {}",
        result.content
    );
    assert!(
        result.content.contains("Rust ownership is a set of rules"),
        "should recover body text from JS eval"
    );
}

#[cfg(all(feature = "quickjs", not(target_arch = "wasm32")))]
#[test]
fn does_not_recover_when_dom_has_enough_content() {
    // A page with plenty of DOM content should NOT trigger SPA recovery,
    // even if data islands are present.
    let mut body = String::from("<html><head><title>Full Page</title></head><body><article>");
    for i in 0..100 {
        body.push_str(&format!(
            "<p>This is paragraph number {i} with enough text to exceed the sparse threshold for SPA content recovery.</p>"
        ));
    }
    body.push_str(
        r##"</article>
        <script type="application/json">{"heading":"Should Not Appear","description":"This content should not be extracted because the DOM already has enough content."}</script>
        </body></html>"##,
    );

    let result = extract_content(&body, "https://example.com", ContentFormat::Markdown);
    assert!(
        !result.content.contains("Should Not Appear"),
        "should NOT recover data island when DOM has enough content"
    );
}
