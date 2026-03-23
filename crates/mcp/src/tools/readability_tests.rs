//! Unit tests for readability.rs — input defaults, should_fallback, extract_article, html_to_plain.

use super::{ReadabilityInput, extract_article, html_to_plain, should_fallback};

// ── ReadabilityInput deserialization ─────────────────────────────────────────

#[test]
fn readability_input_defaults() {
    let json = r#"{"url": "https://example.com"}"#;
    let input: ReadabilityInput = serde_json::from_str(json).unwrap();
    assert_eq!(input.url, "https://example.com");
    assert!(input.plain_text, "plain_text should default to true");
    assert_eq!(input.max_length, 0, "max_length should default to 0");
}

#[test]
fn readability_input_explicit_values() {
    let json = r#"{"url": "https://example.com", "plain_text": false, "max_length": 500}"#;
    let input: ReadabilityInput = serde_json::from_str(json).unwrap();
    assert!(!input.plain_text);
    assert_eq!(input.max_length, 500);
}

#[test]
fn readability_input_missing_url_fails() {
    let result: Result<ReadabilityInput, _> = serde_json::from_str(r#"{}"#);
    assert!(result.is_err());
}

// ── should_fallback ───────────────────────────────────────────────────────────

#[test]
fn should_fallback_triggers_on_auth_errors() {
    assert!(should_fallback(401), "401 Unauthorized must trigger fallback");
    assert!(should_fallback(403), "403 Forbidden must trigger fallback");
    assert!(should_fallback(429), "429 Too Many Requests must trigger fallback");
    assert!(should_fallback(503), "503 Service Unavailable must trigger fallback");
}

#[test]
fn should_fallback_false_for_success_and_client_errors() {
    assert!(!should_fallback(200), "200 OK must not trigger fallback");
    assert!(!should_fallback(404), "404 Not Found must not trigger fallback");
    assert!(!should_fallback(500), "500 Internal Server Error must not trigger fallback");
    assert!(!should_fallback(301), "301 Redirect must not trigger fallback");
    assert!(!should_fallback(400), "400 Bad Request must not trigger fallback");
}

// ── extract_article ───────────────────────────────────────────────────────────

// Minimal valid HTML that Readability can parse and extract an article from.
fn article_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Test Article</title>
  <meta name="author" content="Jane Doe">
  <meta name="description" content="A short excerpt.">
</head>
<body>
  <article>
    <h1>Test Article</h1>
    <p>This is the first paragraph of the article. It has enough text to pass Readability's scoring heuristics and be recognized as the main content of the page.</p>
    <p>A second paragraph with more content ensures that the article body is substantial enough for extraction to succeed reliably across Readability versions.</p>
  </article>
</body>
</html>"#
}

#[test]
fn extract_article_valid_html_returns_content() {
    let result = extract_article(article_html(), "https://example.com/article", true, 0, "direct");
    // Content must be non-empty — Readability extracted something.
    assert!(!result.content.is_empty(), "content should not be empty");
    // Method is preserved.
    assert_eq!(result.method, "direct");
    // Length matches content len.
    assert_eq!(result.length, result.content.len());
    // elapsed_ms is zeroed in extract_article (set by caller).
    assert_eq!(result.elapsed_ms, 0);
}

#[test]
fn extract_article_plain_text_strips_html_tags() {
    let result = extract_article(article_html(), "https://example.com/article", true, 0, "direct");
    assert!(
        !result.content.contains('<'),
        "plain_text=true must strip HTML tags, got: {}",
        &result.content[..result.content.len().min(200)]
    );
}

#[test]
fn extract_article_html_mode_may_contain_tags() {
    let result = extract_article(article_html(), "https://example.com/article", false, 0, "direct");
    // In HTML mode the raw Readability output is returned. If extraction
    // succeeds the content should contain the paragraph text.
    assert!(!result.content.is_empty(), "content must not be empty in html mode");
}

#[test]
fn extract_article_max_length_truncates() {
    let result = extract_article(article_html(), "https://example.com/article", true, 20, "direct");
    // With max_length=20 the content must be short (20 chars + '…' = 21 code units at most).
    // The '…' char is 3 bytes, so ceiling is 23 bytes.
    assert!(
        result.content.len() <= 23,
        "truncated content too long: {} bytes",
        result.content.len()
    );
    assert!(result.content.ends_with('…'), "truncated content must end with '…'");
    // length field reflects actual length after truncation.
    assert_eq!(result.length, result.content.len());
}

#[test]
fn extract_article_max_length_zero_no_truncation() {
    let full = extract_article(article_html(), "https://example.com/article", true, 0, "direct");
    let also_full = extract_article(article_html(), "https://example.com/article", true, 99_999, "direct");
    // max_length=0 means unlimited — must equal a very large limit.
    assert_eq!(full.content, also_full.content);
}

#[test]
fn extract_article_utf8_boundary_safe_truncation() {
    // HTML with a multi-byte UTF-8 character (Cyrillic, 2 bytes each).
    let html = r#"<!DOCTYPE html><html><head><title>UTF8</title></head><body>
      <article><h1>UTF8</h1>
        <p>Привет мир это тест статьи с достаточным количеством текста для извлечения из Readability алгоритма.</p>
        <p>Дополнительный абзац для надёжного прохождения эвристик анализатора контента.</p>
      </article>
    </body></html>"#;
    // Truncate at 10 bytes — must not panic and must be valid UTF-8.
    let result = extract_article(html, "https://example.com/utf8", true, 10, "direct");
    assert!(std::str::from_utf8(result.content.as_bytes()).is_ok());
}

#[test]
fn extract_article_invalid_html_returns_error_message() {
    // Empty string — Readability will fail to extract.
    let result = extract_article("", "https://example.com", true, 0, "direct");
    // Either init failed or parse returned None; either way content is an error message.
    // The function never panics; it returns a ReadabilityResult with a message.
    assert_eq!(result.method, "direct");
    assert_eq!(result.length, 0);
}

#[test]
fn extract_article_method_propagated() {
    let result = extract_article(article_html(), "https://example.com", true, 0, "solved");
    assert_eq!(result.method, "solved");
}

// ── html_to_plain ─────────────────────────────────────────────────────────────

#[test]
fn html_to_plain_strips_tags_and_collapses_whitespace() {
    let html = "<p>Hello   <b>world</b></p><p>  Second   paragraph  </p>";
    let plain = html_to_plain(html);
    // Tags are gone.
    assert!(!plain.contains('<'), "tags must be stripped");
    // No leading/trailing whitespace.
    assert_eq!(plain, plain.trim());
    // No consecutive spaces.
    assert!(!plain.contains("  "), "whitespace must be collapsed");
    // Content is present.
    assert!(plain.contains("Hello"), "text content must be preserved");
    assert!(plain.contains("world"), "bold text must be preserved");
}

#[test]
fn html_to_plain_empty_input_returns_empty() {
    assert_eq!(html_to_plain(""), "");
}

#[test]
fn html_to_plain_only_whitespace_returns_empty() {
    assert_eq!(html_to_plain("   \n\t  "), "");
}

#[test]
fn html_to_plain_trims_result() {
    let html = "<p>   trimmed   </p>";
    let plain = html_to_plain(html);
    assert_eq!(plain, plain.trim());
}

#[test]
fn html_to_plain_nested_tags() {
    let html = "<div><span><em>Nested</em> text</span></div>";
    let plain = html_to_plain(html);
    assert!(plain.contains("Nested"));
    assert!(plain.contains("text"));
    assert!(!plain.contains('<'));
}
