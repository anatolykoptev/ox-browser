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

// ─── Post-extraction sanity gate (issue #110) — pure-function unit tests ──────
//
// The gate has two independent conditions (absolute floor + ratio). Each test
// pins one boundary so the mutation probes (remove ratio / remove floor) fail
// the right test:
//   - remove the ratio condition → `gate_trips_on_low_ratio_above_floor` still
//     passes but the craigslist fixture test catches it (no trip → no
//     fallback → no listings). This unit test is the sharp boundary for the
//     ratio alone.
//   - remove the floor → `gate_does_not_trip_below_floor` fails (a thin page
//     with extreme ratio would trip).

#[test]
fn gate_trips_on_low_ratio_above_floor() {
    // Source well above the floor; extracted holds far less than the fraction.
    let src = "<html><body>".to_string()
        + &"listing item text here. ".repeat(200) // ~5000 visible chars
        + "</body></html>";
    let ext = "<div>loading reading writing</div>"; // ~30 visible chars
    assert!(
        crate::content_detect::visible_text_len(&src) >= EXTRACTION_GATE_SOURCE_FLOOR,
        "fixture setup: src visible text must be above floor"
    );
    assert_eq!(
        extraction_gate_trips(&src, ext),
        Some(EXTRACTION_GATE_REASON),
        "low ratio above floor must trip"
    );
}

#[test]
fn gate_does_not_trip_below_floor_even_with_extreme_ratio() {
    // Source below the floor (a genuinely thin page): must NOT trip no matter
    // how small the extraction is. The ratio here is extreme (2 / 100 = 0.02,
    // well below the 0.10 fraction) so WITHOUT the floor condition this would
    // trip — this is the test that fails if the absolute floor is removed.
    let src = format!("<html><body>{}</body></html>", "a".repeat(100)); // 100 visible
    let ext = "xy"; // 2 visible → ratio 0.02 < fraction
    assert!(
        crate::content_detect::visible_text_len(&src) < EXTRACTION_GATE_SOURCE_FLOOR,
        "fixture setup: src visible text must be below floor"
    );
    assert!(
        (crate::content_detect::visible_text_len(ext) as f64)
            < (crate::content_detect::visible_text_len(&src) as f64)
                * EXTRACTION_GATE_TEXT_FRACTION,
        "fixture setup: ratio must be below fraction (so only the floor prevents a trip)"
    );
    assert_eq!(
        extraction_gate_trips(&src, ext),
        None,
        "below-floor source must never trip, regardless of ratio"
    );
}

#[test]
fn gate_does_not_trip_when_extraction_captures_enough() {
    // Source above floor; extraction captures more than the fraction → accept.
    let src =
        "<html><body>".to_string() + &"real article body text. ".repeat(200) + "</body></html>";
    // ext is ~60% of src visible text — above the 10% fraction.
    let ext = &"real article body text. ".repeat(120);
    assert_eq!(
        extraction_gate_trips(&src, ext),
        None,
        "extraction above the fraction must not trip"
    );
}

#[test]
fn gate_floor_is_strict_threshold() {
    // At exactly the floor, the page IS gated (the exempt condition is
    // `src < FLOOR`, so src == FLOOR proceeds to the ratio check).
    let mut src = String::new();
    // Pad visible text to exactly EXTRACTION_GATE_SOURCE_FLOOR chars.
    for _ in 0..EXTRACTION_GATE_SOURCE_FLOOR {
        src.push('a');
    }
    assert_eq!(
        crate::content_detect::visible_text_len(&src),
        EXTRACTION_GATE_SOURCE_FLOOR,
        "fixture setup: src visible text must equal floor exactly"
    );
    // ext well below fraction → trips (floor does not exempt at equality).
    assert_eq!(
        extraction_gate_trips(&src, "z"),
        Some(EXTRACTION_GATE_REASON),
        "src == floor must be gated, not exempt"
    );
    // One char below the floor → exempt.
    let src_below: String = "a".repeat(EXTRACTION_GATE_SOURCE_FLOOR - 1);
    assert_eq!(
        extraction_gate_trips(&src_below, "z"),
        None,
        "src == floor-1 must be exempt"
    );
}
