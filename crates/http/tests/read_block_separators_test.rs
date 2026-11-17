//! Regression guard: `/read` text output must separate adjacent block
//! elements. Page builders (Elementor, etc.) emit nested `<div>`s with no
//! whitespace between them, and the text format used to glue their contents
//! together ("Welcome, we are:Example Church ...").
//!
//! The expected string below is written by hand from the fixture's markup, not
//! produced by the code under test.

use ox_http::content::{ContentFormat, extract_content, html_to_plain};

const FIXTURE: &str = include_str!("fixtures/read_blocks_minified.html");

// Rule: p/h1-h6/blockquote/pre/ul/ol/table get a blank line on both sides;
// other blocks (div, header, footer, li, tr, td, br) a single newline.
const EXPECTED: &str = "\
Welcome, we are:

Example Church in Springfield

First paragraph with a link, inline emphasis and spans.

Second paragraph.

One
Two bold

Line A
Line B

Line C

keep   this
  indent

Cell 1
Cell 2

Quoted

(c) Example";

#[test]
fn html_to_plain_separates_blocks_and_keeps_inline_spacing() {
    assert_eq!(html_to_plain(FIXTURE), EXPECTED);
}

#[test]
fn read_text_format_separates_blocks_end_to_end() {
    // Same fixture through the real /read path (extractor + gate + text).
    let out = extract_content(FIXTURE, "https://example.com/", ContentFormat::Text);
    assert!(
        !out.content.contains("Welcome, we are:Example"),
        "heading glued to next block: {:?}",
        out.content
    );
    assert!(
        out.content.contains("Second paragraph.\n\nOne"),
        "paragraph/list boundary lost: {:?}",
        out.content
    );
    assert!(
        !out.content.contains("leaked"),
        "script leaked: {:?}",
        out.content
    );
    assert!(
        !out.content.contains("enable js"),
        "noscript leaked: {:?}",
        out.content
    );
}

#[test]
fn inline_elements_never_gain_newlines() {
    let html = "<p>a<span>b</span> <b>c</b><i>d</i>\n  e</p>";
    assert_eq!(html_to_plain(html), "ab cd e");
}

#[test]
fn json_ld_and_metadata_unchanged_by_text_rendering() {
    let html = r#"<html><head><title>T</title><meta property="og:image" content="https://example.com/i.png"><script type="application/ld+json">{"@type":"Article","headline":"H"}</script></head><body><div>a</div><div>b</div></body></html>"#;
    let text = extract_content(html, "https://example.com/", ContentFormat::Text);
    let md = extract_content(html, "https://example.com/", ContentFormat::Markdown);
    assert_eq!(text.json_ld, md.json_ld);
    assert_eq!(text.json_ld.len(), 1);
    assert_eq!(text.og_image, "https://example.com/i.png");
    assert_eq!(text.title, md.title);
}
