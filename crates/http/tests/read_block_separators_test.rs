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
        out.content
            .starts_with("Example Church in Springfield\n\nFirst paragraph with a link"),
        "extracted <main> must start with its first block, separated from the next: {:?}",
        out.content
    );
    assert!(
        out.content.contains("Second paragraph.\n\nOne"),
        "paragraph/list boundary lost: {:?}",
        out.content
    );
    // Scripts/styles inside the extracted body, plus <noscript>, must not leak.
    for leaked in ["bodyleak", "color:blue", "enable js"] {
        assert!(
            !out.content.contains(leaked),
            "{leaked} leaked: {:?}",
            out.content
        );
    }
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

#[test]
fn pre_keeps_edge_newlines_and_br_and_drops_whitespace_only() {
    assert_eq!(
        html_to_plain("<p>x</p><pre>code\n\n</pre><p>y</p>"),
        "x\n\ncode\n\n\n\ny"
    );
    assert_eq!(
        html_to_plain("<p>x</p><pre>\n\ncode</pre><p>y</p>"),
        "x\n\n\ncode\n\ny"
    );
    assert_eq!(
        html_to_plain("<ul><li><pre>a\n\n</pre></li><li>b</li></ul>"),
        "a\n\n\n\nb"
    );
    assert_eq!(html_to_plain("<pre>a<br>b</pre>"), "a\nb");
    // Literal <pre> newlines at the very edges of the output are not trimmed.
    assert_eq!(html_to_plain("<pre>\n\ncode\n\n</pre>"), "\ncode\n\n");
    assert_eq!(html_to_plain("<pre><br>code<br></pre>"), "\ncode\n");
    assert_eq!(html_to_plain("<p>x</p><pre> \t\n </pre><p>y</p>"), "x\n\ny");
    assert_eq!(html_to_plain("<pre> \t </pre>"), "");
}

#[test]
fn block_boundary_is_not_one_of_two_breaks() {
    assert_eq!(html_to_plain("<div>a</div><br><div>b</div>"), "a\nb");
    assert_eq!(html_to_plain("<div>a<br></div><div><br>b</div>"), "a\nb");
    // Two explicit breaks in a row are still a blank line.
    assert_eq!(html_to_plain("<div>a<br><br>b</div>"), "a\n\nb");
    assert_eq!(html_to_plain("a<br>\n<br>b"), "a\n\nb");
}

#[test]
fn bodyless_frameset_document_renders_empty() {
    let html = "<html><head><title>T</title></head><frameset><frame src=\"about:blank\"></frameset></html>";
    assert_eq!(html_to_plain(html), "");
}

#[test]
fn spa_recovery_does_not_duplicate_prose_split_by_block_separators() {
    // The DOM renders the two sentences as adjacent paragraphs ("...\n\n..."); the
    // JSON island holds the same prose on one line. It must dedupe, while the
    // genuinely new island paragraph is still recovered (guards a vacuous pass).
    let html = r#"<html><head><title>T</title><script type="application/json" id="d">{"items":[{"nodeType":"paragraph","content":[{"nodeType":"text","value":"The first sentence. The second sentence."}]},{"nodeType":"paragraph","content":[{"nodeType":"text","value":"Only the island carries this fresh sentence."}]}]}</script></head><body><p>The first sentence.</p><p>The second sentence.</p></body></html>"#;
    let out = extract_content(html, "https://example.com/", ContentFormat::Text);
    assert!(
        out.content
            .contains("Only the island carries this fresh sentence."),
        "island content not recovered at all: {:?}",
        out.content
    );
    assert_eq!(
        out.content.matches("first sentence").count(),
        1,
        "island prose duplicated: {:?}",
        out.content
    );
}

fn island(json: &str) -> String {
    format!(
        r#"<html><head><title>T</title><script type="application/json" id="d">{json}</script></head><body><p>The first sentence.</p><p>The second sentence.</p></body></html>"#
    )
}

#[test]
fn spa_recovery_keeps_island_only_heading_when_body_is_duplicate() {
    let html = island(
        r#"{"heading":"Important eligibility conditions","description":"The first sentence. The second sentence."}"#,
    );
    let out = extract_content(&html, "https://example.com/", ContentFormat::Text);
    assert!(
        out.content
            .starts_with("The first sentence.\n\nThe second sentence."),
        "DOM copy missing: {:?}",
        out.content
    );
    assert!(
        out.content.contains("Important eligibility conditions"),
        "island-only heading dropped with its duplicate body: {:?}",
        out.content
    );
    assert_eq!(
        out.content.matches("first sentence").count(),
        1,
        "duplicate body re-appended: {:?}",
        out.content
    );
}

#[test]
fn spa_dedup_matches_whole_words_only() {
    let html = r#"<html><head><title>T</title><script type="application/json" id="d">{"heading":"Water treatment","description":"Filtration steps explained for every household."}</script></head><body><div>Rainwater</div><div>treatment options</div></body></html>"#;
    let out = extract_content(html, "https://example.com/", ContentFormat::Text);
    assert!(
        out.content.contains("Water treatment"),
        "heading suppressed by a mid-word match across blocks: {:?}",
        out.content
    );
    assert!(
        out.content.starts_with("Rainwater\n\ntreatment options")
            || out.content.starts_with("Rainwater\ntreatment options"),
        "DOM copy missing: {:?}",
        out.content
    );
}
