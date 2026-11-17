//! Regression guard (issue #233): `format: "llm"` must keep every block
//! boundary the markdown format keeps. Two cleanups used to destroy them:
//! `merge_stat_lines` glued a short line onto the next block with a space
//! ("Sunday worship 10:30 AM Wednesday Bible study 7 PM"), and
//! `collapse_repeated_in_line` re-emitted every line word-joined, collapsing
//! `*   ` list markers to `* ` on items with 4+ words while shorter items
//! kept their padding.
//!
//! Every assertion goes through `read_supplied` — the real `/read`
//! supplied-HTML path — not a unit call into the llm module.

use ox_http::content::ReadParams;
use ox_http::read_pipeline::read_supplied;

const URL: &str = "https://example.com/page";

fn params(format: &str, html: &str) -> ReadParams {
    serde_json::from_value(serde_json::json!({
        "url": URL, "format": format, "html": html,
    }))
    .unwrap()
}

/// The issue's input (one 4+ word item, one short item: the padding bug hit only
/// the long one): a heading, two short paragraphs, and a two-item list.
const ISSUE_HTML: &str = "<html><body><main><h1>Hi</h1><p>Sunday worship 10:30 AM</p><p>Wednesday Bible study 7 PM</p><ul><li>Office: Mon-Fri 9-5 except public holidays</li><li>Phone 555</li></ul></main></body></html>";

/// The bullet marker plus the whitespace before the item text — `* ` vs
/// `*   ` is exactly the inconsistency the issue reports.
fn marker_prefix(line: &str) -> &str {
    let end = line
        .find(|c: char| c.is_alphanumeric())
        .unwrap_or(line.len());
    &line[..end]
}

#[tokio::test]
async fn llm_keeps_adjacent_short_paragraphs_on_separate_lines() {
    let out = read_supplied(&params("llm", ISSUE_HTML)).await.unwrap();
    for paragraph in ["Sunday worship 10:30 AM", "Wednesday Bible study 7 PM"] {
        assert!(
            out.content.lines().any(|l| l.trim() == paragraph),
            "paragraph must be its own line (glued into a sentence?): {:?}",
            out.content
        );
    }
}

#[tokio::test]
async fn llm_list_items_stay_on_separate_lines_with_consistent_markers() {
    let out = read_supplied(&params("llm", ISSUE_HTML)).await.unwrap();
    let item1 = out
        .content
        .lines()
        .find(|l| l.contains("Office: Mon-Fri 9-5"))
        .expect("first <li> missing");
    let item2 = out
        .content
        .lines()
        .find(|l| l.contains("Phone 555"))
        .expect("second <li> missing");
    assert_ne!(
        item1, item2,
        "<li> items glued onto one line: {:?}",
        out.content
    );
    assert_eq!(
        marker_prefix(item1),
        marker_prefix(item2),
        "inconsistent list markers: {item1:?} vs {item2:?} in {:?}",
        out.content
    );
}

#[tokio::test]
async fn llm_heading_and_following_paragraph_keep_block_boundary() {
    let out = read_supplied(&params("llm", ISSUE_HTML)).await.unwrap();
    assert!(
        out.content.lines().any(|l| l.trim() == "# Hi"),
        "heading must be its own line: {:?}",
        out.content
    );
    // Markdown separates the heading from the paragraph with a blank line;
    // llm must keep that boundary too.
    assert!(
        out.content.contains("# Hi\n\nSunday worship 10:30 AM"),
        "heading/paragraph boundary lost: {:?}",
        out.content
    );
}

#[tokio::test]
async fn llm_content_has_same_block_line_count_as_markdown() {
    const FIXTURE: &str = "<html><body><main>\
        <h1>Parity Page</h1>\
        <p>First short paragraph.</p><p>Second short paragraph.</p>\
        <h2>Service times</h2>\
        <p>Sunday worship 10:30 AM</p><p>Wednesday Bible study 7 PM</p>\
        <ul><li>Office: Mon-Fri 9-5</li><li>Phone 555</li><li>Email us anytime</li></ul>\
        <ol><li>Step one</li><li>Step two</li></ol>\
        </main></body></html>";

    let llm = read_supplied(&params("llm", FIXTURE)).await.unwrap();
    let md = read_supplied(&params("markdown", FIXTURE)).await.unwrap();

    // Non-empty, non-`>` lines: `> URL:`/`> Title:` preamble lines and
    // blockquote markers are format extras, not content blocks.
    let block_lines = |content: &str| {
        content
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('>'))
            .count()
    };
    assert_eq!(
        block_lines(&llm.content),
        block_lines(&md.content),
        "llm lost block lines\nllm: {:?}\nmarkdown: {:?}",
        llm.content,
        md.content
    );
}
