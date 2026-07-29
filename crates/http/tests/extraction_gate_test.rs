//! Fixture-driven regression tests for the post-extraction sanity gate
//! (issue #110): `/read` returned a hidden loading-curtain overlay instead of
//! a craigslist list page's 115+ listings, HTTP 200, `error: null`.
//!
//! The gate compares visible text of the source and the extracted subtree; a
//! drastic shortfall (source above an absolute floor, extraction below a
//! fraction of it) rejects the extracted subtree and falls back to the whole
//! document converted to the requested format.
//!
//! These tests are the regression-risk work — proving the gate fires on the
//! bug shape AND does not fire on real articles (long and short) or a
//! genuinely thin page. The pure-function boundary tests live in
//! `content_tests.rs`.

use ox_http::content::{ContentFormat, extract_content};
use ox_http::metrics::READ_EXTRACTION_REJECTED_TOTAL;
use std::sync::atomic::Ordering;

fn fixture(name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()))
}

const CRAIGSLIST: &str = "craigslist.org_sfbay_fbh.html";
const THIN: &str = "thin_page.html";

/// Real articles that must extract cleanly (gate must NOT trip). Includes a
/// long one (bbc) and short ones (vercel, github) — a short article in a
/// heavy page is the shape most likely to be caught by mistake.
const ARTICLES: &[(&str, &str)] = &[
    ("www.bbc.com_news.html", "https://www.bbc.com/news"),
    ("nextjs.org.html", "https://nextjs.org"),
    ("vercel.com.html", "https://vercel.com"),
    ("github.com_torvalds.html", "https://github.com/torvalds"),
];

const REASON: &str = "extraction_rejected_low_text_ratio";

// ─── The bug case: the gate trips and the listings come back ─────────────────

#[test]
fn craigslist_list_page_trips_gate_and_returns_listings_html() {
    let html = fixture(CRAIGSLIST);

    // Without the gate, the extractor selects the hidden loading curtain
    // (`<div class="content">loading reading writing saving searching</div>`)
    // and the listings are discarded. With the gate, the whole document is
    // returned for html format — so the listing items must be present.
    let result = extract_content(
        &html,
        "https://www.craigslist.org/search/area/sfbay?cat=fbh",
        ContentFormat::Html,
    );

    assert_eq!(
        result.extraction_note.as_deref(),
        Some(REASON),
        "craigslist list page must trip the gate; got note={:?}",
        result.extraction_note
    );

    // Assert the actual listings are present — not merely that output got
    // longer. The fixture has 100+ `<li class="cl-static-search-result">`.
    let listing_count = result.content.matches("cl-static-search-result").count();
    assert!(
        listing_count >= 100,
        "fallback must contain the listings (>=100 refs to cl-static-search-result); got {listing_count}"
    );

    // The curtain text must not be the whole story — but it IS in the page,
    // so we assert the listings outnumber it rather than asserting absence.
    assert!(
        result.content.contains("cl-static-search-result"),
        "fallback must contain listing markup"
    );
}

#[test]
fn craigslist_list_page_text_fallback_has_listing_text_not_just_curtain() {
    let html = fixture(CRAIGSLIST);
    let result = extract_content(
        &html,
        "https://www.craigslist.org/search/area/sfbay?cat=fbh",
        ContentFormat::Text,
    );

    assert_eq!(
        result.extraction_note.as_deref(),
        Some(REASON),
        "text format must also trip the gate (one gate, all formats)"
    );

    // The bug produced ~590 chars of curtain text. The fallback is the whole
    // document → thousands of words of listing titles.
    let words = result.content.split_whitespace().count();
    assert!(
        words >= 500,
        "text fallback must contain the listings' text (>=500 words); got {words}"
    );

    // The curtain's standalone words must not dominate: "loading" appears in
    // the page, but the listings' job-title text must be present too. Pick a
    // stable listing word from the fixture.
    assert!(
        result.content.contains("jobs")
            || result.content.contains("restaurant")
            || result.content.contains("chef"),
        "text fallback must contain real listing text, not only the curtain"
    );

    // The fallback is the whole document, which carries inline `<script>` and
    // `<style>` source. `html_to_plain` must strip those (issue #110 M1):
    // dom_query's `text_of` collects every text descendant with no tag filter,
    // so without stripping, the Text output leaks inline JS/CSS source. The
    // listings dominate the word count and mask the leak — so assert the
    // script/style source is ABSENT, not merely that listing text is present.
    // Markers taken from the fixture's inline scripts/styles.
    assert!(
        !result.content.contains("onpageshow"),
        "text fallback must not leak inline script source (onpageshow)"
    );
    assert!(
        !result.content.contains("cl.init"),
        "text fallback must not leak inline script source (cl.init)"
    );
    assert!(
        !result.content.contains("specialCurtainMessages"),
        "text fallback must not leak inline script source (specialCurtainMessages)"
    );
    assert!(
        !result.content.contains("unsupportedBrowser"),
        "text fallback must not leak inline script/style source (unsupportedBrowser)"
    );
    // `window.` is a strong script-source signal; the fixture has it only in
    // inline scripts. After stripping, zero occurrences.
    assert_eq!(
        result.content.matches("window.").count(),
        0,
        "text fallback must not contain any `window.` script-source markers"
    );
}

// ─── Real articles must NOT trip ─────────────────────────────────────────────

#[test]
fn real_articles_do_not_trip_gate() {
    for (filename, url) in ARTICLES {
        let html = fixture(filename);
        let result = extract_content(&html, url, ContentFormat::Markdown);
        assert_eq!(
            result.extraction_note, None,
            "{filename}: real article must NOT trip the gate; got note={:?}",
            result.extraction_note
        );
        // And the extraction is still non-empty (sanity: the gate didn't
        // break the normal path).
        assert!(
            !result.content.is_empty(),
            "{filename}: content must still be extracted"
        );
    }
}

// ─── A genuinely thin page must NOT trip ─────────────────────────────────────

#[test]
fn thin_page_does_not_trip_gate() {
    let html = fixture(THIN);
    let result = extract_content(&html, "https://example.com/thin", ContentFormat::Markdown);
    assert_eq!(
        result.extraction_note, None,
        "a genuinely thin page (two paragraphs) must not trip the gate; got note={:?}",
        result.extraction_note
    );
    // And it extracts its real content, not a fallback.
    assert!(
        result.content.contains("first paragraph"),
        "thin page must extract its own content; got: {:?}",
        result.content
    );
}

// ─── The counter reflects a trip ─────────────────────────────────────────────

#[test]
fn gate_counter_increments_on_trip() {
    let before = READ_EXTRACTION_REJECTED_TOTAL.load(Ordering::Relaxed);
    let html = fixture(CRAIGSLIST);
    let _ = extract_content(&html, "https://www.craigslist.org/x", ContentFormat::Html);
    let after = READ_EXTRACTION_REJECTED_TOTAL.load(Ordering::Relaxed);
    assert!(
        after > before,
        "READ_EXTRACTION_REJECTED_TOTAL must increment on a gate trip (before={before}, after={after})"
    );
}

// ─── The counter does NOT increment on a clean extraction ────────────────────

#[test]
fn gate_counter_does_not_increment_on_clean_extraction() {
    // Use the thin page: below the floor, so the gate short-circuits to None
    // without ever reaching the counter. A thin page is the cleanest case to
    // prove the counter is gated behind a real trip, not bumped unconditionally.
    let before = READ_EXTRACTION_REJECTED_TOTAL.load(Ordering::Relaxed);
    let html = fixture(THIN);
    let _ = extract_content(&html, "https://example.com/thin2", ContentFormat::Text);
    let after = READ_EXTRACTION_REJECTED_TOTAL.load(Ordering::Relaxed);
    assert_eq!(
        after, before,
        "counter must NOT increment when the gate does not trip (before={before}, after={after})"
    );
}
