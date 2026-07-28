//! Fixture-based regression tests for content extraction quality.
//!
//! Loads real-world HTML snapshots from `fixtures/` and asserts that
//! `extract_content` produces markdown with at least a minimum word count.
//! These thresholds are set ~20% below current observed values to catch
//! regressions without being brittle to minor extraction changes.
//!
//! Fixtures are stored in `crates/http/tests/fixtures/` (not committed to
//! the published crate — excluded via `.gitignore` in the crate root if
//! needed). They are real HTML snapshots captured on 2026-07-27.

use ox_http::content::{ContentFormat, extract_content};

struct Fixture {
    filename: &'static str,
    url: &'static str,
    min_words: usize,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        filename: "nextjs.org.html",
        url: "https://nextjs.org",
        // Current: ~1220 words. Threshold: 900 (catches Suspense boundary regression).
        min_words: 900,
    },
    Fixture {
        filename: "vercel.com.html",
        url: "https://vercel.com",
        // Current: ~267 words. Threshold: 200 (catches H1 recovery regression).
        min_words: 200,
    },
    Fixture {
        filename: "github.com_torvalds.html",
        url: "https://github.com/torvalds",
        // Current: ~177 words. Threshold: 130 (catches dialog H1 filter regression).
        min_words: 130,
    },
    Fixture {
        filename: "www.bbc.com_news.html",
        url: "https://www.bbc.com/news",
        // Current: ~1660 words. Threshold: 1200 (catches noise filter regression).
        min_words: 1200,
    },
];

fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

#[test]
fn fixtures_meet_word_count_thresholds() {
    for fixture in FIXTURES {
        let path = fixture_dir().join(fixture.filename);
        let html = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));

        let result = extract_content(&html, fixture.url, ContentFormat::Markdown);
        let words = result.content.split_whitespace().count();

        assert!(
            words >= fixture.min_words,
            "{}: extracted {} words, expected at least {}",
            fixture.filename,
            words,
            fixture.min_words
        );
    }
}

#[test]
fn fixtures_extract_non_empty_title() {
    for fixture in FIXTURES {
        let path = fixture_dir().join(fixture.filename);
        let html = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));

        let result = extract_content(&html, fixture.url, ContentFormat::Markdown);
        assert!(
            !result.title.is_empty(),
            "{}: title should not be empty",
            fixture.filename
        );
    }
}
