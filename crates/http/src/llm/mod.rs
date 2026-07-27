//! LLM-optimized output format — token-efficient text for LLM consumption.
//!
//! Takes a [`ReadOutput`] and produces a compact text representation that
//! maximizes information density per token. Strips decorative images,
//! visual-only formatting (bold/italic), and inline link URLs — moving links
//! to a deduplicated section at the end.
//!
//! Ported from webclaw `crates/webclaw-core/src/llm/mod.rs` (MIT), adapted
//! to ox-browser's [`ReadOutput`] type instead of webclaw's `ExtractionResult`.
//!
//! Issue #58: LLM cleanup pipeline (strip JS/CSS/noise from markdown).

mod body;
mod cleanup;
mod images;
mod links;
mod metadata;
mod noise_text;

use crate::content::ReadOutput;

/// Produce a token-optimized text representation of extracted content.
///
/// The output has three sections:
/// 1. Compact metadata header (`> ` prefixed lines)
/// 2. Cleaned body (no images, no bold/italic, links as plain text)
/// 3. Deduplicated links section at the end
/// 4. Structured data (JSON-LD) if useful and under budget
pub fn to_llm_text(output: &ReadOutput) -> String {
    let mut out = String::new();

    // -- 1. Metadata header --
    metadata::build_metadata_header(&mut out, output);

    // -- 2. Process body --
    let processed = body::process_body(&output.content);

    if !processed.text.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&processed.text);
    }

    // -- 3. Links section --
    if !processed.links.is_empty() {
        out.push_str("\n\n## Links\n");
        for (text, href) in &processed.links {
            let label = links::clean_link_label(text);
            if !label.is_empty() {
                out.push_str(&format!("- {label}: {href}\n"));
            }
        }
    }

    // -- 4. Structured data (JSON-LD) --
    // Only emit useful items: Schema.org records with a meaningful @type,
    // and only if the total serialized size stays under a budget. Framework
    // hydration blobs (Next.js pageProps full of ad-targeting flags, build
    // IDs, schedule paths) explode to hundreds of KB and drown the LLM in
    // noise — drop them rather than ship them.
    let mut useful: Vec<_> = output
        .json_ld
        .iter()
        .filter(|v| is_useful_structured_data(v))
        .cloned()
        .collect();
    for value in &mut useful {
        scrub_body_fields(value, 0);
    }
    if !useful.is_empty() {
        let serialized = serde_json::to_string_pretty(&useful).unwrap_or_default();
        const STRUCTURED_DATA_MAX_BYTES: usize = 16 * 1024;
        if serialized.len() <= STRUCTURED_DATA_MAX_BYTES {
            out.push_str("\n\n## Structured Data\n\n```json\n");
            out.push_str(&serialized);
            out.push_str("\n```");
        }
    }

    out.trim().to_string()
}

/// Decide whether a structured-data value carries content worth emitting.
///
/// Schema.org records with a recognizable content `@type` (Article, NewsArticle,
/// Product, Recipe, FAQPage, HowTo, Event, Person, Organization, BreadcrumbList,
/// VideoObject, JobPosting, etc.) are kept. Generic `WebSite` / `WebPage` /
/// `ItemList` records and Next.js `pageProps`-style blobs without a useful
/// `@type` are dropped — they're almost always navigation chrome or framework
/// hydration state.
fn is_useful_structured_data(v: &serde_json::Value) -> bool {
    let Some(obj) = v.as_object() else {
        // SvelteKit can emit compact arrays of page data. Keep those if they
        // are small enough to be useful, while still dropping giant hydration
        // arrays under the same budget as untyped objects.
        if v.is_array() {
            let serialized = serde_json::to_string(v).unwrap_or_default();
            return serialized.len() <= 4 * 1024;
        }
        return false;
    };
    // JSON-LD: @type drives the decision.
    if let Some(t) = obj.get("@type") {
        let types: Vec<String> = match t {
            serde_json::Value::String(s) => vec![s.to_ascii_lowercase()],
            serde_json::Value::Array(a) => a
                .iter()
                .filter_map(|x| x.as_str())
                .map(str::to_ascii_lowercase)
                .collect(),
            _ => Vec::new(),
        };
        if types.is_empty() {
            return false;
        }
        // Drop low-info chrome types.
        const DROP_TYPES: &[&str] = &["website", "webpage", "sitenavigationelement"];
        return types.iter().any(|t| !DROP_TYPES.iter().any(|d| t == d));
    }
    // Next.js pageProps / SvelteKit data without @type: keep only if compact.
    // Anything over ~4KB is almost certainly hydration state, not content.
    let serialized = serde_json::to_string(v).unwrap_or_default();
    serialized.len() <= 4 * 1024
}

/// Recursively remove long fields that duplicate the rendered markdown body.
///
/// `depth` guards against stack exhaustion from attacker-controlled
/// JSON-LD / `__NEXT_DATA__` blobs with pathological nesting: past
/// [`MAX_SCRUB_DEPTH`] levels we stop descending and leave the subtree
/// as-is (it is still size-capped by the `STRUCTURED_DATA_MAX_BYTES`
/// budget in `to_llm_text`).
fn scrub_body_fields(v: &mut serde_json::Value, depth: usize) {
    const BODY_KEYS: &[&str] = &["articleBody"];
    const LONG_BODY_KEYS: &[&str] = &["body", "text", "description"];
    const LONG_THRESHOLD: usize = 500;
    const MAX_SCRUB_DEPTH: usize = 64;

    if depth >= MAX_SCRUB_DEPTH {
        return;
    }

    match v {
        serde_json::Value::Object(map) => {
            map.retain(|key, value| {
                if BODY_KEYS.contains(&key.as_str()) {
                    return false;
                }
                if LONG_BODY_KEYS.contains(&key.as_str())
                    && value.as_str().is_some_and(|s| s.len() >= LONG_THRESHOLD)
                {
                    return false;
                }
                true
            });
            for value in map.values_mut() {
                scrub_body_fields(value, depth + 1);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                scrub_body_fields(value, depth + 1);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Integration tests that exercise the full pipeline through to_llm_text
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::ReadOutput;

    fn make_output(content: &str) -> ReadOutput {
        ReadOutput {
            title: "Test Page".into(),
            content: content.into(),
            author: String::new(),
            excerpt: "A test page".into(),
            url: "https://example.com".into(),
            format: "llm".into(),
            length: content.len(),
            method: "direct".into(),
            elapsed_ms: 42,
            json_ld: vec![],
            og_image: String::new(),
            published_at: String::new(),
            modified_at: String::new(),
            section: String::new(),
            site_name: String::new(),
            tags: vec![],
            language: "en".into(),
            error: None,
        }
    }

    #[test]
    fn metadata_header_includes_populated_fields() {
        let result = make_output("# Hello");
        let out = to_llm_text(&result);

        assert!(out.contains("> URL: https://example.com"));
        assert!(out.contains("> Title: Test Page"));
        assert!(out.contains("> Description: A test page"));
        assert!(out.contains("> Language: en"));
        assert!(!out.contains("> Author:"));
    }

    #[test]
    fn strips_image_markdown() {
        let md = "Some text\n\n![logo](https://cdn.example.com/img/logo.png)\n\nMore text";
        let result = make_output(md);
        let out = to_llm_text(&result);

        assert!(!out.contains("!["));
        assert!(!out.contains("cdn.example.com"));
        assert!(out.contains("Some text"));
        assert!(out.contains("More text"));
    }

    #[test]
    fn strips_bold_and_italic() {
        let md = "This is **bold text** and *italic text* and __also bold__ and _also italic_.";
        let result = make_output(md);
        let out = to_llm_text(&result);

        assert!(out.contains("This is bold text and italic text and also bold and also italic."));
        assert!(!out.contains("**"));
        assert!(!out.contains("__"));
    }

    #[test]
    fn moves_links_to_end() {
        let md = "Check out [Rust](https://rust-lang.org) and [Go](https://go.dev) for details.";
        let result = make_output(md);
        let out = to_llm_text(&result);

        assert!(out.contains("Check out Rust and Go for details."));
        assert!(out.contains("## Links"));
        assert!(out.contains("- Rust: https://rust-lang.org"));
        assert!(out.contains("- Go: https://go.dev"));
    }

    #[test]
    fn skips_anchor_and_javascript_links() {
        let md = "Go to [top](#top) and [click](javascript:void(0)) and [real](https://real.example.com).";
        let result = make_output(md);
        let out = to_llm_text(&result);

        assert!(out.contains("## Links"));
        assert!(out.contains("- real: https://real.example.com"));
        let links_section = out.split("## Links").nth(1).unwrap_or("");
        assert!(!links_section.contains("#top"));
        assert!(!links_section.contains("javascript:"));
    }

    #[test]
    fn collapses_excessive_whitespace() {
        let md = "Line one\n\n\n\n\nLine two\n\n\n\nLine three";
        let result = make_output(md);
        let out = to_llm_text(&result);

        assert!(
            !out.contains("\n\n\n"),
            "Found 3+ consecutive newlines in: {:?}",
            out
        );
    }

    #[test]
    fn preserves_code_blocks() {
        let md = "Example:\n\n```rust\nfn main() {\n    println!(\"hello\");\n}\n```\n\nDone.";
        let result = make_output(md);
        let out = to_llm_text(&result);

        assert!(out.contains("```rust"));
        assert!(out.contains("fn main()"));
        assert!(out.contains("```"));
    }

    #[test]
    fn preserves_list_structure() {
        let md = "Features:\n\n- Fast\n- Safe\n- Concurrent";
        let result = make_output(md);
        let out = to_llm_text(&result);

        assert!(out.contains("- Fast"));
        assert!(out.contains("- Safe"));
        assert!(out.contains("- Concurrent"));
    }

    #[test]
    fn deduplicates_links() {
        let md = "Visit [Example](https://example.org/page) or [Example again](https://example.org/page).";
        let result = make_output(md);
        let out = to_llm_text(&result);

        let link_count = out.matches("https://example.org/page").count();
        assert_eq!(link_count, 1, "Expected link once, got: {out}");
    }

    #[test]
    fn empty_metadata_fields_excluded() {
        let result = ReadOutput {
            title: String::new(),
            content: "Just content".into(),
            author: String::new(),
            excerpt: String::new(),
            url: String::new(),
            format: "llm".into(),
            length: 0,
            method: "direct".into(),
            elapsed_ms: 0,
            json_ld: vec![],
            og_image: String::new(),
            published_at: String::new(),
            modified_at: String::new(),
            section: String::new(),
            site_name: String::new(),
            tags: vec![],
            language: String::new(),
            error: None,
        };

        let out = to_llm_text(&result);
        assert!(!out.contains("> "), "metadata header leaked: {out}");
        assert!(out.contains("Just content"));
    }

    #[test]
    fn does_not_strip_emphasis_inside_code_blocks() {
        let md = "Normal **bold** text\n\n```python\ndef foo(**kwargs):\n    return _internal_var_\n```\n\nMore text";
        let result = make_output(md);
        let out = to_llm_text(&result);

        assert!(out.contains("Normal bold text"));
        assert!(out.contains("**kwargs"));
        assert!(out.contains("_internal_var_"));
    }

    #[test]
    fn converts_linked_images_to_links() {
        let md = "[![Read the docs](https://img.example.com/docs.png)](https://docs.example.com)";
        let result = make_output(md);
        let out = to_llm_text(&result);

        assert!(!out.contains("!["), "Image not converted: {out}");
        assert!(
            out.contains("https://docs.example.com"),
            "Link URL missing from footer: {out}"
        );
        assert!(out.contains("Read the docs"), "Link text missing: {out}");
    }

    // -- Structured-data gating tests --

    fn make_output_with_structured(values: Vec<serde_json::Value>) -> ReadOutput {
        let mut r = make_output("# Body");
        r.json_ld = values;
        r
    }

    #[test]
    fn structured_data_drops_chrome_types() {
        let r = make_output_with_structured(vec![serde_json::json!({
            "@type": "WebSite",
            "name": "Example",
            "url": "https://example.com"
        })]);
        let out = to_llm_text(&r);
        assert!(
            !out.contains("## Structured Data"),
            "WebSite chrome leaked into output: {out}"
        );
    }

    #[test]
    fn structured_data_keeps_article_types() {
        let r = make_output_with_structured(vec![serde_json::json!({
            "@type": "NewsArticle",
            "headline": "Big news",
            "datePublished": "2026-05-10"
        })]);
        let out = to_llm_text(&r);
        assert!(
            out.contains("## Structured Data"),
            "NewsArticle dropped: {out}"
        );
        assert!(out.contains("Big news"));
    }

    #[test]
    fn structured_data_scrubs_duplicate_article_body() {
        let body = "This is the rendered article body. ".repeat(40);
        let r = make_output_with_structured(vec![serde_json::json!({
            "@type": "NewsArticle",
            "headline": "Big news",
            "articleBody": body,
            "description": "A short useful summary"
        })]);
        let out = to_llm_text(&r);
        assert!(out.contains("Big news"));
        assert!(out.contains("A short useful summary"));
        assert!(
            !out.contains("articleBody"),
            "Duplicate article body leaked: {out}"
        );
    }

    #[test]
    fn structured_data_drops_oversized_blob() {
        let big = "x".repeat(32 * 1024);
        let r = make_output_with_structured(vec![serde_json::json!({
            "buildId": "abc",
            "isFallback": false,
            "noise": big
        })]);
        let out = to_llm_text(&r);
        assert!(
            !out.contains("## Structured Data"),
            "Oversized untyped blob leaked: len={}",
            out.len()
        );
    }

    #[test]
    fn structured_data_keeps_compact_untyped() {
        let r = make_output_with_structured(vec![serde_json::json!({
            "title": "Hi",
            "body": "small enough to keep"
        })]);
        let out = to_llm_text(&r);
        assert!(
            out.contains("## Structured Data"),
            "Compact untyped dropped: {out}"
        );
    }

    /// Walk `value` down its single `"n"` child link and return the depth
    /// at which an `articleBody` key is still present (i.e. was NOT
    /// scrubbed). Used to observe exactly where the recursion stopped.
    fn first_unscrubbed_article_body_depth(mut value: &serde_json::Value) -> Option<usize> {
        let mut depth = 0;
        loop {
            let obj = value.as_object()?;
            if obj.contains_key("articleBody") {
                return Some(depth);
            }
            value = obj.get("n")?;
            depth += 1;
        }
    }

    #[test]
    fn scrub_body_fields_bounds_recursion_on_deep_nesting() {
        const DEPTH: usize = 80;
        let mut node = serde_json::json!({ "articleBody": "x".repeat(600) });
        for _ in 0..DEPTH {
            node = serde_json::json!({
                "articleBody": "x".repeat(600),
                "n": node,
            });
        }

        scrub_body_fields(&mut node, 0);

        let stopped_at = first_unscrubbed_article_body_depth(&node)
            .expect("recursion must stop and leave a deep articleBody intact");
        assert_eq!(
            stopped_at, 64,
            "recursion should stop at the depth cap, stopped at {stopped_at}"
        );
        assert!(
            node.as_object().unwrap().get("articleBody").is_none(),
            "shallow articleBody must still be scrubbed"
        );
    }
}
