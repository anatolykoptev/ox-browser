//! Content extraction — shared types and pure functions.
//!
//! No HTTP, no async. Takes HTML string, returns clean content.

use serde::{Deserialize, Serialize};

/// Output format for content extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentFormat {
    #[default]
    Text,
    Markdown,
    Html,
    /// Token-optimized text for LLM consumption: strips images, emphasis,
    /// CSS/JS noise; moves links to a deduplicated footer; gates JSON-LD.
    /// See [`crate::llm::to_llm_text`].
    Llm,
}

impl ContentFormat {
    pub fn from_param(s: &str) -> Self {
        match s {
            "markdown" | "md" => Self::Markdown,
            "html" => Self::Html,
            "llm" => Self::Llm,
            _ => Self::Text,
        }
    }
}

/// Shared input params for read pipeline.
#[derive(Debug, Clone, Deserialize)]
pub struct ReadParams {
    pub url: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub max_length: usize,
    /// Per-call deadline in seconds. `None` → the seam default
    /// (`deadline::DEFAULT_CALL_TIMEOUT_SECS`); `Some(s)` → clamped to
    /// `[1, deadline::MAX_CALL_TIMEOUT_SECS]`. Bounds the WHOLE read
    /// pipeline (fetch + extract + solver escalation + rate-limit wait),
    /// not one attempt — issue #139. Same field/name/units/ceiling as
    /// `/fetch`'s `timeout`, the MCP `fetch`/`read` tools, and the CLI
    /// `--timeout` flag. The legacy `timeout_secs` spelling is accepted
    /// via a serde alias but is not the canonical name.
    #[serde(default, alias = "timeout_secs")]
    pub timeout: Option<u64>,
}

fn default_format() -> String {
    "text".into()
}

/// Shared output from read pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct ReadOutput {
    pub title: String,
    pub content: String,
    pub author: String,
    pub excerpt: String,
    pub url: String,
    pub format: String,
    pub length: usize,
    pub method: String,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub json_ld: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub og_image: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub published_at: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub modified_at: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub section: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub site_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Bounded token naming what happened during extraction, or `None` when
    /// extraction was accepted cleanly. Currently the only value is
    /// `extraction_rejected_low_text_ratio`: the post-extraction sanity gate
    /// (issue #110) found the extracted subtree held far less of the page's
    /// visible text than the source and rejected it, so `content` is the whole
    /// document converted to the requested format instead of the extracted
    /// subtree. Lets a caller distinguish a clean read from a gate fallback
    /// (the silent-200 failure mode). The rate is also exported as
    /// `oxbrowser_read_extraction_rejected_total`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extraction_note: Option<String>,
}

/// Article metadata extracted from HTML meta tags and JSON-LD.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArticleMeta {
    pub published_at: String,
    pub modified_at: String,
    pub section: String,
    pub site_name: String,
    pub tags: Vec<String>,
    pub language: String,
}

/// Extracted content (intermediate, before adding request metadata).
pub struct ExtractedContent {
    pub title: String,
    pub content: String,
    pub author: String,
    pub excerpt: String,
    pub length: usize,
    pub json_ld: Vec<serde_json::Value>,
    pub og_image: String,
    pub meta: ArticleMeta,
    /// Set when the post-extraction sanity gate rejected the extracted
    /// subtree and `content` was rebuilt from the whole document instead
    /// (issue #110). A bounded token (`extraction_rejected_low_text_ratio`)
    /// naming what happened, or `None` when extraction was accepted. Threaded
    /// through to `ReadOutput::extraction_note` so the caller can distinguish
    /// a clean extraction from a gate fallback — the silent-200 failure mode
    /// the issue is about.
    pub extraction_note: Option<String>,
}

// ─── Post-extraction sanity gate (issue #110) ───────────────────────────────
//
// Readability-style extraction assumes an *article*. On a list/index page
// there is no article, and the scorer settles on whatever scores least badly
// — empirically a hidden loading curtain on craigslist list pages, which
// carries ~50 chars of "loading reading writing saving searching" while the
// real 115+ listings sit in a sibling `<ol>` the extractor never selects.
// The caller gets HTTP 200, a plausible title, non-empty body, and no signal
// that 99% of the document was discarded.
//
// The gate compares visible text (not bytes — byte ratios are a function of
// markup bloat) of the source and the extracted subtree. A drastic shortfall
// means extraction discarded the real content; the whole document, converted
// to the requested format, is returned instead. On a list/index page the
// document *is* the content — the article abstraction does not apply and
// there is nothing better to select.
//
// Thresholds were chosen empirically against the fixtures in
// `crates/http/tests/fixtures/` (measured 2026-07-29 via
// `content_detect::visible_text_len`, char-based — see issue #110 L1):
//
//   fixture                          src_vis  ext_vis  ratio
//   craigslist.org_sfbay_fbh           17791       51  0.0029  ← trips
//   github.com_torvalds                 3589     1296  0.3611  ← nearest non-trip (Latin)
//   news.ycombinator.com_38765228        521      165  0.3167  ← critical band, non-trip
//   vercel.com                          3110     1443  0.4640
//   ja.wikipedia.org_buffett             845      563  0.6663  ← non-Latin, non-trip
//   www.bbc.com_news                    8965     6006  0.6699
//   nextjs.org                          6081     5909  0.9717
//   thin_page                            128      108  0.8438  ← below floor
//
// FRACTION = 0.10: craigslist (0.0029) is at 2.9% of the threshold (35× below,
// margin 0.097); the nearest non-tripping fixture, github.com_torvalds
// (0.3611), is 3.6× above (margin 0.261). The critical band [0.10, 0.36) is
// covered by news.ycombinator.com_38765228 (0.3167) — a real short page where
// the extractor captures a legitimate subset. Both margins are wide.
// FLOOR = 500 (char-based): thin_page (128) is at 25.6% of the floor (3.9×
// below, exempt); craigslist (17791) is 36× above (gated). A genuinely thin
// page (two paragraphs) never trips no matter what the ratio says. A non-Latin
// page crosses the floor at 500 codepoints, not 500 bytes — without char-based
// counting a CJK page would cross at ~167 chars (issue #110 L1).

/// Source visible text below this never trips the gate — a genuinely thin
/// page extracts normally regardless of the ratio. Measured margin: the
/// thin-page fixture (two paragraphs) has 128 visible chars, 3.9× below this.
///
/// # The floor is NOT redundant — do not delete it
///
/// An earlier draft of the PR body claimed the floor was unreachable because
/// `score_node` (extractor.rs) skips nodes under 50 chars, so a selected
/// subtree is always ≥ ~50 visible chars and `ext < src × 0.10` already
/// implies `src > 500`. That reasoning is wrong: `score_node` gates the
/// **extracted** node at 50 **bytes** (`text.len()`, extractor.rs:245-248),
/// not the source, and not visible chars. A sub-500-char source whose
/// extractor selects a ≥50-byte node whose visible text is under 10% of the
/// source would trip without the floor. The floor is reachable in principle;
/// what is missing is a fixture that exercises it, not the floor itself. Keep
/// it as defence against a future extractor change that returns smaller
/// subtrees, and against a source that is short but not thin-page-short.
const EXTRACTION_GATE_SOURCE_FLOOR: usize = 500;

/// Extracted visible text must be at least this fraction of source visible
/// text, or the gate trips. Measured margin: the bug fixture (craigslist
/// list page) extracts 0.29% of source (35× below this); the nearest
/// legitimate extraction (github.com_torvalds) captures 36% (3.6× above);
/// the critical band [0.10, 0.36) is covered by the HN thread fixture
/// (0.3167, non-trip).
const EXTRACTION_GATE_TEXT_FRACTION: f64 = 0.10;

/// Token placed in `ExtractedContent::extraction_note` / `ReadOutput::
/// extraction_note` when the gate trips. Bounded (not a free string) so it
/// is stable for metrics/log matching.
const EXTRACTION_GATE_REASON: &str = "extraction_rejected_low_text_ratio";

/// Post-extraction sanity gate (issue #110). Returns `Some(reason)` when the
/// extracted subtree holds far less of the page's visible text than the
/// source and the source is above the absolute floor — meaning extraction
/// discarded the real content and the caller should fall back to the whole
/// document. Returns `None` when extraction is accepted.
///
/// Both inputs are reduced to visible text (non-whitespace, excluding
/// `<script>`/`<style>`) via [`crate::content_detect::visible_text_len`];
/// comparing bytes would make the ratio a function of markup bloat and trip
/// on a well-extracted article inside a heavy page.
fn extraction_gate_trips(source_html: &str, extracted_html: &str) -> Option<&'static str> {
    let src = crate::content_detect::visible_text_len(source_html);
    if src < EXTRACTION_GATE_SOURCE_FLOOR {
        return None;
    }
    let ext = crate::content_detect::visible_text_len(extracted_html);
    if (ext as f64) < (src as f64) * EXTRACTION_GATE_TEXT_FRACTION {
        return Some(EXTRACTION_GATE_REASON);
    }
    None
}

/// Extract clean content from HTML.
pub fn extract_content(html: &str, url: &str, format: ContentFormat) -> ExtractedContent {
    if html.is_empty() {
        return ExtractedContent {
            title: String::new(),
            content: String::new(),
            author: String::new(),
            excerpt: String::new(),
            length: 0,
            json_ld: Vec::new(),
            og_image: String::new(),
            meta: ArticleMeta::default(),
            extraction_note: None,
        };
    }

    // Extract JSON-LD, og:image, and article metadata before content extraction.
    let json_ld = crate::json_ld::extract_json_ld(html);
    let og_image = extract_og_image(html);
    let meta = extract_article_meta(html, &json_ld);

    // Parse the document once — reused by extractor and SPA recovery.
    let doc = dom_query::Document::from(html);
    let base_url = url::Url::parse(url).ok();

    // Run the extractor: scores candidate nodes, picks the best, returns HTML.
    let extracted = crate::extractor::extract_content_html(&doc, base_url.as_ref());

    // Post-extraction sanity gate (issue #110): on a list/index page the
    // extractor picks a wrong container (e.g. a hidden loading curtain). If
    // the extracted subtree holds far less visible text than the source, reject
    // it and convert the whole document instead. One gate, one fallback, one
    // code path — applies to text/markdown/llm/html and to both the direct and
    // chrome-render fetch paths (both call this function).
    let (content_source_html, recovered_h1, extraction_note): (
        String,
        String,
        Option<&'static str>,
    ) = match extraction_gate_trips(html, &extracted.html) {
        Some(reason) => {
            crate::metrics::record_read_extraction_rejected();
            tracing::info!(
                reason = reason,
                "read extraction gate rejected subtree — falling back to whole document"
            );
            // Whole document: H1 recovery is unnecessary (the H1 is in the doc
            // and survives noise filtering for markdown, or is in the raw HTML
            // for the html format).
            (html.to_string(), String::new(), Some(reason))
        }
        None => (extracted.html, extracted.recovered_h1, None),
    };

    // Convert the content node HTML (or the whole document, on gate fallback)
    // to the requested format.
    //
    // NOTE: ContentFormat::Text does NOT get recovery passes (H1, hero
    // paragraph, announcements, section headings, footer CTA/sitemap).
    // These passes insert markdown-specific syntax (`# heading`, `**bold**`,
    // `[link](url)`) that has no plain-text equivalent. Text format gets
    // the raw content node converted to plain text — users who need the
    // recovered content should use Markdown or LLM format instead.
    // (Issue #73: documented asymmetry, intentional.)
    let mut content = match format {
        ContentFormat::Text => {
            let plain = html_to_plain(&content_source_html);
            if plain.is_empty() {
                html_to_plain(html)
            } else {
                plain
            }
        }
        ContentFormat::Llm | ContentFormat::Markdown => {
            let mut md = html_to_fit_markdown(&content_source_html);
            // Run recovery passes on markdown output (H1, hero, announcements,
            // section headings, footer CTA, footer sitemap).
            let mut links = Vec::new();
            crate::extractor::recover_content(
                &doc,
                base_url.as_ref(),
                &mut md,
                &recovered_h1,
                &mut links,
            );
            md
        }
        ContentFormat::Html => content_source_html.clone(),
    };

    // SPA content recovery: if DOM extraction is sparse, try data islands
    // and JS eval to recover content embedded in <script> tags.
    // Only applies to text/markdown/llm formats — HTML format is raw.
    // On a gate fallback the content is the whole document (not sparse), so
    // the internal word-count gate in recover_spa_content skips it — no
    // change needed here.
    if matches!(
        format,
        ContentFormat::Text | ContentFormat::Markdown | ContentFormat::Llm
    ) {
        recover_spa_content(html, &mut content);
    }

    let length = content.len();

    // Title: og:title → twitter:title → <title> tag (webclaw priority).
    // The recovered H1 is part of the content (prepended as a heading by
    // recover_content), not the page title — using it as title caused
    // wrong titles on pages where the H1 is a section heading or dialog
    // header (e.g., GitHub's "Provide feedback" h1).
    let title = extract_meta_content(html, "og:title")
        .or_else(|| extract_meta_content(html, "twitter:title"))
        .or_else(|| Some(extract_title_from_html(html)))
        .unwrap_or_default();

    // Byline: extract from JSON-LD author or meta tags.
    let author = json_ld_string(&json_ld, "author")
        .or_else(|| extract_meta_content(html, "author"))
        .or_else(|| extract_meta_content(html, "article:author"))
        .unwrap_or_default();

    // Excerpt: extract from meta description or JSON-LD description.
    let excerpt = extract_meta_content(html, "description")
        .or_else(|| extract_meta_content(html, "og:description"))
        .or_else(|| json_ld_string(&json_ld, "description"))
        .unwrap_or_default();

    ExtractedContent {
        title,
        content,
        author,
        excerpt,
        length,
        json_ld,
        og_image,
        meta,
        extraction_note: extraction_note.map(str::to_owned),
    }
}

/// Recover content from SPA data islands and inline JS when DOM extraction is sparse.
///
/// Runs only when the `quickjs` feature is enabled (default). Two passes:
/// 1. `data_island::try_extract` — static JSON in `<script type="application/json">`
/// 2. `js_eval::extract_js_data` — QuickJS sandbox executes inline `<script>` tags
///    to capture `window.__*` data blobs (Next.js `self.__next_f`, React state, etc.)
///
/// Both passes gate on a sparse threshold (word count < 500) and deduplicate
/// against the existing markdown to avoid adding content already in the DOM.
#[cfg(all(feature = "quickjs", not(target_arch = "wasm32")))]
fn recover_spa_content(html: &str, content: &mut String) {
    let dom_word_count: usize = content.split_whitespace().count();

    // Pass 1: static JSON data islands
    let doc = dom_query::Document::from(html);
    if let Some(island_md) = crate::data_island::try_extract(&doc, dom_word_count, content) {
        if !content.is_empty() {
            content.push_str("\n\n");
        }
        content.push_str(&island_md);
    }

    // Pass 2: QuickJS eval of inline scripts (only if markers are present)
    if crate::js_eval::has_js_candidate_data(html) {
        let blobs = crate::js_eval::extract_js_data_from_doc(&doc);
        if !blobs.is_empty() {
            let js_text = crate::js_eval::extract_readable_text(&blobs);
            if !js_text.is_empty() {
                if !content.is_empty() {
                    content.push_str("\n\n");
                }
                content.push_str(&js_text);
            }
        }
    }
}

/// No-op stub when the `quickjs` feature is disabled.
#[cfg(not(all(feature = "quickjs", not(target_arch = "wasm32"))))]
fn recover_spa_content(_html: &str, _content: &mut String) {}

/// Extract og:image URL from HTML meta tags.
fn extract_og_image(html: &str) -> String {
    // Look for <meta property="og:image" content="...">
    let needle = "property=\"og:image\"";
    let pos = html
        .find(needle)
        .or_else(|| html.find("property='og:image'"));
    let Some(pos) = pos else { return String::new() };

    // Search for content="..." nearby (within 200 chars)
    let end = html.floor_char_boundary(html.len().min(pos + 200));
    let slice = &html[pos..end];
    if let Some(c_start) = slice.find("content=\"") {
        let val_start = c_start + 9;
        if let Some(c_end) = slice[val_start..].find('"') {
            return slice[val_start..val_start + c_end].to_string();
        }
    }
    if let Some(c_start) = slice.find("content='") {
        let val_start = c_start + 9;
        if let Some(c_end) = slice[val_start..].find('\'') {
            return slice[val_start..val_start + c_end].to_string();
        }
    }
    String::new()
}

/// Large HTML + tiny extracted text = likely anti-bot page.
pub fn is_low_quality(html: &str, extracted_text: &str) -> bool {
    html.len() > 5_000 && extracted_text.len() < 100
}

/// HTTP status codes that trigger headless fallback.
pub fn should_fallback(status: u16) -> bool {
    matches!(status, 401 | 403 | 429 | 503)
}

/// Truncate at UTF-8 char boundary, append ellipsis.
pub fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut r = s[..end].to_string();
    r.push('…');
    r
}

fn extract_title_from_html(html: &str) -> String {
    let doc = dom_query::Document::from(html);
    doc.select("title").text().to_string().trim().to_string()
}

pub fn html_to_plain(html: &str) -> String {
    let doc = dom_query::Document::from(html);
    // Strip tags whose text content is never visible to a reader (inline JS,
    // CSS, `<noscript>` fallback). Without this, `body.text()` collects every
    // `NodeData::Text` descendant with no tag filter — so when the extraction
    // gate falls back to the whole document (issue #110), the Text output
    // carries inline script/style source. Markdown already strips these via
    // the same [`INVISIBLE_TAG_SELECTORS`] list; Text must too. One list, no
    // drift. (Nav/footer/header text IS visible to a reader and stays — only
    // the invisible tags are stripped here, unlike markdown which also drops
    // chrome via [`NOISE_SELECTORS`].)
    for sel in INVISIBLE_TAG_SELECTORS {
        doc.select(sel).remove();
    }
    let text = doc.select("body").text().to_string();
    collapse_whitespace(&text)
}

pub fn html_to_fit_markdown(html: &str) -> String {
    let doc = dom_query::Document::from(html);
    for sel in INVISIBLE_TAG_SELECTORS {
        doc.select(sel).remove();
    }
    for sel in NOISE_SELECTORS {
        doc.select(sel).remove();
    }
    // Second pass: DOM-level noise filter catches what CSS selectors can't
    // (partial class matches, ID prefixes, ARIA roles on non-standard elements,
    // hidden elements). Tailwind-safe: animation utilities are not noise.
    crate::noise::remove_noise(&doc);
    htmd::convert(&doc.html()).unwrap_or_default()
}

/// Tags whose text content is never visible to a reader — inline JS (`script`),
/// CSS (`style`), and `<noscript>` fallback. dom_query's `text_of` collects
/// every `NodeData::Text` descendant with no tag filter, so without stripping
/// these, `html_to_plain` leaks inline script/style source when the extraction
/// gate falls back to the whole document (issue #110). Shared by
/// `html_to_plain` and `html_to_fit_markdown` so the two formats cannot drift
/// on which invisible tags they strip.
const INVISIBLE_TAG_SELECTORS: &[&str] = &["script", "style", "noscript"];

fn collapse_whitespace(s: &str) -> String {
    let mut r = String::with_capacity(s.len());
    let mut prev = true;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !prev {
                r.push(' ');
                prev = true;
            }
        } else {
            r.push(ch);
            prev = false;
        }
    }
    r.trim().to_string()
}

/// Boilerplate/chrome selectors stripped by `html_to_fit_markdown` (in
/// addition to [`INVISIBLE_TAG_SELECTORS`]). Not applied to plain-text output
/// — nav/footer/header text is visible to a reader and belongs in Text.
pub const NOISE_SELECTORS: &[&str] = &[
    "nav",
    "footer",
    "header",
    ".nav",
    ".navbar",
    ".footer",
    ".sidebar",
    ".menu",
    ".breadcrumb",
    ".pagination",
    ".cookie-banner",
    ".cookie-consent",
    "#cookie-banner",
    "[role=navigation]",
    "[role=banner]",
    "[role=contentinfo]",
    "iframe",
];

/// Extract article metadata from HTML meta tags and JSON-LD.
///
/// Checks multiple sources for each field (meta tags, JSON-LD, HTML attributes)
/// to maximize extraction success across different sites.
#[allow(clippy::field_reassign_with_default)] // per-field assignment with source comments reads better than a giant struct literal
fn extract_article_meta(html: &str, json_ld: &[serde_json::Value]) -> ArticleMeta {
    let mut meta = ArticleMeta::default();

    // 1. published_at — try multiple sources
    // Source: <meta property="article:published_time">
    meta.published_at = extract_meta_content(html, "article:published_time")
        // Source: <meta name="date">
        .or_else(|| extract_meta_content(html, "date"))
        // Source: <meta name="pubdate">
        .or_else(|| extract_meta_content(html, "pubdate"))
        // Source: <meta name="dc.date">
        .or_else(|| extract_meta_content(html, "dc.date"))
        // Source: <meta name="sailthru.date">
        .or_else(|| extract_meta_content(html, "sailthru.date"))
        // Source: <time datetime="..."> (first occurrence)
        .or_else(|| extract_time_datetime(html))
        // Source: JSON-LD datePublished
        .or_else(|| json_ld_string(json_ld, "datePublished"))
        .unwrap_or_default();

    // 2. modified_at
    meta.modified_at = extract_meta_content(html, "article:modified_time")
        .or_else(|| json_ld_string(json_ld, "dateModified"))
        .unwrap_or_default();

    // 3. section / category
    meta.section = extract_meta_content(html, "article:section")
        .or_else(|| json_ld_string(json_ld, "articleSection"))
        .unwrap_or_default();

    // 4. site_name
    meta.site_name = extract_meta_content(html, "og:site_name")
        .or_else(|| json_ld_string(json_ld, "publisher"))
        .unwrap_or_default();

    // 5. tags
    let mut tags = Vec::new();
    // Source: multiple <meta property="article:tag"> values
    for tag in extract_all_meta_content(html, "article:tag") {
        if !tag.is_empty() {
            tags.push(tag);
        }
    }
    // Source: JSON-LD keywords (comma-separated string or array)
    if tags.is_empty()
        && let Some(kw) = json_ld_string(json_ld, "keywords")
    {
        for tag in kw.split(',') {
            let t = tag.trim().to_string();
            if !t.is_empty() {
                tags.push(t);
            }
        }
    }
    // Source: <meta name="keywords">
    if tags.is_empty()
        && let Some(kw) = extract_meta_content(html, "keywords")
    {
        for tag in kw.split(',') {
            let t = tag.trim().to_string();
            if !t.is_empty() {
                tags.push(t);
            }
        }
    }
    meta.tags = tags;

    // 6. language
    meta.language = extract_meta_content(html, "og:locale")
        .or_else(|| extract_html_lang(html))
        .or_else(|| extract_meta_content(html, "content-language"))
        .or_else(|| json_ld_string(json_ld, "inLanguage"))
        .unwrap_or_default();

    meta
}

/// Extract content attribute from a meta tag by property or name.
fn extract_meta_content(html: &str, attr_value: &str) -> Option<String> {
    // Try property="..." first, then name="..."
    for attr in &["property", "name"] {
        let needle = format!("{attr}=\"{attr_value}\"");
        if let Some(pos) = html.find(&needle) {
            let end = html.floor_char_boundary(html.len().min(pos + 300));
            let slice = &html[pos..end];
            if let Some(val) = extract_content_attr(slice)
                && !val.is_empty()
            {
                return Some(val);
            }
        }
        // Also try single quotes
        let needle_sq = format!("{attr}='{attr_value}'");
        if let Some(pos) = html.find(&needle_sq) {
            let end = html.floor_char_boundary(html.len().min(pos + 300));
            let slice = &html[pos..end];
            if let Some(val) = extract_content_attr(slice)
                && !val.is_empty()
            {
                return Some(val);
            }
        }
    }
    None
}

/// Extract all content attributes for a given meta property (for multi-value tags like article:tag).
fn extract_all_meta_content(html: &str, attr_value: &str) -> Vec<String> {
    let needle = format!("property=\"{attr_value}\"");
    let mut results = Vec::new();
    let mut search_from = 0;
    while let Some(pos) = html[search_from..].find(&needle) {
        let abs_pos = search_from + pos;
        let end = html.floor_char_boundary(html.len().min(abs_pos + 300));
        let slice = &html[abs_pos..end];
        if let Some(val) = extract_content_attr(slice)
            && !val.is_empty()
        {
            results.push(val);
        }
        search_from = abs_pos + needle.len();
    }
    results
}

/// Extract content="..." attribute value from a meta tag slice.
fn extract_content_attr(slice: &str) -> Option<String> {
    if let Some(c_start) = slice.find("content=\"") {
        let val_start = c_start + 9;
        if let Some(c_end) = slice[val_start..].find('"') {
            return Some(slice[val_start..val_start + c_end].to_string());
        }
    }
    if let Some(c_start) = slice.find("content='") {
        let val_start = c_start + 9;
        if let Some(c_end) = slice[val_start..].find('\'') {
            return Some(slice[val_start..val_start + c_end].to_string());
        }
    }
    None
}

/// Extract datetime from the first <time datetime="..."> tag.
fn extract_time_datetime(html: &str) -> Option<String> {
    let needle = "datetime=\"";
    let pos = html.find(needle)?;
    let val_start = pos + needle.len();
    let c_end = html[val_start..].find('"')?;
    let val = &html[val_start..val_start + c_end];
    if val.len() >= 10 {
        Some(val.to_string())
    } else {
        None
    }
}

/// Extract lang attribute from <html lang="...">.
fn extract_html_lang(html: &str) -> Option<String> {
    let needle = "<html";
    let pos = html.find(needle)?;
    let end = html.floor_char_boundary(html.len().min(pos + 200));
    let slice = &html[pos..end];
    if let Some(l_start) = slice.find("lang=\"") {
        let val_start = l_start + 6;
        if let Some(l_end) = slice[val_start..].find('"') {
            let val = slice[val_start..val_start + l_end].to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Extract a string field from JSON-LD objects.
fn json_ld_string(json_ld: &[serde_json::Value], field: &str) -> Option<String> {
    for obj in json_ld {
        // Direct field
        if let Some(val) = obj.get(field).and_then(|v| v.as_str())
            && !val.is_empty()
        {
            return Some(val.to_string());
        }
        // For "publisher" — may be an object with "name"
        if field == "publisher"
            && let Some(pub_obj) = obj.get("publisher")
            && let Some(name) = pub_obj.get("name").and_then(|v| v.as_str())
        {
            return Some(name.to_string());
        }
        // For "keywords" — may be an array
        if field == "keywords"
            && let Some(arr) = obj.get("keywords").and_then(|v| v.as_array())
        {
            let kw: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if !kw.is_empty() {
                return Some(kw.join(", "));
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "content_tests.rs"]
mod tests;
