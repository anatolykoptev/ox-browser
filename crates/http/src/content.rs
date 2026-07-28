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

    // Convert the content node HTML to the requested format.
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
            let plain = html_to_plain(&extracted.html);
            if plain.is_empty() {
                html_to_plain(html)
            } else {
                plain
            }
        }
        ContentFormat::Llm | ContentFormat::Markdown => {
            let mut md = html_to_fit_markdown(&extracted.html);
            // Run recovery passes on markdown output (H1, hero, announcements,
            // section headings, footer CTA, footer sitemap).
            let mut links = Vec::new();
            crate::extractor::recover_content(
                &doc,
                base_url.as_ref(),
                &mut md,
                &extracted.recovered_h1,
                &mut links,
            );
            md
        }
        ContentFormat::Html => extracted.html.clone(),
    };

    // SPA content recovery: if DOM extraction is sparse, try data islands
    // and JS eval to recover content embedded in <script> tags.
    // Only applies to text/markdown/llm formats — HTML format is raw.
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
    let text = doc.select("body").text().to_string();
    collapse_whitespace(&text)
}

pub fn html_to_fit_markdown(html: &str) -> String {
    let doc = dom_query::Document::from(html);
    for sel in NOISE_SELECTORS {
        doc.select(sel).remove();
    }
    // Second pass: DOM-level noise filter catches what CSS selectors can't
    // (partial class matches, ID prefixes, ARIA roles on non-standard elements,
    // hidden elements). Tailwind-safe: animation utilities are not noise.
    crate::noise::remove_noise(&doc);
    htmd::convert(&doc.html()).unwrap_or_default()
}

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
    "script",
    "style",
    "noscript",
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
