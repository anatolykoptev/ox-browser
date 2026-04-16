//! Content extraction — shared types and pure functions.
//!
//! No HTTP, no async. Takes HTML string, returns clean content.

use readabilityrs::Readability;
use serde::{Deserialize, Serialize};

/// Output format for content extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentFormat {
    #[default]
    Text,
    Markdown,
    Html,
}

impl ContentFormat {
    pub fn from_param(s: &str) -> Self {
        match s {
            "markdown" | "md" => Self::Markdown,
            "html" => Self::Html,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    // Extract JSON-LD, og:image, and article metadata before readability strips meta tags.
    let json_ld = crate::json_ld::extract_json_ld(html);
    let og_image = extract_og_image(html);
    let meta = extract_article_meta(html, &json_ld);

    let article = Readability::new(html, Some(url), None)
        .ok()
        .and_then(|r| r.parse());

    match article {
        Some(a) => {
            let raw = a.content.unwrap_or_default();
            let content = match format {
                ContentFormat::Text => {
                    let tc = collapse_whitespace(&a.text_content.unwrap_or_default());
                    if tc.is_empty() { html_to_plain(&raw) } else { tc }
                }
                _ => convert_format(&raw, format),
            };
            let length = content.len();
            let title = a.title.unwrap_or_else(|| extract_title_from_html(html));
            ExtractedContent {
                title,
                content,
                author: a.byline.unwrap_or_default(),
                excerpt: a.excerpt.unwrap_or_default(),
                length,
                json_ld,
                og_image,
                meta,
            }
        }
        None => {
            let content = convert_format(html, format);
            let length = content.len();
            let title = extract_title_from_html(html);
            ExtractedContent {
                title,
                content,
                author: String::new(),
                excerpt: String::new(),
                length,
                json_ld,
                og_image,
                meta,
            }
        }
    }}

/// Extract og:image URL from HTML meta tags.
fn extract_og_image(html: &str) -> String {
    // Look for <meta property="og:image" content="...">
    let needle = "property=\"og:image\"";
    let pos = html.find(needle).or_else(|| html.find("property='og:image'"));
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

fn convert_format(html: &str, format: ContentFormat) -> String {
    match format {
        ContentFormat::Text => html_to_plain(html),
        ContentFormat::Markdown => html_to_fit_markdown(html),
        ContentFormat::Html => html.to_string(),
    }
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
    "nav", "footer", "header", ".nav", ".navbar", ".footer", ".sidebar",
    ".menu", ".breadcrumb", ".pagination", ".cookie-banner", ".cookie-consent",
    "#cookie-banner", "[role=navigation]", "[role=banner]", "[role=contentinfo]",
    "script", "style", "noscript", "iframe",
];

impl Default for ArticleMeta {
    fn default() -> Self {
        Self {
            published_at: String::new(),
            modified_at: String::new(),
            section: String::new(),
            site_name: String::new(),
            tags: Vec::new(),
            language: String::new(),
        }
    }
}

/// Extract article metadata from HTML meta tags and JSON-LD.
///
/// Checks multiple sources for each field (meta tags, JSON-LD, HTML attributes)
/// to maximize extraction success across different sites.
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
    if tags.is_empty() {
        if let Some(kw) = json_ld_string(json_ld, "keywords") {
            for tag in kw.split(',') {
                let t = tag.trim().to_string();
                if !t.is_empty() {
                    tags.push(t);
                }
            }
        }
    }
    // Source: <meta name="keywords">
    if tags.is_empty() {
        if let Some(kw) = extract_meta_content(html, "keywords") {
            for tag in kw.split(',') {
                let t = tag.trim().to_string();
                if !t.is_empty() {
                    tags.push(t);
                }
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
            if let Some(val) = extract_content_attr(slice) {
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
        // Also try single quotes
        let needle_sq = format!("{attr}='{attr_value}'");
        if let Some(pos) = html.find(&needle_sq) {
            let end = html.floor_char_boundary(html.len().min(pos + 300));
            let slice = &html[pos..end];
            if let Some(val) = extract_content_attr(slice) {
                if !val.is_empty() {
                    return Some(val);
                }
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
        if let Some(val) = extract_content_attr(slice) {
            if !val.is_empty() {
                results.push(val);
            }
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
        if let Some(val) = obj.get(field).and_then(|v| v.as_str()) {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
        // For "publisher" — may be an object with "name"
        if field == "publisher" {
            if let Some(pub_obj) = obj.get("publisher") {
                if let Some(name) = pub_obj.get("name").and_then(|v| v.as_str()) {
                    return Some(name.to_string());
                }
            }
        }
        // For "keywords" — may be an array
        if field == "keywords" {
            if let Some(arr) = obj.get("keywords").and_then(|v| v.as_array()) {
                let kw: Vec<String> = arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                if !kw.is_empty() {
                    return Some(kw.join(", "));
                }
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "content_tests.rs"]
mod tests;
