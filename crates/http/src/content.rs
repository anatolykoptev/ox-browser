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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Extracted content (intermediate, before adding request metadata).
pub struct ExtractedContent {
    pub title: String,
    pub content: String,
    pub author: String,
    pub excerpt: String,
    pub length: usize,
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
        };
    }
    let article = Readability::new(html, Some(url), None)
        .ok()
        .and_then(|r| r.parse());

    match article {
        Some(a) => {
            let raw = a.content.unwrap_or_default();
            let content = match format {
                ContentFormat::Text => a.text_content.unwrap_or_else(|| html_to_plain(&raw)),
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
            }
        }
    }
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

#[cfg(test)]
#[path = "content_tests.rs"]
mod tests;
