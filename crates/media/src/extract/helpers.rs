//! Shared helper functions for image extraction.

use url::Url;

use super::resolve_url;

/// Patterns in URL path that indicate non-photo images.
const SKIP_PATTERNS: &[&str] = &[
    "/logo",
    "/icon",
    "/favicon",
    "/sprite",
    "/avatar",
    "/badge",
    "/banner-ad",
    "/pixel",
    "/tracking",
    "/spacer",
    "/blank",
    "/loading",
    "/spinner",
    "/emoji",
    "/smiley",
    "/button",
    "mc.yandex.ru/watch",
    "google-analytics.com",
    "facebook.com/tr",
    "doubleclick.net",
];

/// File extensions to skip.
const SKIP_EXTENSIONS: &[&str] = &["svg", "gif", "ico", "cur", "bmp"];

/// Check if an image URL should be skipped (tracking, icons, etc.).
pub(crate) fn should_skip(url: &str) -> bool {
    let lower = url.to_lowercase();

    let path = lower.split('?').next().unwrap_or(&lower);
    for ext in SKIP_EXTENSIONS {
        if path.ends_with(&format!(".{ext}")) {
            return true;
        }
    }

    for pat in SKIP_PATTERNS {
        if lower.contains(pat) {
            return true;
        }
    }

    false
}

/// Parse a dimension string like "1024" or "800px" into u32.
pub(crate) fn parse_dimension(s: &str) -> u32 {
    s.trim().trim_end_matches("px").parse().unwrap_or(0)
}

/// Extract og:title from document.
pub(crate) fn extract_og_title(doc: &dom_query::Document) -> String {
    doc.select("meta[property='og:title']")
        .iter()
        .next()
        .and_then(|n| n.attr("content").map(|s| s.to_string()))
        .unwrap_or_default()
}

/// Parse srcset and return the URL of the largest candidate.
pub(crate) fn best_srcset_url(srcset: &Option<String>, base: &Option<Url>) -> Option<String> {
    let srcset = srcset.as_deref()?;
    let mut best_url = String::new();
    let mut best_w: u32 = 0;

    for candidate in srcset.split(',') {
        let parts: Vec<&str> = candidate.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let url = resolve_url(parts[0], base);
        if url.is_empty() {
            continue;
        }
        let w = parts
            .get(1)
            .and_then(|d| d.trim_end_matches('w').parse::<u32>().ok())
            .unwrap_or(1);
        if w >= best_w {
            best_w = w;
            best_url = url;
        }
    }

    if best_url.is_empty() {
        None
    } else {
        Some(best_url)
    }
}

/// Extract URLs from `background-image: url(...)` in inline style.
pub(crate) fn extract_bg_urls(style: &str, base: &Option<Url>) -> Vec<String> {
    let mut urls = Vec::new();
    let lower = style.to_lowercase();
    let mut search = &lower[..];
    while let Some(pos) = search.find("url(") {
        let start = pos + 4;
        let rest = &style[start..];
        let end = rest.find(')').unwrap_or(rest.len());
        let raw = rest[..end].trim().trim_matches(|c| c == '\'' || c == '"');
        let url = resolve_url(raw, base);
        if !url.is_empty() {
            urls.push(url);
        }
        search = &lower[start + end..];
    }
    urls
}
