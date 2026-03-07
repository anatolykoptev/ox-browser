//! Extract candidate images from HTML page.
//!
//! Parses `<img>`, `<picture><source>`, `og:image`, and CSS background-image
//! URLs. Filters out logos, icons, SVGs, GIFs, and tiny images.

use std::collections::HashSet;

use dom_query::Document;
use url::Url;

use crate::ImageResult;

/// Patterns in URL path that indicate non-photo images.
const SKIP_PATTERNS: &[&str] = &[
    "/logo", "/icon", "/favicon", "/sprite", "/avatar",
    "/badge", "/banner-ad", "/pixel", "/tracking",
    "/spacer", "/blank", "/loading", "/spinner",
    "/emoji", "/smiley", "/button",
    "mc.yandex.ru/watch", "google-analytics.com",
    "facebook.com/tr", "doubleclick.net",
];

/// File extensions to skip.
const SKIP_EXTENSIONS: &[&str] = &["svg", "gif", "ico", "cur", "bmp"];

/// Minimum dimension (width or height) to keep an image.
const MIN_DIMENSION: u32 = 200;

/// Extract candidate photo URLs from HTML, resolving relative URLs against base.
pub fn extract_images(html: &str, base_url: &str) -> Vec<ImageResult> {
    let doc = Document::from(html);
    let base = Url::parse(base_url).ok();
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    // 1. og:image (highest priority — curated by site owner)
    for node in doc.select("meta[property='og:image']").iter() {
        if let Some(content) = node.attr("content") {
            let url = resolve_url(content.as_ref(), &base);
            if !url.is_empty() && seen.insert(url.clone()) && !should_skip(&url) {
                results.push(ImageResult {
                    url,
                    thumbnail: String::new(),
                    source: base_url.to_string(),
                    title: extract_og_title(&doc),
                    width: 0,
                    height: 0,
                    engine: "extract".into(),
                });
            }
        }
    }

    // 2. <img> tags
    for node in doc.select("img").iter() {
        let src = node.attr("src").map(|s| s.to_string());
        let srcset = node.attr("srcset").map(|s| s.to_string());
        let alt = node
            .attr("alt")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let w = parse_dimension(&node.attr("width").unwrap_or_default());
        let h = parse_dimension(&node.attr("height").unwrap_or_default());

        // Prefer largest srcset candidate
        let best_url = best_srcset_url(&srcset, &base)
            .or_else(|| src.map(|s| resolve_url(&s, &base)))
            .unwrap_or_default();

        if best_url.is_empty() || !seen.insert(best_url.clone()) {
            continue;
        }
        if should_skip(&best_url) {
            continue;
        }
        // Skip if dimensions are known and too small
        if (w > 0 && w < MIN_DIMENSION) && (h > 0 && h < MIN_DIMENSION) {
            continue;
        }

        results.push(ImageResult {
            url: best_url,
            thumbnail: String::new(),
            source: base_url.to_string(),
            title: alt,
            width: w,
            height: h,
            engine: "extract".into(),
        });
    }

    // 3. <picture><source> — srcset with type preference (webp > jpeg)
    for node in doc.select("picture > source[srcset]").iter() {
        let srcset = node.attr("srcset").map(|s| s.to_string());
        if let Some(url) = best_srcset_url(&srcset, &base) {
            if !url.is_empty() && seen.insert(url.clone()) && !should_skip(&url) {
                results.push(ImageResult {
                    url,
                    thumbnail: String::new(),
                    source: base_url.to_string(),
                    title: String::new(),
                    width: 0,
                    height: 0,
                    engine: "extract".into(),
                });
            }
        }
    }

    // 4. CSS background-image in style attributes
    for node in doc.select("[style]").iter() {
        if let Some(style) = node.attr("style") {
            for url in extract_bg_urls(style.as_ref(), &base) {
                if seen.insert(url.clone()) && !should_skip(&url) {
                    results.push(ImageResult {
                        url,
                        thumbnail: String::new(),
                        source: base_url.to_string(),
                        title: String::new(),
                        width: 0,
                        height: 0,
                        engine: "extract".into(),
                    });
                }
            }
        }
    }

    results
}

fn resolve_url(src: &str, base: &Option<Url>) -> String {
    let trimmed = src.trim();
    if trimmed.starts_with("data:") {
        return String::new();
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    if let Some(base) = base {
        if let Ok(resolved) = base.join(trimmed) {
            return resolved.to_string();
        }
    }
    String::new()
}

fn should_skip(url: &str) -> bool {
    let lower = url.to_lowercase();

    // Skip by extension
    let path = lower.split('?').next().unwrap_or(&lower);
    for ext in SKIP_EXTENSIONS {
        if path.ends_with(&format!(".{ext}")) {
            return true;
        }
    }

    // Skip by path pattern
    for pat in SKIP_PATTERNS {
        if lower.contains(pat) {
            return true;
        }
    }

    false
}

fn parse_dimension(s: &str) -> u32 {
    s.trim().trim_end_matches("px").parse().unwrap_or(0)
}

fn extract_og_title(doc: &Document) -> String {
    doc.select("meta[property='og:title']")
        .iter()
        .next()
        .and_then(|n| n.attr("content").map(|s| s.to_string()))
        .unwrap_or_default()
}

/// Parse srcset and return the URL of the largest candidate.
fn best_srcset_url(srcset: &Option<String>, base: &Option<Url>) -> Option<String> {
    let srcset = srcset.as_deref()?;
    let mut best_url = String::new();
    let mut best_w: u32 = 0;

    for candidate in srcset.split(',') {
        let parts: Vec<&str> = candidate.trim().split_whitespace().collect();
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
fn extract_bg_urls(style: &str, base: &Option<Url>) -> Vec<String> {
    let mut urls = Vec::new();
    let lower = style.to_lowercase();
    let mut search = &lower[..];
    while let Some(pos) = search.find("url(") {
        let start = pos + 4;
        let rest = &style[start..]; // use original case
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_og_image() {
        let html = r#"<html><head>
            <meta property="og:image" content="https://example.com/hero.jpg"/>
            <meta property="og:title" content="Test Place"/>
        </head><body></body></html>"#;
        let results = extract_images(html, "https://example.com/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/hero.jpg");
        assert_eq!(results[0].title, "Test Place");
        assert_eq!(results[0].engine, "extract");
    }

    #[test]
    fn extract_img_tags() {
        let html = r#"<html><body>
            <img src="https://example.com/photo1.jpg" width="1024" height="768" alt="Photo 1">
            <img src="https://example.com/photo2.webp" width="800" height="600">
            <img src="/logo.png" width="100" height="50">
            <img src="icon.svg">
        </body></html>"#;
        let results = extract_images(html, "https://example.com/page");
        // logo.png skipped (pattern), icon.svg skipped (extension),
        // logo.png also small (100x50 both < 200)
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].url, "https://example.com/photo1.jpg");
        assert_eq!(results[0].width, 1024);
        assert_eq!(results[0].title, "Photo 1");
    }

    #[test]
    fn extract_relative_urls() {
        let html = r#"<html><body>
            <img src="/uploads/photo.jpg" width="800" height="600">
        </body></html>"#;
        let results = extract_images(html, "https://example.com/about/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/uploads/photo.jpg");
    }

    #[test]
    fn extract_srcset_largest() {
        let html = r#"<html><body>
            <img src="small.jpg" srcset="medium.jpg 800w, large.jpg 1600w">
        </body></html>"#;
        let results = extract_images(html, "https://example.com/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/large.jpg");
    }

    #[test]
    fn extract_background_image() {
        let html = r#"<html><body>
            <div style="background-image: url('https://example.com/bg.jpg')"></div>
        </body></html>"#;
        let results = extract_images(html, "https://example.com/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/bg.jpg");
    }

    #[test]
    fn skip_data_urls() {
        let html = r#"<html><body>
            <img src="data:image/gif;base64,R0lGODlhAQ">
            <img src="https://example.com/real.jpg">
        </body></html>"#;
        let results = extract_images(html, "https://example.com/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/real.jpg");
    }

    #[test]
    fn dedup_same_url() {
        let html = r#"<html><head>
            <meta property="og:image" content="https://example.com/hero.jpg"/>
        </head><body>
            <img src="https://example.com/hero.jpg">
        </body></html>"#;
        let results = extract_images(html, "https://example.com/");
        assert_eq!(results.len(), 1); // deduped
    }

    #[test]
    fn skip_tracking_pixels() {
        let html = r#"<html><body>
            <img src="https://tracker.com/pixel.png" width="1" height="1">
            <img src="https://example.com/photo.jpg" width="800" height="600">
        </body></html>"#;
        let results = extract_images(html, "https://example.com/");
        // pixel has /pixel pattern AND 1x1 dimensions
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/photo.jpg");
    }
}
