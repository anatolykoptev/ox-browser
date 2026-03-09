//! Image extraction from HTML (methods 1-4).
//!
//! Extracts `og:image`, `<img>`, `<picture><source>`, and CSS background-image URLs.

use std::collections::HashSet;
use dom_query::Document;
use url::Url;
use super::{ExtractedMedia, MediaKind, resolve_url};
use super::helpers::{should_skip, parse_dimension, extract_og_title, best_srcset_url, extract_bg_urls};

/// Minimum dimension (width or height) to keep an image.
const MIN_DIMENSION: u32 = 200;

/// Run all image extraction methods and append to results.
pub(crate) fn extract_images(
    doc: &Document,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    extract_og_images(doc, base_url, base, seen, results);
    extract_img_tags(doc, base_url, base, seen, results);
    extract_picture_sources(doc, base_url, base, seen, results);
    extract_bg_images(doc, base_url, base, seen, results);
}

/// 1. og:image meta tags.
fn extract_og_images(
    doc: &Document,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    for node in doc.select("meta[property='og:image']").iter() {
        if let Some(content) = node.attr("content") {
            let url = resolve_url(content.as_ref(), base);
            if !url.is_empty() && seen.insert(url.clone()) && !should_skip(&url) {
                results.push(ExtractedMedia {
                    url,
                    source: base_url.to_string(),
                    title: extract_og_title(doc),
                    width: 0,
                    height: 0,
                    media_kind: MediaKind::Image,
                });
            }
        }
    }
}

/// 2. `<img>` tags with src/srcset.
fn extract_img_tags(
    doc: &Document,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    for node in doc.select("img").iter() {
        let src = node.attr("src").map(|s| s.to_string());
        let srcset = node.attr("srcset").map(|s| s.to_string());
        let alt = node
            .attr("alt")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let w = parse_dimension(&node.attr("width").unwrap_or_default());
        let h = parse_dimension(&node.attr("height").unwrap_or_default());

        let best_url = best_srcset_url(&srcset, base)
            .or_else(|| src.map(|s| resolve_url(&s, base)))
            .unwrap_or_default();

        if best_url.is_empty() || !seen.insert(best_url.clone()) {
            continue;
        }
        if should_skip(&best_url) {
            continue;
        }
        if (w > 0 && w < MIN_DIMENSION) && (h > 0 && h < MIN_DIMENSION) {
            continue;
        }

        results.push(ExtractedMedia {
            url: best_url,
            source: base_url.to_string(),
            title: alt,
            width: w,
            height: h,
            media_kind: MediaKind::Image,
        });
    }
}

/// 3. `<picture><source>` srcset.
fn extract_picture_sources(
    doc: &Document,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    for node in doc.select("picture > source[srcset]").iter() {
        let srcset = node.attr("srcset").map(|s| s.to_string());
        if let Some(url) = best_srcset_url(&srcset, base) {
            if !url.is_empty() && seen.insert(url.clone()) && !should_skip(&url) {
                results.push(ExtractedMedia {
                    url,
                    source: base_url.to_string(),
                    title: String::new(),
                    width: 0,
                    height: 0,
                    media_kind: MediaKind::Image,
                });
            }
        }
    }
}

/// 4. CSS `background-image: url(...)` in style attributes.
fn extract_bg_images(
    doc: &Document,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    for node in doc.select("[style]").iter() {
        if let Some(style) = node.attr("style") {
            for url in extract_bg_urls(style.as_ref(), base) {
                if seen.insert(url.clone()) && !should_skip(&url) {
                    results.push(ExtractedMedia {
                        url,
                        source: base_url.to_string(),
                        title: String::new(),
                        width: 0,
                        height: 0,
                        media_kind: MediaKind::Image,
                    });
                }
            }
        }
    }
}
