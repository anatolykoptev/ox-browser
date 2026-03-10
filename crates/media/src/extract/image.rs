//! Image extraction from HTML (methods 1-4).
//!
//! Extracts `og:image`, `<img>`, `<picture><source>`, and CSS background-image URLs.

use super::{ExtractContext, ExtractedMedia, MediaKind, resolve_url};
use super::helpers::{should_skip, parse_dimension, extract_og_title, best_srcset_url, extract_bg_urls};

/// Minimum dimension (width or height) to keep an image.
const MIN_DIMENSION: u32 = 200;

/// Run all image extraction methods and append to results.
pub(crate) fn extract_images(ctx: &mut ExtractContext) {
    extract_og_images(ctx);
    extract_img_tags(ctx);
    extract_picture_sources(ctx);
    extract_bg_images(ctx);
}

/// 1. og:image meta tags.
fn extract_og_images(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("meta[property='og:image']").iter() {
        if let Some(content) = node.attr("content") {
            let url = resolve_url(content.as_ref(), ctx.base);
            if !url.is_empty() && ctx.seen.insert(url.clone()) && !should_skip(&url) {
                ctx.results.push(ExtractedMedia {
                    url,
                    source: ctx.base_url.to_string(),
                    title: extract_og_title(ctx.doc),
                    width: 0,
                    height: 0,
                    media_kind: MediaKind::Image,
                });
            }
        }
    }
}

/// 2. `<img>` tags with src/srcset.
fn extract_img_tags(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("img").iter() {
        let src = node.attr("src").map(|s| s.to_string());
        let srcset = node.attr("srcset").map(|s| s.to_string());
        let alt = node
            .attr("alt")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let w = parse_dimension(&node.attr("width").unwrap_or_default());
        let h = parse_dimension(&node.attr("height").unwrap_or_default());

        let best_url = best_srcset_url(&srcset, ctx.base)
            .or_else(|| src.map(|s| resolve_url(&s, ctx.base)))
            .unwrap_or_default();

        if best_url.is_empty() || !ctx.seen.insert(best_url.clone()) {
            continue;
        }
        if should_skip(&best_url) {
            continue;
        }
        if (w > 0 && w < MIN_DIMENSION) && (h > 0 && h < MIN_DIMENSION) {
            continue;
        }

        ctx.results.push(ExtractedMedia {
            url: best_url,
            source: ctx.base_url.to_string(),
            title: alt,
            width: w,
            height: h,
            media_kind: MediaKind::Image,
        });
    }
}

/// 3. `<picture><source>` srcset.
fn extract_picture_sources(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("picture > source[srcset]").iter() {
        let srcset = node.attr("srcset").map(|s| s.to_string());
        if let Some(url) = best_srcset_url(&srcset, ctx.base) {
            if !url.is_empty() && ctx.seen.insert(url.clone()) && !should_skip(&url) {
                ctx.results.push(ExtractedMedia {
                    url,
                    source: ctx.base_url.to_string(),
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
fn extract_bg_images(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("[style]").iter() {
        if let Some(style) = node.attr("style") {
            for url in extract_bg_urls(style.as_ref(), ctx.base) {
                if ctx.seen.insert(url.clone()) && !should_skip(&url) {
                    ctx.results.push(ExtractedMedia {
                        url,
                        source: ctx.base_url.to_string(),
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
