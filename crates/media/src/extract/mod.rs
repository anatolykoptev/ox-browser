//! Extract candidate media (images + videos) from HTML.
//!
//! Parses `<img>`, `<picture><source>`, `og:image`, CSS background-image,
//! `<video>`, `og:video`, `twitter:player:stream`, JSON-LD VideoObject,
//! and inline JS video URL heuristics.

pub(crate) mod helpers;
mod image;
mod video;

use std::collections::HashSet;
use dom_query::Document;
use url::Url;

/// Shared context for all extraction methods.
pub(crate) struct ExtractContext<'a> {
    pub doc: &'a Document,
    pub base_url: &'a str,
    pub base: &'a Option<Url>,
    pub seen: HashSet<String>,
    pub results: Vec<ExtractedMedia>,
}

impl<'a> ExtractContext<'a> {
    fn new(doc: &'a Document, base_url: &'a str, base: &'a Option<Url>) -> Self {
        Self { doc, base_url, base, seen: HashSet::new(), results: Vec::new() }
    }
}

/// A media item extracted from HTML.
#[derive(Debug, Clone)]
pub struct ExtractedMedia {
    pub url: String,
    pub title: String,
    pub width: u32,
    pub height: u32,
    pub media_kind: MediaKind,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Image,
    Video,
}

/// Extract candidate media URLs from HTML, resolving relative URLs against base.
pub fn extract_media(html: &str, base_url: &str) -> Vec<ExtractedMedia> {
    let doc = Document::from(html);
    let base = Url::parse(base_url).ok();
    let mut ctx = ExtractContext::new(&doc, base_url, &base);

    // Image extraction (methods 1-4)
    image::extract_images(&mut ctx);

    // Video extraction (methods 5-9)
    video::extract_videos(&mut ctx);

    ctx.results
}

/// Create a video `ExtractedMedia` with default dimensions.
pub(crate) fn video_media(url: String, title: String, source: &str) -> ExtractedMedia {
    ExtractedMedia { url, title, width: 0, height: 0, media_kind: MediaKind::Video, source: source.to_string() }
}

/// Resolve a potentially relative URL against a base.
pub(crate) fn resolve_url(src: &str, base: &Option<Url>) -> String {
    let trimmed = src.trim();
    if trimmed.starts_with("data:") {
        return String::new();
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    if let Some(base) = base
        && let Ok(resolved) = base.join(trimmed)
    {
        return resolved.to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests;
