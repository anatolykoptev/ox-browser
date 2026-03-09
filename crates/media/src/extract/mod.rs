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
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    // Image extraction (methods 1-4)
    image::extract_images(&doc, base_url, &base, &mut seen, &mut results);

    // Video extraction (methods 5-9)
    video::extract_videos(&doc, base_url, &base, &mut seen, &mut results);

    results
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
    if let Some(base) = base {
        if let Ok(resolved) = base.join(trimmed) {
            return resolved.to_string();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Image tests (8 existing) ===

    #[test]
    fn extract_og_image() {
        let html = r#"<html><head>
            <meta property="og:image" content="https://example.com/hero.jpg"/>
            <meta property="og:title" content="Test Place"/>
        </head><body></body></html>"#;
        let results = extract_media(html, "https://example.com/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/hero.jpg");
        assert_eq!(results[0].title, "Test Place");
        assert_eq!(results[0].media_kind, MediaKind::Image);
    }

    #[test]
    fn extract_img_tags() {
        let html = r#"<html><body>
            <img src="https://example.com/photo1.jpg" width="1024" height="768" alt="Photo 1">
            <img src="https://example.com/photo2.webp" width="800" height="600">
            <img src="/logo.png" width="100" height="50">
            <img src="icon.svg">
        </body></html>"#;
        let results = extract_media(html, "https://example.com/page");
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
        let results = extract_media(html, "https://example.com/about/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/uploads/photo.jpg");
    }

    #[test]
    fn extract_srcset_largest() {
        let html = r#"<html><body>
            <img src="small.jpg" srcset="medium.jpg 800w, large.jpg 1600w">
        </body></html>"#;
        let results = extract_media(html, "https://example.com/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/large.jpg");
    }

    #[test]
    fn extract_background_image() {
        let html = r#"<html><body>
            <div style="background-image: url('https://example.com/bg.jpg')"></div>
        </body></html>"#;
        let results = extract_media(html, "https://example.com/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/bg.jpg");
    }

    #[test]
    fn skip_data_urls() {
        let html = r#"<html><body>
            <img src="data:image/gif;base64,R0lGODlhAQ">
            <img src="https://example.com/real.jpg">
        </body></html>"#;
        let results = extract_media(html, "https://example.com/");
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
        let results = extract_media(html, "https://example.com/");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn skip_tracking_pixels() {
        let html = r#"<html><body>
            <img src="https://tracker.com/pixel.png" width="1" height="1">
            <img src="https://example.com/photo.jpg" width="800" height="600">
        </body></html>"#;
        let results = extract_media(html, "https://example.com/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/photo.jpg");
    }

    // === Video tests ===

    #[test]
    fn extract_video_tag() {
        let html =
            r#"<html><body><video src="https://example.com/clip.mp4"></video></body></html>"#;
        let results = extract_media(html, "https://example.com/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].media_kind, MediaKind::Video);
        assert_eq!(results[0].url, "https://example.com/clip.mp4");
    }

    #[test]
    fn extract_video_source_tag() {
        let html = r#"<html><body><video><source src="https://example.com/clip.mp4" type="video/mp4"></video></body></html>"#;
        let results = extract_media(html, "https://example.com/");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].media_kind, MediaKind::Video);
    }

    #[test]
    fn extract_og_video() {
        let html = r#"<html><head><meta property="og:video" content="https://example.com/video.mp4"/></head></html>"#;
        let results = extract_media(html, "https://example.com/");
        assert!(results.iter().any(|r| r.media_kind == MediaKind::Video
            && r.url == "https://example.com/video.mp4"));
    }

    #[test]
    fn extract_json_ld_video() {
        let html = r#"<html><head><script type="application/ld+json">{"@type":"VideoObject","contentUrl":"https://example.com/v.mp4","name":"Test"}</script></head></html>"#;
        let results = extract_media(html, "https://example.com/");
        let video = results
            .iter()
            .find(|r| r.media_kind == MediaKind::Video)
            .unwrap();
        assert_eq!(video.url, "https://example.com/v.mp4");
        assert_eq!(video.title, "Test");
    }

    #[test]
    fn extract_twitter_player() {
        let html = r#"<html><head><meta name="twitter:player:stream" content="https://example.com/stream.mp4"/></head></html>"#;
        let results = extract_media(html, "https://example.com/");
        assert!(results.iter().any(|r| r.media_kind == MediaKind::Video));
    }
}
