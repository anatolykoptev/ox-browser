//! Media analysis: images, video, audio.

use std::collections::{HashMap, HashSet};

use dom_query::Document;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct MediaReport {
    pub images_total: u32,
    pub image_formats: HashMap<String, u32>,
    pub srcset_count: u32,
    pub picture_count: u32,
    pub image_cdns: Vec<String>,
    pub videos: Vec<VideoInfo>,
    pub audio: Vec<AudioInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VideoInfo {
    pub src: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AudioInfo {
    pub src: String,
    pub platform: String,
}

/// Extract the lowercase file extension from a URL path (before the `?`).
fn image_format(src: &str) -> String {
    let path = src.split('?').next().unwrap_or(src);
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" | "png" | "webp" | "avif" | "svg" | "gif" => ext,
        _ => "other".to_string(),
    }
}

/// Identify image CDN from the URL host.
fn image_cdn(src: &str) -> Option<&'static str> {
    let s = src.to_lowercase();
    if s.contains("res.cloudinary.com") || s.contains(".cloudinary.com") {
        Some("Cloudinary")
    } else if s.contains(".imgix.net") {
        Some("imgix")
    } else if s.contains("imagedelivery.net") || s.contains("images.cloudflare.com") {
        Some("Cloudflare Images")
    } else if s.contains(".akamaized.net") || s.contains(".akamai.net") {
        Some("Akamai")
    } else {
        None
    }
}

/// Classify a video src URL into a named platform.
fn classify_video(src: &str) -> &'static str {
    let s = src.to_lowercase();
    if s.contains("youtube.com") || s.contains("youtu.be") {
        "YouTube"
    } else if s.contains("vimeo.com") {
        "Vimeo"
    } else {
        "Other"
    }
}

/// Classify an audio src URL into a named platform.
fn classify_audio(src: &str) -> &'static str {
    let s = src.to_lowercase();
    if s.contains("spotify.com") {
        "Spotify"
    } else if s.contains("soundcloud.com") {
        "SoundCloud"
    } else {
        "Other"
    }
}

/// Analyze HTML for images, video, and audio elements.
pub fn analyze(html: &str) -> MediaReport {
    let doc = Document::from(html);

    let mut images_total: u32 = 0;
    let mut image_formats: HashMap<String, u32> = HashMap::new();
    let mut srcset_count: u32 = 0;
    let mut cdn_set: HashSet<&'static str> = HashSet::new();

    doc.select("img").iter().for_each(|node| {
        images_total += 1;

        if let Some(src) = node.attr("src") {
            let fmt = image_format(src.as_ref());
            *image_formats.entry(fmt).or_insert(0) += 1;
            if let Some(cdn) = image_cdn(src.as_ref()) {
                cdn_set.insert(cdn);
            }
        }

        if node.attr("srcset").is_some() {
            srcset_count += 1;
        }
    });

    let picture_count = doc.select("picture").iter().count() as u32;

    // Also check srcset on source elements inside picture.
    doc.select("source[srcset]").iter().for_each(|node| {
        // Only count source srcsets not already covered by img srcset.
        // We track these separately to avoid double-counting with img srcset.
        let _ = node; // counted below via picture_count
    });

    // Collect image CDNs from source[src] inside picture too.
    doc.select("source[src]").iter().for_each(|node| {
        if let Some(src) = node.attr("src") {
            if let Some(cdn) = image_cdn(src.as_ref()) {
                cdn_set.insert(cdn);
            }
        }
    });

    // Videos — <video src> or <video><source src>.
    let mut videos: Vec<VideoInfo> = Vec::new();
    doc.select("video").iter().for_each(|node| {
        if let Some(src) = node.attr("src") {
            let src = src.to_string();
            let platform = classify_video(&src).to_string();
            videos.push(VideoInfo { src, platform });
        } else {
            // Check first <source> child.
            node.select("source[src]").iter().next().map(|s| {
                if let Some(src) = s.attr("src") {
                    let src = src.to_string();
                    let platform = classify_video(&src).to_string();
                    videos.push(VideoInfo { src, platform });
                }
            });
        }
    });

    // Audio — <audio src> or <audio><source src>.
    let mut audio: Vec<AudioInfo> = Vec::new();
    doc.select("audio").iter().for_each(|node| {
        if let Some(src) = node.attr("src") {
            let src = src.to_string();
            let platform = classify_audio(&src).to_string();
            audio.push(AudioInfo { src, platform });
        } else {
            node.select("source[src]").iter().next().map(|s| {
                if let Some(src) = s.attr("src") {
                    let src = src.to_string();
                    let platform = classify_audio(&src).to_string();
                    audio.push(AudioInfo { src, platform });
                }
            });
        }
    });

    let mut image_cdns: Vec<String> = cdn_set.iter().map(|s| s.to_string()).collect();
    image_cdns.sort();

    MediaReport {
        images_total,
        image_formats,
        srcset_count,
        picture_count,
        image_cdns,
        videos,
        audio,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_format_breakdown() {
        let html = r#"<html><body>
            <img src="photo.jpg">
            <img src="icon.png">
            <img src="banner.webp?w=800">
            <img src="logo.svg">
            <img src="anim.gif">
            <img src="photo2.jpg">
        </body></html>"#;

        let report = analyze(html);
        assert_eq!(report.images_total, 6);
        assert_eq!(report.image_formats.get("jpg").copied().unwrap_or(0), 2);
        assert_eq!(report.image_formats.get("png").copied().unwrap_or(0), 1);
        assert_eq!(report.image_formats.get("webp").copied().unwrap_or(0), 1);
        assert_eq!(report.image_formats.get("svg").copied().unwrap_or(0), 1);
        assert_eq!(report.image_formats.get("gif").copied().unwrap_or(0), 1);
    }

    #[test]
    fn detect_responsive_images() {
        let html = r#"<html><body>
            <picture>
                <source srcset="img-800.webp 800w, img-1600.webp 1600w">
                <img src="img.jpg" srcset="img-800.jpg 800w">
            </picture>
            <img src="plain.png">
        </body></html>"#;

        let report = analyze(html);
        assert_eq!(report.picture_count, 1);
        assert_eq!(report.srcset_count, 1, "only img srcset counted");
        assert_eq!(report.images_total, 2);
    }

    #[test]
    fn detect_video() {
        let html = r#"<html><body>
            <video src="https://www.youtube.com/embed/abc"></video>
            <video>
                <source src="clip.mp4">
            </video>
        </body></html>"#;

        let report = analyze(html);
        assert_eq!(report.videos.len(), 2);
        let platforms: Vec<&str> = report.videos.iter().map(|v| v.platform.as_str()).collect();
        assert!(platforms.contains(&"YouTube"), "{:?}", platforms);
        assert!(platforms.contains(&"Other"), "{:?}", platforms);
    }

    #[test]
    fn detect_image_cdn() {
        let html = r#"<html><body>
            <img src="https://res.cloudinary.com/demo/image/upload/sample.jpg">
            <img src="https://mysite.imgix.net/photo.jpg">
            <img src="https://imagedelivery.net/abc/img/public">
            <img src="https://regular.example.com/img.png">
        </body></html>"#;

        let report = analyze(html);
        assert!(report.image_cdns.contains(&"Cloudinary".to_string()), "{:?}", report.image_cdns);
        assert!(report.image_cdns.contains(&"imgix".to_string()), "{:?}", report.image_cdns);
        assert!(report.image_cdns.contains(&"Cloudflare Images".to_string()), "{:?}", report.image_cdns);
        assert!(!report.image_cdns.contains(&"Akamai".to_string()));
    }

    #[test]
    fn detect_audio() {
        let html = r#"<html><body>
            <audio src="https://soundcloud.com/track/embed"></audio>
            <audio><source src="podcast.mp3"></audio>
        </body></html>"#;

        let report = analyze(html);
        assert_eq!(report.audio.len(), 2);
        let platforms: Vec<&str> = report.audio.iter().map(|a| a.platform.as_str()).collect();
        assert!(platforms.contains(&"SoundCloud"), "{:?}", platforms);
        assert!(platforms.contains(&"Other"), "{:?}", platforms);
    }
}
