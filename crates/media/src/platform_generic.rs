//! Generic platform downloader — extract media from HTML.

use dom_query::Document;
use tracing::{debug, info};

use crate::download::{download_to_file, media_path};
use crate::extract::{MediaKind, extract_media};
use crate::platform::PlatformDownloader;
use crate::{MediaConfig, MediaError, MediaFile, MediaRequest, MediaResult, MediaType};

pub struct GenericDownloader {
    pub html: String,
    pub base_url: String,
}

#[async_trait::async_trait]
impl PlatformDownloader for GenericDownloader {
    async fn download(
        &self,
        _url: &str,
        req: &MediaRequest,
        max_bytes: u64,
        config: &MediaConfig,
    ) -> Result<MediaResult, MediaError> {
        let mut items = extract_media(&self.html, &self.base_url);

        match req.media_type {
            MediaType::Video => items.retain(|m| m.media_kind == MediaKind::Video),
            MediaType::Image => items.retain(|m| m.media_kind == MediaKind::Image),
            MediaType::Auto => {}
        }
        if let Some(min_w) = req.min_width {
            items.retain(|m| m.width == 0 || m.width >= min_w);
        }
        if items.is_empty() {
            return match req.media_type {
                MediaType::Image => Err(MediaError::NoImageFound),
                _ => Err(MediaError::NoVideoFound),
            };
        }

        items.sort_by(|a, b| {
            let rank = |k: MediaKind| if k == MediaKind::Video { 0u8 } else { 1 };
            rank(a.media_kind).cmp(&rank(b.media_kind)).then_with(|| {
                let area =
                    |m: &crate::extract::ExtractedMedia| (m.width as u64) * (m.height as u64);
                area(b).cmp(&area(a))
            })
        });
        items.truncate(req.max_results.unwrap_or(config.default_max_results));
        debug!(count = items.len(), "downloading generic media items");

        let mut files = Vec::with_capacity(items.len());
        for item in &items {
            let ext = url_extension(&item.url, item.media_kind);
            let dest = media_path("generic", &item.url, ext);
            let size = download_to_file(&item.url, &dest, max_bytes, "").await?;
            files.push(MediaFile {
                path: dest.to_string_lossy().into_owned(),
                size_bytes: size,
                width: if item.width > 0 {
                    Some(item.width)
                } else {
                    None
                },
                height: if item.height > 0 {
                    Some(item.height)
                } else {
                    None
                },
            });
        }

        let doc = Document::from(self.html.as_str());
        let title = crate::extract::helpers::extract_og_title(&doc);
        let first_kind = items.first().map(|i| i.media_kind);
        let result_type = if first_kind == Some(MediaKind::Video) {
            MediaType::Video
        } else {
            MediaType::Image
        };
        let title = if title.is_empty() { None } else { Some(title) };
        info!(count = files.len(), "generic download complete");
        Ok(MediaResult::generic(files, title, result_type))
    }
}

fn url_extension(url: &str, kind: MediaKind) -> &str {
    let path = url.split('?').next().unwrap_or(url);
    if let Some(dot) = path.rfind('.') {
        let ext = &path[dot + 1..];
        if !ext.is_empty() && ext.len() <= 5 && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
            return ext;
        }
    }
    match kind {
        MediaKind::Video => "mp4",
        MediaKind::Image => "jpg",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_extension_from_path() {
        assert_eq!(
            url_extension("https://example.com/video.mp4", MediaKind::Video),
            "mp4"
        );
        assert_eq!(
            url_extension("https://example.com/photo.webp", MediaKind::Image),
            "webp"
        );
        assert_eq!(
            url_extension("https://example.com/img.jpg?w=800", MediaKind::Image),
            "jpg"
        );
    }

    #[test]
    fn url_extension_fallback() {
        assert_eq!(
            url_extension("https://example.com/media", MediaKind::Video),
            "mp4"
        );
        assert_eq!(
            url_extension("https://example.com/media", MediaKind::Image),
            "jpg"
        );
    }

    #[test]
    fn url_extension_ignores_long() {
        assert_eq!(
            url_extension("https://example.com/file.toolong", MediaKind::Video),
            "mp4"
        );
    }
}
