//! Orchestrator: ties platform detection, extraction, download, and merge together.

use dom_query::Document;
use tracing::{debug, info};

use crate::detect::{detect_platform, Platform};
use crate::download::{download_to_file, media_path};
use crate::extract::{extract_media, MediaKind};
use crate::merge::merge_dash;
use crate::youtube::{build_video_info, find_player_response};
use crate::{MediaError, MediaFile, MediaRequest, MediaResult, MediaStats, MediaType, Quality};

const DEFAULT_MAX_HEIGHT: u32 = 1080;
const DEFAULT_MAX_SIZE_MB: f64 = 50.0;
const DEFAULT_MAX_RESULTS: usize = 1;

/// Main entry point: detect platform, fetch HTML, extract/download media.
pub async fn download(
    http_client: &ox_http::HttpClient,
    req: &MediaRequest,
) -> Result<MediaResult, MediaError> {
    let platform = detect_platform(&req.url);
    let max_bytes = (req.max_size_mb.unwrap_or(DEFAULT_MAX_SIZE_MB) * 1_048_576.0) as u64;
    info!(url = %req.url, ?platform, "starting media download");

    let resp = http_client
        .get(&req.url)
        .await
        .map_err(|e| MediaError::FetchFailed(e.to_string()))?;
    if resp.status >= 400 {
        return Err(MediaError::FetchFailed(format!("HTTP {}", resp.status)));
    }

    match platform {
        Platform::YouTube => download_youtube(&resp.body, &req.url, req, max_bytes).await,
        Platform::Generic => download_generic(&resp.body, &resp.url, req, max_bytes).await,
    }
}

/// YouTube: parse playerResponse, download video (+ audio if DASH), merge.
async fn download_youtube(
    html: &str, url: &str, req: &MediaRequest, max_bytes: u64,
) -> Result<MediaResult, MediaError> {
    let pr = find_player_response(html).ok_or(MediaError::NoVideoFound)?;
    let info = build_video_info(&pr, req.max_height.unwrap_or(DEFAULT_MAX_HEIGHT));
    let video_url = info.video_url.as_deref().ok_or(MediaError::NoVideoFound)?;
    debug!(video_url, audio = info.audio_url.is_some(), "YouTube streams found");

    let video_dest = media_path("yt", url, "mp4");
    let video_size = download_to_file(video_url, &video_dest, max_bytes).await?;

    let (final_path, final_size, merged) = if let Some(ref audio_url) = info.audio_url {
        let audio_dest = media_path("yt", &format!("{url}_audio"), "m4a");
        download_to_file(audio_url, &audio_dest, max_bytes).await?;
        let merged_dest = media_path("yt", &format!("{url}_merged"), "mp4");
        merge_dash(&video_dest, &audio_dest, &merged_dest)
            .map_err(|e| MediaError::MergeFailed(e.to_string()))?;
        let size = tokio::fs::metadata(&merged_dest)
            .await
            .map_err(|e| MediaError::DownloadFailed(format!("stat merged: {e}")))?
            .len();
        (merged_dest, size, true)
    } else {
        (video_dest, video_size, false)
    };

    info!(path = %final_path.display(), size = final_size, merged, "YouTube download complete");
    Ok(MediaResult {
        media_type: MediaType::Video,
        files: vec![MediaFile {
            path: final_path.to_string_lossy().into_owned(),
            size_bytes: final_size,
            width: Some(info.width),
            height: Some(info.height),
        }],
        platform: Some("youtube".into()),
        title: info.title,
        author: info.author,
        description: info.description,
        duration_secs: info.duration_secs.map(|s| s as f64),
        stats: Some(MediaStats { views: Some(info.views), likes: None, comments: None }),
        quality: Some(Quality { width: info.width, height: info.height }),
        merged,
    })
}

/// Generic: extract media from HTML, filter, download.
async fn download_generic(
    html: &str, base_url: &str, req: &MediaRequest, max_bytes: u64,
) -> Result<MediaResult, MediaError> {
    let mut items = extract_media(html, base_url);

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

    // Sort: videos first, then by area descending
    items.sort_by(|a, b| {
        let rank = |k: MediaKind| if k == MediaKind::Video { 0u8 } else { 1 };
        rank(a.media_kind).cmp(&rank(b.media_kind)).then_with(|| {
            let area = |m: &crate::extract::ExtractedMedia| (m.width as u64) * (m.height as u64);
            area(b).cmp(&area(a))
        })
    });
    items.truncate(req.max_results.unwrap_or(DEFAULT_MAX_RESULTS));
    debug!(count = items.len(), "downloading generic media items");

    let mut files = Vec::with_capacity(items.len());
    for item in &items {
        let ext = url_extension(&item.url, item.media_kind);
        let dest = media_path("generic", &item.url, ext);
        let size = download_to_file(&item.url, &dest, max_bytes).await?;
        files.push(MediaFile {
            path: dest.to_string_lossy().into_owned(),
            size_bytes: size,
            width: if item.width > 0 { Some(item.width) } else { None },
            height: if item.height > 0 { Some(item.height) } else { None },
        });
    }

    let doc = Document::from(html);
    let title = crate::extract::helpers::extract_og_title(&doc);
    let first_kind = items.first().map(|i| i.media_kind);
    let result_type = if first_kind == Some(MediaKind::Video) { MediaType::Video } else { MediaType::Image };
    info!(count = files.len(), "generic download complete");

    Ok(MediaResult {
        media_type: result_type,
        files,
        platform: Some("generic".into()),
        title: if title.is_empty() { None } else { Some(title) },
        author: None,
        description: None,
        duration_secs: None,
        stats: None,
        quality: None,
        merged: false,
    })
}

/// Extract file extension from URL path, with fallback based on media kind.
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
        assert_eq!(url_extension("https://example.com/video.mp4", MediaKind::Video), "mp4");
        assert_eq!(url_extension("https://example.com/photo.webp", MediaKind::Image), "webp");
        assert_eq!(url_extension("https://example.com/img.jpg?w=800", MediaKind::Image), "jpg");
    }

    #[test]
    fn url_extension_fallback() {
        assert_eq!(url_extension("https://example.com/media", MediaKind::Video), "mp4");
        assert_eq!(url_extension("https://example.com/media", MediaKind::Image), "jpg");
    }

    #[test]
    fn url_extension_ignores_long() {
        assert_eq!(url_extension("https://example.com/file.toolong", MediaKind::Video), "mp4");
    }
}
