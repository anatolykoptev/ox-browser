//! YouTube platform downloader via Innertube API.

use tracing::{debug, info};

use crate::download::{download_to_file, media_path};
use crate::innertube;
use crate::merge::merge_dash;
use crate::platform::PlatformDownloader;
use crate::youtube::build_video_info;
use crate::{MediaConfig, MediaError, MediaFile, MediaRequest, MediaResult};

pub struct YouTubeDownloader;

#[async_trait::async_trait]
impl PlatformDownloader for YouTubeDownloader {
    async fn download(
        &self,
        url: &str,
        req: &MediaRequest,
        max_bytes: u64,
        config: &MediaConfig,
    ) -> Result<MediaResult, MediaError> {
        let video_id = innertube::extract_video_id(url)
            .ok_or_else(|| MediaError::FetchFailed("no video ID in URL".into()))?;

        let proxy = &config.proxy_url;
        let pr = innertube::fetch_player_response(video_id, config, proxy).await?;
        let info = build_video_info(&pr, req.max_height.unwrap_or(config.default_max_height));
        let video_url = info.video_url.as_deref().ok_or(MediaError::NoVideoFound)?;
        debug!(video_url, audio = info.audio_url.is_some(), "YouTube streams found");

        let video_dest = media_path("yt", url, "mp4");
        let video_size = download_to_file(video_url, &video_dest, max_bytes, proxy).await?;

        let (final_path, final_size, merged) = if let Some(ref audio_url) = info.audio_url {
            let audio_dest = media_path("yt", &format!("{url}_audio"), "m4a");
            download_to_file(audio_url, &audio_dest, max_bytes, proxy).await?;
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
        let file = MediaFile {
            path: final_path.to_string_lossy().into_owned(),
            size_bytes: final_size,
            width: Some(info.width),
            height: Some(info.height),
        };
        Ok(MediaResult::youtube(
            file, info.title, info.author, info.description,
            info.duration_secs.map(|s| s as f64), info.views,
            info.width, info.height, merged,
        ))
    }
}
