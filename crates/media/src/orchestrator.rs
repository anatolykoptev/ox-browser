//! Orchestrator: detect platform, dispatch to platform-specific downloader.

use tracing::info;

use crate::detect::{Platform, detect_platform};
use crate::platform::PlatformDownloader;
use crate::platform_generic::GenericDownloader;
use crate::platform_youtube::YouTubeDownloader;
use crate::{MediaConfig, MediaError, MediaRequest, MediaResult};

/// Main entry point: detect platform, dispatch download.
pub async fn download(
    http_client: &ox_http::HttpClient,
    req: &MediaRequest,
    config: &MediaConfig,
) -> Result<MediaResult, MediaError> {
    let platform = detect_platform(&req.url);
    let max_bytes = (req.max_size_mb.unwrap_or(config.default_max_size_mb) * 1_048_576.0) as u64;
    info!(url = %req.url, ?platform, "starting media download");

    match platform {
        Platform::YouTube => {
            YouTubeDownloader
                .download(&req.url, req, max_bytes, config)
                .await
        }
        Platform::Generic => {
            let resp = http_client
                .get(&req.url)
                .await
                .map_err(|e| MediaError::FetchFailed(e.to_string()))?;
            if resp.status >= 400 {
                return Err(MediaError::FetchFailed(format!("HTTP {}", resp.status)));
            }
            let downloader = GenericDownloader {
                html: resp.body.clone(),
                base_url: resp.url.clone(),
            };
            downloader.download(&req.url, req, max_bytes, config).await
        }
    }
}
