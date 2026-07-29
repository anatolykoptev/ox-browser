//! Orchestrator: detect platform, dispatch to platform-specific downloader.

use ox_http::{BrowserProfile, platform_matched_profile};
use tracing::info;

use crate::detect::{Platform, detect_platform};
use crate::platform::PlatformDownloader;
use crate::platform_generic::GenericDownloader;
use crate::platform_youtube::YouTubeDownloader;
use crate::{MediaConfig, MediaError, MediaRequest, MediaResult};

/// Main entry point: detect platform, dispatch download.
///
/// The browser identity carried by the media-fetch client is the profile the
/// originating `http_client` is configured with (`http_client.config().profile`)
/// — the SAME identity that fetched the page (for the generic path) or that the
/// operator chose for the deployment (for the YouTube path, where there is no
/// originating page fetch). When the operator set `profile = "none"` (no
/// fingerprinting), the media path falls back to `platform_matched_profile()`
/// so it still carries a coherent browser identity rather than a bare Rust
/// client — a bare client after a profiled page fetch is the
/// one-visitor-two-clients correlation signal issue #101 closes.
pub async fn download(
    http_client: &ox_http::HttpClient,
    req: &MediaRequest,
    config: &MediaConfig,
) -> Result<MediaResult, MediaError> {
    let platform = detect_platform(&req.url);
    let max_bytes = (req.max_size_mb.unwrap_or(config.default_max_size_mb) * 1_048_576.0) as u64;
    // B: thread the originating fetch's profile into the media client. When
    // the operator disabled fingerprinting (`profile = "none"`), pick a
    // platform-matched profile so the media path is still coherent.
    let profile: &'static BrowserProfile = http_client
        .config()
        .profile
        .unwrap_or_else(platform_matched_profile);
    info!(url = %req.url, ?platform, browser = %profile.browser, os = %profile.os, "starting media download");

    match platform {
        Platform::YouTube => {
            YouTubeDownloader
                .download(&req.url, req, max_bytes, config, profile)
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
            downloader
                .download(&req.url, req, max_bytes, config, profile)
                .await
        }
    }
}
