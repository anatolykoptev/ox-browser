//! Platform abstraction for media downloads.

use ox_http::BrowserProfile;

use crate::{MediaConfig, MediaError, MediaRequest, MediaResult};

/// Trait for platform-specific download logic.
#[async_trait::async_trait]
pub trait PlatformDownloader: Send + Sync {
    /// Download media from this platform.
    ///
    /// `profile` is the browser identity to carry on the media-fetch client
    /// (threaded from the originating `HttpClient` so the page fetch and the
    /// media fetch present the same identity — issue #101).
    #[allow(clippy::too_many_arguments)] // 6 params: url, req, max_bytes, config, profile
    async fn download(
        &self,
        url: &str,
        req: &MediaRequest,
        max_bytes: u64,
        config: &MediaConfig,
        profile: &BrowserProfile,
    ) -> Result<MediaResult, MediaError>;
}
