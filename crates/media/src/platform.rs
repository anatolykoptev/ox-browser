//! Platform abstraction for media downloads.

use crate::{MediaConfig, MediaError, MediaRequest, MediaResult};

/// Trait for platform-specific download logic.
#[async_trait::async_trait]
pub trait PlatformDownloader: Send + Sync {
    /// Download media from this platform.
    async fn download(
        &self,
        url: &str,
        req: &MediaRequest,
        max_bytes: u64,
        config: &MediaConfig,
    ) -> Result<MediaResult, MediaError>;
}
