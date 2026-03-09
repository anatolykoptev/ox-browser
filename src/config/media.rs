//! Media download settings — YouTube ANDROID_VR client, proxy, defaults.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MediaSection {
    /// Default max video height (pixels).
    pub default_max_height: u32,
    /// Default max file size (MB).
    pub default_max_size_mb: f64,
    /// Default max results for generic extraction.
    pub default_max_results: usize,
    /// Innertube API endpoint URL.
    pub innertube_url: String,
    /// ANDROID_VR client version for Innertube.
    pub android_vr_version: String,
    /// Rotating proxy URL for YouTube API (empty = direct).
    pub proxy_url: String,
}

impl Default for MediaSection {
    fn default() -> Self {
        let cfg = ox_media::MediaConfig::default();
        Self {
            default_max_height: cfg.default_max_height,
            default_max_size_mb: cfg.default_max_size_mb,
            default_max_results: cfg.default_max_results,
            innertube_url: cfg.innertube_url,
            android_vr_version: cfg.android_vr_version,
            proxy_url: cfg.proxy_url,
        }
    }
}

impl MediaSection {
    /// Convert to the media crate's config type.
    /// `MEDIA_PROXY_URL` env var overrides config file.
    pub fn to_media_config(&self) -> ox_media::MediaConfig {
        let proxy_url = std::env::var("MEDIA_PROXY_URL")
            .unwrap_or_else(|_| self.proxy_url.clone());
        ox_media::MediaConfig {
            default_max_height: self.default_max_height,
            default_max_size_mb: self.default_max_size_mb,
            default_max_results: self.default_max_results,
            innertube_url: self.innertube_url.clone(),
            android_vr_version: self.android_vr_version.clone(),
            proxy_url,
        }
    }
}
