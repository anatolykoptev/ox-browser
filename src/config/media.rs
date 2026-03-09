//! Media download settings — YouTube Innertube client versions, defaults.

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
    /// TVHTML5_SIMPLY_EMBEDDED_PLAYER client version.
    pub tv_embedded_version: String,
    /// MWEB client version.
    pub mweb_version: String,
}

impl Default for MediaSection {
    fn default() -> Self {
        let cfg = ox_media::MediaConfig::default();
        Self {
            default_max_height: cfg.default_max_height,
            default_max_size_mb: cfg.default_max_size_mb,
            default_max_results: cfg.default_max_results,
            innertube_url: cfg.innertube_url,
            tv_embedded_version: cfg.tv_embedded_version,
            mweb_version: cfg.mweb_version,
        }
    }
}

impl MediaSection {
    /// Convert to the media crate's config type.
    pub fn to_media_config(&self) -> ox_media::MediaConfig {
        ox_media::MediaConfig {
            default_max_height: self.default_max_height,
            default_max_size_mb: self.default_max_size_mb,
            default_max_results: self.default_max_results,
            innertube_url: self.innertube_url.clone(),
            tv_embedded_version: self.tv_embedded_version.clone(),
            mweb_version: self.mweb_version.clone(),
        }
    }
}
