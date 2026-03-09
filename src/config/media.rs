//! Media download settings — YouTube Innertube client versions, PO Token, defaults.

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
    /// MWEB client version.
    pub mweb_version: String,
    /// bgutil-pot sidecar URL for PO Token generation (empty = disabled).
    pub pot_url: String,
}

impl Default for MediaSection {
    fn default() -> Self {
        let cfg = ox_media::MediaConfig::default();
        Self {
            default_max_height: cfg.default_max_height,
            default_max_size_mb: cfg.default_max_size_mb,
            default_max_results: cfg.default_max_results,
            innertube_url: cfg.innertube_url,
            mweb_version: cfg.mweb_version,
            pot_url: cfg.pot_url,
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
            mweb_version: self.mweb_version.clone(),
            pot_url: self.pot_url.clone(),
        }
    }
}
