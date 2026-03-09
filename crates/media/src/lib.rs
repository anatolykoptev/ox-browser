pub mod cleanup;
pub mod detect;
pub mod download;
pub mod extract;
pub mod innertube;
pub mod merge;
pub mod orchestrator;
pub mod youtube;

pub use orchestrator::download;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Media download configuration — externalized constants.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MediaConfig {
    /// Default max video height when not specified in request (pixels).
    pub default_max_height: u32,
    /// Default max file size when not specified in request (MB).
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

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            default_max_height: 1080,
            default_max_size_mb: 50.0,
            default_max_results: 1,
            innertube_url: "https://www.youtube.com/youtubei/v1/player".into(),
            tv_embedded_version: "2.0".into(),
            mweb_version: "2.20240304.08.00".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaRequest {
    pub url: String,
    #[serde(default)]
    pub media_type: MediaType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size_mb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_results: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_width: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MediaType {
    #[default]
    Auto,
    Video,
    Image,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaFile {
    pub path: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaStats {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub views: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub likes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quality {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaResult {
    pub media_type: MediaType,
    pub files: Vec<MediaFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<MediaStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<Quality>,
    #[serde(default)]
    pub merged: bool,
}

#[derive(Debug, Error)]
pub enum MediaError {
    #[error("no video found")]
    NoVideoFound,
    #[error("no image found")]
    NoImageFound,
    #[error("download failed: {0}")]
    DownloadFailed(String),
    #[error("size exceeded: {0}")]
    SizeExceeded(String),
    #[error("merge failed: {0}")]
    MergeFailed(String),
    #[error("fetch failed: {0}")]
    FetchFailed(String),
}
