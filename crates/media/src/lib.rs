pub mod cleanup;
pub mod detect;
pub mod download;
pub mod extract;
pub mod http;
pub mod innertube;
pub mod merge;
pub mod orchestrator;
pub mod platform;
pub mod platform_generic;
pub mod platform_youtube;
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
    /// ANDROID_VR client version for Innertube.
    pub android_vr_version: String,
    /// Rotating proxy URL for YouTube API (empty = direct).
    pub proxy_url: String,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            default_max_height: 1080,
            default_max_size_mb: 50.0,
            default_max_results: 1,
            innertube_url: "https://www.youtube.com/youtubei/v1/player".into(),
            android_vr_version: "1.60.19".into(),
            proxy_url: String::new(),
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

/// Parameters for building a YouTube media result.
pub struct YouTubeResultParams {
    pub file: MediaFile,
    pub title: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub duration_secs: Option<f64>,
    pub views: i64,
    pub width: u32,
    pub height: u32,
    pub merged: bool,
}

impl MediaResult {
    /// Build result for a YouTube download.
    pub fn youtube(p: YouTubeResultParams) -> Self {
        Self {
            media_type: MediaType::Video,
            files: vec![p.file],
            platform: Some("youtube".into()),
            title: p.title, author: p.author, description: p.description,
            duration_secs: p.duration_secs,
            stats: Some(MediaStats { views: Some(p.views), likes: None, comments: None }),
            quality: Some(Quality { width: p.width, height: p.height }),
            merged: p.merged,
        }
    }

    /// Build result for a generic download.
    pub fn generic(files: Vec<MediaFile>, title: Option<String>, media_type: MediaType) -> Self {
        Self {
            media_type,
            files,
            platform: Some("generic".into()),
            title,
            author: None, description: None, duration_secs: None,
            stats: None, quality: None, merged: false,
        }
    }
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
