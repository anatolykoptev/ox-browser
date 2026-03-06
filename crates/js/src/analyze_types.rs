//! Types for the `/analyze` endpoint response.

use ox_intelligence::{
    accessibility::AccessibilityReport, api_discovery::ApiReport, content::ContentReport,
    fonts::FontsReport, media::MediaReport, performance::PerformanceReport, pwa::PwaReport,
    seo::SeoReport,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct AnalyzeRequest {
    pub url: String,
}

#[derive(Serialize)]
pub struct AnalyzeResponse {
    pub url: String,
    pub status: u16,
    pub technologies: Vec<TechInfo>,
    pub meta: MetaInfo,
    pub assets: AssetInfo,
    pub seo: SeoReport,
    pub performance: PerformanceReport,
    pub accessibility: AccessibilityReport,
    pub content: ContentReport,
    pub media: MediaReport,
    pub fonts: FontsReport,
    pub pwa: PwaReport,
    pub api: ApiReport,
    pub method: String,
    pub cf_detected: bool,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct TechInfo {
    pub name: String,
    pub categories: Vec<String>,
    pub confidence: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Serialize)]
pub struct MetaInfo {
    pub generator: String,
    pub server: String,
    pub powered_by: String,
    pub title: String,
}

#[derive(Serialize)]
pub struct AssetInfo {
    pub scripts: Vec<String>,
    pub stylesheets: Vec<String>,
}

impl AnalyzeResponse {
    /// Build an error response with default values for all intelligence sections.
    pub fn error(url: String, elapsed_ms: u64, err: String) -> Self {
        Self {
            url,
            status: 0,
            technologies: vec![],
            meta: MetaInfo {
                generator: String::new(),
                server: String::new(),
                powered_by: String::new(),
                title: String::new(),
            },
            assets: AssetInfo {
                scripts: vec![],
                stylesheets: vec![],
            },
            seo: SeoReport::default(),
            performance: PerformanceReport::default(),
            accessibility: AccessibilityReport::default(),
            content: ContentReport::default(),
            media: MediaReport::default(),
            fonts: FontsReport::default(),
            pwa: PwaReport::default(),
            api: ApiReport::default(),
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms,
            error: Some(err),
        }
    }
}
