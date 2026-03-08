//! Crawl result types.

use serde::Serialize;

/// Result for a single crawled page.
#[derive(Debug, Clone, Serialize)]
pub struct CrawlResult {
    pub url: String,
    pub status: u16,
    pub depth: u32,
    pub title: String,
    pub markdown: String,
    pub content_length: usize,
    pub links_found: usize,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sitemap_lastmod: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sitemap_priority: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
}

/// Aggregate statistics for a completed crawl.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CrawlStats {
    pub pages_crawled: usize,
    pub pages_skipped: usize,
    pub errors: usize,
    pub total_elapsed_ms: u64,
    pub discovery: String,
    pub sitemaps_found: usize,
    pub sitemap_urls_total: usize,
    pub sitemap_urls_filtered: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_dir: Option<String>,
}
