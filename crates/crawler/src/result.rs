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
}

/// Aggregate statistics for a completed crawl.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CrawlStats {
    pub pages_crawled: usize,
    pub pages_skipped: usize,
    pub errors: usize,
    pub total_elapsed_ms: u64,
}
