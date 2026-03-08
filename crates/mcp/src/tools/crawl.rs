//! MCP tool: crawl — BFS site crawling with streaming results.

use std::sync::Arc;
use std::time::Instant;

use ox_crawler::{CrawlConfig, CrawlResult, CrawlScope, Crawler};
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};

use rmcp::schemars;
use schemars::JsonSchema;

use super::OxMcpServer;

/// Input parameters for the `crawl` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CrawlInput {
    /// Seed URL to start crawling from.
    pub url: String,
    /// Maximum crawl depth. Default: 3.
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
    /// Maximum number of pages to crawl. Default: 50.
    #[serde(default = "default_max_pages")]
    pub max_pages: usize,
    /// Scope: "same_domain" (default) or "same_host".
    #[serde(default)]
    pub scope: Option<String>,
    /// Include markdown content in results. Default: true.
    #[serde(default)]
    pub include_markdown: Option<bool>,
    /// Discovery mode: "bfs" (default), "sitemap", or "hybrid".
    #[serde(default)]
    pub discovery: Option<String>,
    /// Explicit sitemap URL. Auto-discovers if not set.
    #[serde(default)]
    pub sitemap_url: Option<String>,
    /// Filter sitemap index entries by name substring.
    #[serde(default)]
    pub sitemap_filter: Option<Vec<String>>,
    /// Only URLs with lastmod >= this ISO date.
    #[serde(default)]
    pub sitemap_since: Option<String>,
    /// Save page markdown to files. Default: false.
    #[serde(default)]
    pub save_to_file: Option<bool>,
}

fn default_max_depth() -> u32 {
    3
}
fn default_max_pages() -> usize {
    50
}

#[derive(Serialize)]
struct CrawlToolResult {
    pages_crawled: usize,
    errors: usize,
    elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    discovery: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sitemaps_found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_dir: Option<String>,
    pages: Vec<PageSummary>,
}

#[derive(Serialize)]
struct PageSummary {
    url: String,
    status: u16,
    depth: u32,
    title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    markdown: String,
    content_length: usize,
    links_found: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
}

impl From<CrawlResult> for PageSummary {
    fn from(r: CrawlResult) -> Self {
        Self {
            url: r.url,
            status: r.status,
            depth: r.depth,
            title: r.title,
            markdown: r.markdown,
            content_length: r.content_length,
            links_found: r.links_found,
            error: r.error,
            source: r.source,
            file_path: r.file_path,
        }
    }
}

impl OxMcpServer {
    pub(crate) async fn do_crawl(
        &self,
        input: CrawlInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();

        let scope = match input.scope.as_deref() {
            Some("same_host") => CrawlScope::SameHost,
            Some("same_domain") | None => CrawlScope::SameDomain,
            Some(other) => {
                return Err(McpError::invalid_params(
                    format!("unknown scope: {other}"),
                    None,
                ));
            }
        };

        let config = CrawlConfig {
            max_depth: input.max_depth,
            max_pages: input.max_pages,
            scope,
            include_markdown: input.include_markdown.unwrap_or(true),
            discovery: input.discovery.unwrap_or_else(|| "bfs".into()),
            sitemap_url: input.sitemap_url,
            sitemap_filter: input.sitemap_filter.unwrap_or_default(),
            sitemap_since: input.sitemap_since,
            save_to_file: input.save_to_file.unwrap_or(false),
            ..Default::default()
        };

        let discovery_mode = config.discovery.clone();
        let crawler = Crawler::new(Arc::clone(&self.http_client), config);
        let (mut rx, discovery) = crawler.crawl(&input.url).await;

        let mut pages = Vec::new();
        let mut error_count = 0usize;

        while let Some(result) = rx.recv().await {
            if result.error.is_some() {
                error_count += 1;
            }
            pages.push(PageSummary::from(result));
        }

        let result = CrawlToolResult {
            pages_crawled: pages.len() - error_count,
            errors: error_count,
            elapsed_ms: start.elapsed().as_millis() as u64,
            discovery: if discovery_mode != "bfs" { Some(discovery_mode) } else { None },
            sitemaps_found: if discovery.sitemaps_found > 0 { Some(discovery.sitemaps_found) } else { None },
            output_dir: None,
            pages,
        };

        let json = serde_json::to_string(&result)
            .unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
