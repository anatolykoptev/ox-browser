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
            ..Default::default()
        };

        let crawler = Crawler::new(Arc::clone(&self.http_client), config);
        let (mut rx, _discovery) = crawler.crawl(&input.url).await;

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
            pages,
        };

        let json = serde_json::to_string(&result)
            .unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
