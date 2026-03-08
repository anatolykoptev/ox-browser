//! POST /crawl — site crawling with SSE streaming results.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::Json;
use ox_crawler::{CrawlConfig, CrawlScope, Crawler};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Crawl request body.
#[derive(Deserialize)]
pub struct CrawlRequest {
    pub url: String,
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
    #[serde(default = "default_max_pages")]
    pub max_pages: usize,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub include_markdown: Option<bool>,
    #[serde(default)]
    pub budget: Option<HashMap<String, usize>>,
    #[serde(default)]
    pub discovery: Option<String>,
    #[serde(default)]
    pub sitemap_url: Option<String>,
    #[serde(default)]
    pub sitemap_filter: Option<Vec<String>>,
    #[serde(default)]
    pub sitemap_since: Option<String>,
    #[serde(default)]
    pub sitemap_max_depth: Option<u32>,
    #[serde(default)]
    pub sitemap_max_files: Option<usize>,
    #[serde(default)]
    pub save_to_file: Option<bool>,
}

fn default_max_depth() -> u32 {
    3
}
fn default_max_pages() -> usize {
    100
}

/// Summary sent as the final SSE event.
#[derive(Serialize)]
pub struct CrawlSummary {
    pub pages_crawled: usize,
    pub errors: usize,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sitemaps_found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_dir: Option<String>,
}

pub async fn crawl(
    State(state): State<AppState>,
    Json(req): Json<CrawlRequest>,
) -> impl IntoResponse {
    let scope = match req.scope.as_deref() {
        Some("same_host") => CrawlScope::SameHost,
        Some("same_domain") | None => CrawlScope::SameDomain,
        Some(other) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown scope: {other}"),
            ));
        }
    };

    let include_markdown = req.include_markdown.unwrap_or(true);

    let config = CrawlConfig {
        max_depth: req.max_depth,
        max_pages: req.max_pages,
        scope,
        include_markdown,
        budget: req.budget.unwrap_or_default(),
        discovery: req.discovery.unwrap_or_else(|| "bfs".into()),
        sitemap_url: req.sitemap_url,
        sitemap_filter: req.sitemap_filter.unwrap_or_default(),
        sitemap_since: req.sitemap_since,
        sitemap_max_depth: req.sitemap_max_depth.unwrap_or(3),
        sitemap_max_files: req.sitemap_max_files.unwrap_or(50),
        save_to_file: req.save_to_file.unwrap_or(false),
        ..Default::default()
    };

    let discovery_mode = config.discovery.clone();
    let crawler = Crawler::new(Arc::clone(&state.http_client), config);
    let (mut rx, discovery) = crawler.crawl(&req.url).await;
    let start = std::time::Instant::now();

    let stream = async_stream::stream! {
        // Emit sitemap discovery event if applicable
        if discovery.sitemaps_found > 0 {
            let sitemap_json = serde_json::json!({
                "phase": "discover",
                "sitemaps_found": discovery.sitemaps_found,
                "urls_found": discovery.urls_total,
                "urls_filtered": discovery.urls_filtered,
            });
            yield Ok::<_, Infallible>(Event::default().event("sitemap").data(sitemap_json.to_string()));
        }

        let mut pages = 0usize;
        let mut errors = 0usize;

        while let Some(result) = rx.recv().await {
            if result.error.is_some() {
                errors += 1;
            } else {
                pages += 1;
            }
            if let Ok(json) = serde_json::to_string(&result) {
                yield Ok::<_, Infallible>(Event::default().event("page").data(json));
            }
        }

        let summary = CrawlSummary {
            pages_crawled: pages,
            errors,
            elapsed_ms: start.elapsed().as_millis() as u64,
            discovery: if discovery_mode != "bfs" { Some(discovery_mode.clone()) } else { None },
            sitemaps_found: if discovery.sitemaps_found > 0 { Some(discovery.sitemaps_found) } else { None },
            output_dir: None,
        };
        if let Ok(json) = serde_json::to_string(&summary) {
            yield Ok(Event::default().event("done").data(json));
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crawl_request_defaults() {
        let json = r#"{"url": "https://example.com"}"#;
        let req: CrawlRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.url, "https://example.com");
        assert_eq!(req.max_depth, 3);
        assert_eq!(req.max_pages, 100);
        assert!(req.scope.is_none());
        assert!(req.include_markdown.is_none());
        assert!(req.budget.is_none());
    }

    #[test]
    fn crawl_request_with_options() {
        let json = r#"{
            "url": "https://example.com",
            "max_depth": 5,
            "max_pages": 50,
            "scope": "same_host",
            "include_markdown": false,
            "budget": {"*": 200, "/blog": 10}
        }"#;
        let req: CrawlRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.max_depth, 5);
        assert_eq!(req.max_pages, 50);
        assert_eq!(req.scope.as_deref(), Some("same_host"));
        assert_eq!(req.include_markdown, Some(false));
        let budget = req.budget.unwrap();
        assert_eq!(budget["*"], 200);
        assert_eq!(budget["/blog"], 10);
    }

    #[test]
    fn crawl_summary_serializes() {
        let summary = CrawlSummary {
            pages_crawled: 42,
            errors: 3,
            elapsed_ms: 5000,
            discovery: None,
            sitemaps_found: None,
            output_dir: None,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["pages_crawled"], 42);
        assert_eq!(json["errors"], 3);
        assert_eq!(json["elapsed_ms"], 5000);
        // Optional fields omitted when None
        assert!(json.get("discovery").is_none());
        assert!(json.get("sitemaps_found").is_none());
    }

    #[test]
    fn crawl_request_sitemap_params() {
        let json = r#"{
            "url": "https://example.com",
            "discovery": "sitemap",
            "sitemap_filter": ["posts"],
            "sitemap_since": "2026-01-01",
            "save_to_file": true
        }"#;
        let req: CrawlRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.discovery.as_deref(), Some("sitemap"));
        assert_eq!(req.sitemap_filter.as_ref().unwrap()[0], "posts");
        assert_eq!(req.save_to_file, Some(true));
    }
}
