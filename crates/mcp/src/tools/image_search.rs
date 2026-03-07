//! MCP tool: image_search

use std::sync::Arc;
use std::time::Instant;

use ox_imagesearch::bing::BingImages;
use ox_imagesearch::brave::BraveImages;
use ox_imagesearch::ddg::DdgImages;
use ox_imagesearch::fusion::ImageSearchEngine;
use ox_imagesearch::openverse::OpenverseImages;
use ox_imagesearch::pexels::PexelsImages;
use ox_imagesearch::{ImageEngine, ImageResult};
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};

use rmcp::schemars;
use schemars::JsonSchema;

use super::OxMcpServer;

/// Input parameters for the `image_search` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImageSearchInput {
    /// Search query for images.
    pub query: String,
    /// Engines to use: "bing", "ddg", "openverse", "pexels", "brave". Default: bing+ddg.
    #[serde(default)]
    pub engines: Vec<String>,
    /// Maximum results to return. Default: 10.
    #[serde(default = "default_max")]
    pub max_results: usize,
}

fn default_max() -> usize {
    10
}

#[derive(Serialize)]
struct ImageSearchResult {
    images: Vec<ImageResult>,
    engines_used: Vec<String>,
    elapsed_ms: u64,
}

impl OxMcpServer {
    pub(crate) async fn do_image_search(
        &self,
        input: ImageSearchInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();

        let mut engines: Vec<Arc<dyn ImageEngine>> = Vec::new();
        let use_all = input.engines.is_empty();
        if use_all || input.engines.iter().any(|e| e == "bing") {
            engines.push(Arc::new(BingImages));
        }
        if use_all || input.engines.iter().any(|e| e == "ddg") {
            engines.push(Arc::new(DdgImages));
        }
        // API-based engines: opt-in only (proxied requests may be blocked by API providers)
        if input.engines.iter().any(|e| e == "openverse") {
            engines.push(Arc::new(OpenverseImages));
        }
        if input.engines.iter().any(|e| e == "pexels") {
            if let Ok(key) = std::env::var("PEXELS_API_KEY") {
                engines.push(Arc::new(PexelsImages { api_key: key }));
            }
        }
        if input.engines.iter().any(|e| e == "brave") {
            engines.push(Arc::new(BraveImages));
        }

        let engine_names: Vec<String> =
            engines.iter().map(|e| e.name().to_owned()).collect();
        let search = ImageSearchEngine::new(engines);
        let images = search
            .search(self.http_client.clone(), &input.query, input.max_results)
            .await;

        let result = ImageSearchResult {
            images,
            engines_used: engine_names,
            elapsed_ms: start.elapsed().as_millis() as u64,
        };
        let json = serde_json::to_string(&result)
            .unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
