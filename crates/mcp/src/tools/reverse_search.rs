//! MCP tool: reverse_image_search

use std::sync::Arc;
use std::time::Instant;

use ox_reverse::{
    GoogleLens, ReverseEngine, ReverseSearchEngine, YandexImages,
};
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::Deserialize;

use rmcp::schemars;
use schemars::JsonSchema;

use super::OxMcpServer;

/// Input parameters for the `reverse_image_search` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReverseSearchInput {
    /// Image URL to reverse search.
    pub url: String,
    /// Engines to use: "google_lens", "yandex". Default: both.
    #[serde(default)]
    pub engines: Vec<String>,
    /// Maximum results to return. Default: 20.
    pub max_results: Option<usize>,
}

impl OxMcpServer {
    pub(crate) async fn do_reverse_search(
        &self,
        input: ReverseSearchInput,
    ) -> Result<CallToolResult, McpError> {
        let _start = Instant::now();

        let mut engines: Vec<Arc<dyn ReverseEngine>> = Vec::new();
        let use_all = input.engines.is_empty();

        if use_all || input.engines.iter().any(|e| e == "google_lens") {
            engines.push(Arc::new(GoogleLens));
        }
        if use_all || input.engines.iter().any(|e| e == "yandex") {
            engines.push(Arc::new(YandexImages));
        }

        let max_results =
            input.max_results.unwrap_or(self.defaults.reverse_max_results);
        let search = ReverseSearchEngine::new(engines);
        let result = search
            .search(self.http_client.clone(), &input.url, max_results)
            .await;

        let json = serde_json::to_string(&result)
            .unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
