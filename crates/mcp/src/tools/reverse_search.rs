//! MCP tool: reverse_image_search

use std::sync::Arc;
use std::time::Instant;

use ox_reverse::{GoogleLens, ReverseEngine, ReverseSearchEngine, YandexImages};
use rmcp::ErrorData as McpError;
use rmcp::model::*;
use serde::Deserialize;

use rmcp::schemars;
use schemars::JsonSchema;

use ox_js::inbound_auth::InboundAuth;

use super::OxMcpServer;

/// Input parameters for the `reverse_image_search` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReverseSearchInput {
    /// Image URL to reverse search.
    pub url: String,
    /// Engines to use: "google_lens", "yandex". Default: yandex only.
    #[serde(default)]
    pub engines: Vec<String>,
    /// Maximum results to return. Default: 20.
    pub max_results: Option<usize>,
}

impl OxMcpServer {
    pub(crate) async fn do_reverse_search(
        &self,
        input: ReverseSearchInput,
        auth: InboundAuth,
    ) -> Result<CallToolResult, McpError> {
        // The URL is embedded in a Yandex / Lens query: an onion name would go
        // to a third party. Refuse before any engine is built.
        if let Some(e) = ox_http::tor::refuse_onion_for_third_party(&input.url) {
            let json = serde_json::json!({"error": e.to_string()});
            return Ok(CallToolResult::error(vec![Content::text(json.to_string())]));
        }
        let _start = Instant::now();

        let mut engines: Vec<Arc<dyn ReverseEngine>> = Vec::new();
        let use_all = input.engines.is_empty();

        // Google Lens disabled by default (SPA results need headless browser).
        if input.engines.iter().any(|e| e == "google_lens") {
            engines.push(Arc::new(GoogleLens));
        }
        if use_all || input.engines.iter().any(|e| e == "yandex") {
            engines.push(Arc::new(YandexImages));
        }

        let max_results = input
            .max_results
            .unwrap_or(self.defaults.reverse_max_results);
        let search = ReverseSearchEngine::new(engines);
        // ox-browser#177 / SEC-CR-018: `client_for` stamps the gate's
        // `ok_secret` decision — see do_fetch.
        let http = Arc::new(self.client_for(auth));
        let result = search.search(http, &input.url, max_results).await;

        let json =
            serde_json::to_string(&result).unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
