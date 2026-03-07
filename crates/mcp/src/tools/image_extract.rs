//! MCP tool: image_extract

use std::time::Instant;

use ox_imagesearch::extract::extract_images;
use ox_imagesearch::ImageResult;
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};

use rmcp::schemars;
use schemars::JsonSchema;

use super::OxMcpServer;

/// Input parameters for the `image_extract` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImageExtractInput {
    /// URL of the page to extract images from.
    pub url: String,
    /// Minimum image width in pixels. Images with unknown width are kept. Default: 400.
    #[serde(default = "default_min_width")]
    pub min_width: u32,
}

fn default_min_width() -> u32 {
    400
}

#[derive(Serialize)]
struct ImageExtractResult {
    images: Vec<ImageResult>,
    total_on_page: usize,
    elapsed_ms: u64,
}

impl OxMcpServer {
    pub(crate) async fn do_image_extract(
        &self,
        input: ImageExtractInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();

        let resp = self
            .http_client
            .get(&input.url)
            .await
            .map_err(|e| McpError::internal_error(format!("fetch failed: {e}"), None))?;

        if resp.status != 200 {
            return Err(McpError::internal_error(
                format!("HTTP {}", resp.status),
                None,
            ));
        }

        let all = extract_images(&resp.body, &input.url);
        let total_on_page = all.len();

        let filtered: Vec<ImageResult> = all
            .into_iter()
            .filter(|img| img.width == 0 || img.width >= input.min_width)
            .collect();

        let result = ImageExtractResult {
            images: filtered,
            total_on_page,
            elapsed_ms: start.elapsed().as_millis() as u64,
        };
        let json = serde_json::to_string(&result)
            .unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
