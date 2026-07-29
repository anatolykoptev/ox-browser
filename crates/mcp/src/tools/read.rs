//! MCP tool: read — unified content extraction.
//!
//! Thin wrapper over `ox_http::read_pipeline::read_page`.

use ox_http::content::ReadParams;
use ox_http::read_pipeline;
use rmcp::ErrorData as McpError;
use rmcp::model::*;
use rmcp::schemars::{self, JsonSchema};
use serde::Deserialize;

use super::OxMcpServer;

/// Input for the `read` MCP tool (extends ReadParams with JsonSchema).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadInput {
    /// URL to read content from.
    pub url: String,
    /// Output format: "text" (default), "markdown", "html", or "llm".
    /// "llm" produces token-optimized text: strips images/emphasis/CSS/JS
    /// noise, moves links to a deduplicated footer, gates JSON-LD.
    #[serde(default = "default_format")]
    pub format: String,
    /// Max content length in chars. 0 = unlimited.
    #[serde(default)]
    pub max_length: usize,
    /// Per-call deadline in seconds. `None` → seam default; `Some(s)` →
    /// clamped to `[1, MAX_CALL_TIMEOUT_SECS]`. Bounds the whole read
    /// pipeline, not one attempt. Same field/units/ceiling as `/fetch`,
    /// `/read`, MCP `fetch`, and the CLI `--timeout` flag (issue #139).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

fn default_format() -> String {
    "text".into()
}

impl From<ReadInput> for ReadParams {
    fn from(i: ReadInput) -> Self {
        Self {
            url: i.url,
            format: i.format,
            max_length: i.max_length,
            timeout_secs: i.timeout_secs,
        }
    }
}

impl OxMcpServer {
    pub(crate) async fn do_read(&self, input: ReadInput) -> Result<CallToolResult, McpError> {
        let params: ReadParams = input.into();
        let output =
            read_pipeline::read_page(&self.http_client, &params, &self.site_handlers).await;

        let is_err = output.error.is_some();
        let json = serde_json::to_string(&output).unwrap_or_default();
        if is_err {
            Ok(CallToolResult::error(vec![Content::text(json)]))
        } else {
            Ok(CallToolResult::success(vec![Content::text(json)]))
        }
    }
}

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;
