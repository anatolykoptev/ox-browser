//! MCP tool implementation for security scanning.

use std::collections::HashMap;
use std::time::Instant;

use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::Deserialize;

use rmcp::schemars;
use schemars::JsonSchema;

use super::OxMcpServer;

/// Input parameters for the `security_scan` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SecurityScanInput {
    /// The URL to scan for security issues.
    pub url: String,
}

impl OxMcpServer {
    /// Fetch a page and run passive security analysis.
    pub(crate) async fn do_security_scan(
        &self,
        input: SecurityScanInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();

        let resp = match self.http_client.get(&input.url).await {
            Ok(r) => r,
            Err(e) => {
                let json = serde_json::json!({
                    "url": input.url,
                    "error": e.to_string(),
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                });
                return Ok(CallToolResult::error(vec![Content::text(json.to_string())]));
            }
        };

        let headers: HashMap<String, String> = resp
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|val| (k.to_string().to_lowercase(), val.to_owned()))
            })
            .collect();

        let set_cookie_headers: Vec<String> = resp
            .headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(|s| s.to_owned()))
            .collect();

        let report = ox_security::analyze_security(
            &input.url,
            &headers,
            &set_cookie_headers,
            &resp.body,
            ox_security::ScanMode::Public,
        );

        let json = serde_json::to_string(&report).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
