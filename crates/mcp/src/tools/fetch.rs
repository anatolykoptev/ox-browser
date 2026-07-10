//! MCP tool implementations for fetch and fetch_smart.

use std::collections::HashMap;
use std::time::Instant;

use ox_http::detect_cloudflare;
use rmcp::ErrorData as McpError;
use rmcp::model::*;
use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::OxMcpServer;

/// Input parameters for the `fetch` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FetchInput {
    /// The URL to fetch.
    pub url: String,
}

/// Input parameters for the `fetch_smart` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FetchSmartInput {
    /// The URL to fetch with automatic CF bypass.
    pub url: String,
    /// Save response body to file instead of returning inline. Default: true.
    #[serde(default = "default_true")]
    pub save_to_file: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
struct FetchResult {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
    cf_detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cf_type: Option<String>,
    elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct FetchSmartResult {
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
    method: String,
    cf_detected: bool,
    elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl OxMcpServer {
    /// Stealth HTTP fetch via wreq+BoringSSL.
    pub(crate) async fn do_fetch(&self, input: FetchInput) -> Result<CallToolResult, McpError> {
        let start = Instant::now();
        let elapsed = || start.elapsed().as_millis() as u64;
        match self.http_client.get(&input.url).await {
            Ok(resp) => {
                let cf = detect_cloudflare(&resp);
                let headers: HashMap<String, String> = resp
                    .headers
                    .iter()
                    .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_owned())))
                    .collect();
                let result = FetchResult {
                    status: resp.status,
                    headers,
                    body: resp.body,
                    cf_detected: cf.is_some(),
                    cf_type: cf.map(|c| c.challenge_type.to_string()),
                    elapsed_ms: elapsed(),
                    error: None,
                };
                let json = serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => {
                let result = FetchResult {
                    status: 0,
                    headers: HashMap::new(),
                    body: String::new(),
                    cf_detected: false,
                    cf_type: None,
                    elapsed_ms: elapsed(),
                    error: Some(e.to_string()),
                };
                let json = serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
                Ok(CallToolResult::error(vec![Content::text(json)]))
            }
        }
    }

    /// Fetch with automatic CF bypass via middleware chain.
    /// DEPRECATED: Use the `read` MCP tool instead.
    pub(crate) async fn do_fetch_smart(
        &self,
        input: FetchSmartInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();
        let save = input.save_to_file;
        let url = input.url.clone();

        // Middleware chain handles CF detect + solve + retry automatically.
        match self.http_client.get(&input.url).await {
            Ok(resp) => Ok(smart_ok(
                resp.status,
                resp.body,
                "auto",
                false,
                start,
                save,
                &url,
            )),
            Err(e) => Ok(smart_error(start, &e.to_string())),
        }
    }
}
#[allow(clippy::too_many_arguments)] // assembles an OK result from independent fields
fn smart_ok(
    status: u16,
    body: String,
    method: &str,
    cf: bool,
    start: Instant,
    save: bool,
    url: &str,
) -> CallToolResult {
    let (body_field, file_path) = if save {
        match ox_core::save::save_response(url, &body) {
            Ok(path) => (None, Some(path.display().to_string())),
            Err(e) => {
                tracing::warn!(error = %e, "failed to save response, returning inline");
                (Some(body), None)
            }
        }
    } else {
        (Some(body), None)
    };
    let r = FetchSmartResult {
        status,
        body: body_field,
        file_path,
        method: method.into(),
        cf_detected: cf,
        elapsed_ms: start.elapsed().as_millis() as u64,
        error: None,
    };
    let json = serde_json::to_string(&r).unwrap_or_default();
    CallToolResult::success(vec![Content::text(json)])
}

fn smart_error(start: Instant, msg: &str) -> CallToolResult {
    let r = FetchSmartResult {
        status: 0,
        body: None,
        file_path: None,
        method: "direct".into(),
        cf_detected: false,
        elapsed_ms: start.elapsed().as_millis() as u64,
        error: Some(msg.to_string()),
    };
    let json = serde_json::to_string(&r).unwrap_or_default();
    CallToolResult::error(vec![Content::text(json)])
}

#[cfg(test)]
#[path = "fetch_tests.rs"]
mod tests;
