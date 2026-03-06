//! MCP tool implementations for fetch and fetch_smart.

use std::collections::HashMap;
use std::time::Instant;

use ox_http::detect_cloudflare;
use ox_http::ChallengeType;
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};

use rmcp::schemars;
use schemars::JsonSchema;
use url::Url;

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
    body: String,
    method: String,
    cf_detected: bool,
    elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl OxMcpServer {
    /// Stealth HTTP fetch via wreq+BoringSSL.
    pub(crate) async fn do_fetch(
        &self,
        input: FetchInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();

        match self.http_client.get(&input.url).await {
            Ok(resp) => {
                let cf = detect_cloudflare(&resp);
                let headers: HashMap<String, String> = resp
                    .headers
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str()
                            .ok()
                            .map(|val| (k.to_string(), val.to_owned()))
                    })
                    .collect();

                let result = FetchResult {
                    status: resp.status,
                    headers,
                    body: resp.body,
                    cf_detected: cf.is_some(),
                    cf_type: cf.map(|c| c.challenge_type.to_string()),
                    elapsed_ms: start.elapsed().as_millis() as u64,
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
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: Some(e.to_string()),
                };
                let json = serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
                Ok(CallToolResult::error(vec![Content::text(json)]))
            }
        }
    }

    /// Three-tier fetch: fast wreq, CF detection, headless solve + retry.
    pub(crate) async fn do_fetch_smart(
        &self,
        input: FetchSmartInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();
        let domain = Url::parse(&input.url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();

        // Stage 1: Fast wreq fetch.
        let resp = match self.http_client.get(&input.url).await {
            Ok(r) => r,
            Err(e) => {
                return Ok(smart_error(start, &e.to_string()));
            }
        };

        let cf = detect_cloudflare(&resp);
        if cf.is_none() {
            return Ok(smart_ok(resp.status, resp.body, "direct", false, start));
        }

        let challenge = cf.unwrap();
        tracing::info!(domain, challenge = %challenge.challenge_type, "CF detected");

        if challenge.challenge_type == ChallengeType::Block {
            return Ok(smart_ok(resp.status, resp.body, "direct", true, start));
        }

        // Stage 2: Headless solve -> retry with cookies.
        match self.provider.solve(&input.url, challenge.challenge_type).await {
            Ok(solved) => {
                self.cache.put(&domain, solved);
                match self.http_client.get(&input.url).await {
                    Ok(retry) => Ok(smart_ok(
                        retry.status,
                        retry.body,
                        "solved",
                        true,
                        start,
                    )),
                    Err(e) => Ok(smart_error(start, &format!("retry failed: {e}"))),
                }
            }
            Err(e) => Ok(smart_error(start, &format!("solve failed: {e}"))),
        }
    }
}

fn smart_ok(
    status: u16,
    body: String,
    method: &str,
    cf: bool,
    start: Instant,
) -> CallToolResult {
    let r = FetchSmartResult {
        status,
        body,
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
        body: String::new(),
        method: "direct".into(),
        cf_detected: false,
        elapsed_ms: start.elapsed().as_millis() as u64,
        error: Some(msg.to_string()),
    };
    let json = serde_json::to_string(&r).unwrap_or_default();
    CallToolResult::error(vec![Content::text(json)])
}
