//! MCP tool: readability — extract article content from a URL.
//! Two-stage fetch: fast wreq first, headless fallback on 401/403.
//! DEPRECATED: Use the `read` tool instead.

use ox_http::ChallengeType;
use rmcp::ErrorData as McpError;
use rmcp::model::*;
use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use url::Url;

use super::OxMcpServer;

/// Input parameters for the `readability` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadabilityInput {
    /// URL to extract article content from.
    pub url: String,
    /// Return plain text (true) or clean HTML (false). Default: true.
    #[serde(default = "default_true")]
    pub plain_text: bool,
    /// Max content length in chars. 0 = unlimited. Default: 0.
    #[serde(default)]
    pub max_length: usize,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
struct ReadabilityResult {
    title: String,
    content: String,
    author: String,
    excerpt: String,
    length: usize,
    elapsed_ms: u64,
    /// "direct" or "solved" (headless fallback was used).
    method: String,
}

impl OxMcpServer {
    pub(crate) async fn do_readability(
        &self,
        input: ReadabilityInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();

        let resp = self
            .http_client
            .get(&input.url)
            .await
            .map_err(|e| McpError::internal_error(format!("fetch: {e}"), None))?;

        let (html, method) = if resp.status == 200 {
            (resp.body, "direct")
        } else if ox_http::content::should_fallback(resp.status) {
            tracing::info!(url = %input.url, status = resp.status, "readability: non-200, attempting headless fallback");
            let html = self.headless_fetch(&input.url).await.map_err(|e| {
                McpError::internal_error(
                    format!("HTTP {} + headless fallback failed: {e}", resp.status),
                    None,
                )
            })?;
            (html, "solved")
        } else {
            return Err(McpError::internal_error(
                format!("HTTP {}", resp.status),
                None,
            ));
        };

        let format = if input.plain_text {
            ox_http::content::ContentFormat::Text
        } else {
            ox_http::content::ContentFormat::Html
        };
        let extracted = ox_http::content::extract_content(&html, &input.url, format);
        let mut content = extracted.content;
        if input.max_length > 0 {
            content = ox_http::content::truncate_utf8(&content, input.max_length);
        }
        let length = content.len();
        let result = ReadabilityResult {
            title: extracted.title,
            content,
            author: extracted.author,
            excerpt: extracted.excerpt,
            length,
            elapsed_ms: start.elapsed().as_millis() as u64,
            method: method.into(),
        };

        let json =
            serde_json::to_string(&result).unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Solve via headless browser, cache cookies, retry GET.
    async fn headless_fetch(&self, url: &str) -> Result<String, String> {
        let domain = Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();
        let solved = self.provider.solve(url, ChallengeType::JsChallenge).await?;
        self.cache.put(&domain, solved);
        tracing::info!(domain = %domain, "headless solved, retrying GET");
        let retry = self
            .http_client
            .get(url)
            .await
            .map_err(|e| format!("retry after solve: {e}"))?;
        if retry.status != 200 {
            return Err(format!("retry got HTTP {}", retry.status));
        }
        Ok(retry.body)
    }
}
