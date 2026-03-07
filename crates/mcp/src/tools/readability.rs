//! MCP tool: readability — extract article content from a URL.

use readabilityrs::Readability;
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use rmcp::schemars;
use schemars::JsonSchema;

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

        if resp.status != 200 {
            return Err(McpError::internal_error(
                format!("HTTP {}", resp.status),
                None,
            ));
        }

        let r = Readability::new(&resp.body, Some(&input.url), None)
            .map_err(|e| McpError::internal_error(format!("readability init: {e}"), None))?;
        let article = r.parse().ok_or_else(|| {
            McpError::internal_error("readability: could not extract article", None)
        })?;

        let raw_content = article.content.unwrap_or_default();
        let mut content = if input.plain_text {
            html_to_plain(&raw_content)
        } else {
            raw_content
        };

        if input.max_length > 0 && content.len() > input.max_length {
            let mut end = input.max_length;
            while end < content.len() && !content.is_char_boundary(end) {
                end += 1;
            }
            content.truncate(end);
            content.push('…');
        }

        let result = ReadabilityResult {
            title: article.title.unwrap_or_default(),
            length: content.len(),
            content,
            author: article.byline.unwrap_or_default(),
            excerpt: article.excerpt.unwrap_or_default(),
            elapsed_ms: start.elapsed().as_millis() as u64,
        };

        let json = serde_json::to_string(&result)
            .unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

fn html_to_plain(html: &str) -> String {
    let doc = dom_query::Document::from(html);
    let text = doc.select("body").text().to_string();
    let mut result = String::with_capacity(text.len());
    let mut prev_ws = true;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                result.push(' ');
                prev_ws = true;
            }
        } else {
            result.push(ch);
            prev_ws = false;
        }
    }
    result.trim().to_string()
}
