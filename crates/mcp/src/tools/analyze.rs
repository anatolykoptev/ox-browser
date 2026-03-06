//! MCP tool implementation for tech stack analysis.

use std::collections::HashMap;
use std::time::Instant;

use ox_core::Page;
use ox_http::detect_cloudflare;
use ox_intelligence::fingerprint::Fingerprinter;
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};

use rmcp::schemars;
use schemars::JsonSchema;

use super::OxMcpServer;

/// Input parameters for the `analyze` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeInput {
    /// The URL to analyze for technology detection.
    pub url: String,
}

#[derive(Serialize)]
struct AnalyzeResult {
    url: String,
    status: u16,
    technologies: Vec<TechInfo>,
    meta: MetaInfo,
    assets: AssetInfo,
    cf_detected: bool,
    elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct TechInfo {
    name: String,
    category: String,
    confidence: u8,
}

#[derive(Serialize)]
struct MetaInfo {
    generator: String,
    server: String,
    powered_by: String,
    title: String,
}

#[derive(Serialize)]
struct AssetInfo {
    scripts: Vec<String>,
    stylesheets: Vec<String>,
}

impl OxMcpServer {
    /// Fetch a page and detect its technology stack.
    pub(crate) async fn do_analyze(
        &self,
        input: AnalyzeInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();

        let resp = match self.http_client.get(&input.url).await {
            Ok(r) => r,
            Err(e) => {
                let r = AnalyzeResult {
                    url: input.url,
                    status: 0,
                    technologies: vec![],
                    meta: MetaInfo {
                        generator: String::new(),
                        server: String::new(),
                        powered_by: String::new(),
                        title: String::new(),
                    },
                    assets: AssetInfo {
                        scripts: vec![],
                        stylesheets: vec![],
                    },
                    cf_detected: false,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: Some(e.to_string()),
                };
                let json = serde_json::to_string(&r).unwrap_or_default();
                return Ok(CallToolResult::error(vec![Content::text(json)]));
            }
        };

        let cf_detected = detect_cloudflare(&resp).is_some();
        let page = Page::new(resp.url.clone(), resp.status, &resp.body);

        let headers: HashMap<String, String> = resp
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|val| (k.to_string().to_lowercase(), val.to_owned()))
            })
            .collect();

        let meta_tags: HashMap<String, String> = page
            .meta_tags()
            .into_iter()
            .filter(|m| !m.name.is_empty())
            .map(|m| (m.name.to_lowercase(), m.content))
            .collect();

        let script_srcs: Vec<String> = page
            .select("script[src]")
            .iter()
            .filter_map(|s| s.attr("src").map(|v| v.to_string()))
            .collect();

        let stylesheets: Vec<String> = page
            .select("link[rel='stylesheet'][href]")
            .iter()
            .filter_map(|s| s.attr("href").map(|v| v.to_string()))
            .collect();

        let fingerprinter = Fingerprinter::new();
        let detections =
            fingerprinter.detect(&headers, &resp.body, &meta_tags, &script_srcs);

        let technologies: Vec<TechInfo> = detections
            .into_iter()
            .map(|d| TechInfo {
                name: d.name,
                category: d.category,
                confidence: d.confidence,
            })
            .collect();

        let meta = MetaInfo {
            generator: meta_tags.get("generator").cloned().unwrap_or_default(),
            server: headers.get("server").cloned().unwrap_or_default(),
            powered_by: headers
                .get("x-powered-by")
                .cloned()
                .unwrap_or_default(),
            title: page.title(),
        };

        let result = AnalyzeResult {
            url: input.url,
            status: resp.status,
            technologies,
            meta,
            assets: AssetInfo {
                scripts: script_srcs,
                stylesheets,
            },
            cf_detected,
            elapsed_ms: start.elapsed().as_millis() as u64,
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
