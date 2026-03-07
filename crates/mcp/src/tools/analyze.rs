//! MCP tool: analyze — fetch page, detect technologies, run intelligence modules.

use std::collections::HashMap;
use std::time::Instant;

use ox_core::Page;
use ox_http::detect_cloudflare;
use ox_intelligence::{
    accessibility, api_discovery, content, fingerprint, fonts, media, performance, pwa, seo,
};
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};

use rmcp::schemars;
use schemars::JsonSchema;

use super::OxMcpServer;

/// Input parameters for the `analyze` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeInput {
    /// The URL to analyze for technology detection and site intelligence.
    pub url: String,
}

#[derive(Serialize)]
struct AnalyzeResult {
    url: String,
    status: u16,
    technologies: Vec<TechInfo>,
    meta: MetaInfo,
    assets: AssetInfo,
    seo: seo::SeoReport,
    performance: performance::PerformanceReport,
    accessibility: accessibility::AccessibilityReport,
    content: content::ContentReport,
    media: media::MediaReport,
    fonts: fonts::FontsReport,
    pwa: pwa::PwaReport,
    api: api_discovery::ApiReport,
    cf_detected: bool,
    elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct TechInfo {
    name: String,
    categories: Vec<String>,
    confidence: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
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
    /// Fetch a page and run full site intelligence analysis.
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
                    seo: Default::default(),
                    performance: Default::default(),
                    accessibility: Default::default(),
                    content: Default::default(),
                    media: Default::default(),
                    fonts: Default::default(),
                    pwa: Default::default(),
                    api: Default::default(),
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

        // Extract cookies for fingerprinting
        let cookies: HashMap<String, String> = headers
            .get("set-cookie")
            .map(|v| {
                v.split(';')
                    .filter_map(|pair| {
                        let mut kv = pair.trim().splitn(2, '=');
                        let k = kv.next()?.trim().to_owned();
                        let val = kv.next().unwrap_or("").trim().to_owned();
                        if k.is_empty() {
                            None
                        } else {
                            Some((k, val))
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Technology fingerprinting (rswappalyzer — 7,000+ techs)
        let detections = fingerprint::detect(
            &input.url, &headers, &resp.body, &meta_tags, &script_srcs, &cookies,
        );

        let technologies: Vec<TechInfo> = detections
            .into_iter()
            .map(|d| TechInfo {
                name: d.name,
                categories: d.categories,
                confidence: d.confidence,
                version: d.version,
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

        // Run all intelligence modules
        let seo_report = seo::analyze(&resp.body);
        let perf_report = performance::analyze(&headers, &resp.body);
        let a11y_report = accessibility::analyze(&resp.body);
        let content_report = content::analyze(&resp.body, &input.url);
        let media_report = media::analyze(&resp.body);
        let fonts_report = fonts::analyze(&resp.body);
        let pwa_report = pwa::analyze(&resp.body);
        let api_report = api_discovery::analyze(&resp.body);

        let result = AnalyzeResult {
            url: input.url,
            status: resp.status,
            technologies,
            meta,
            assets: AssetInfo {
                scripts: script_srcs,
                stylesheets,
            },
            seo: seo_report,
            performance: perf_report,
            accessibility: a11y_report,
            content: content_report,
            media: media_report,
            fonts: fonts_report,
            pwa: pwa_report,
            api: api_report,
            cf_detected,
            elapsed_ms: start.elapsed().as_millis() as u64,
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
