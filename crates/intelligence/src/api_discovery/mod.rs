//! API discovery: fetch/axios/XHR endpoints, GraphQL, Next.js/Nuxt data, forms, WebSockets,
//! WebMCP tools, and public API detection.

pub mod public_api;
#[cfg(test)]
mod tests;
pub mod webmcp;

use dom_query::Document;
use regex::Regex;
use serde::Serialize;

pub use public_api::PublicApiReport;
pub use webmcp::{WebMcpReport, WebMcpTool};

#[derive(Debug, Clone, Serialize, Default)]
pub struct ApiReport {
    pub endpoints: Vec<ApiEndpoint>,
    pub graphql_detected: bool,
    pub next_data: bool,
    pub nuxt_data: bool,
    pub form_actions: Vec<String>,
    pub websocket_urls: Vec<String>,
    pub webmcp: WebMcpReport,
    pub public_api: PublicApiReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiEndpoint {
    pub url: String,
    pub method: String,
    pub source: String,
}

fn extract_fetch_endpoints(script: &str) -> Vec<ApiEndpoint> {
    let re = Regex::new(r#"fetch\s*\(\s*['"]([^'"]+)['"]"#).expect("valid regex");
    re.captures_iter(script)
        .map(|cap| ApiEndpoint {
            url: cap[1].to_string(),
            method: "GET".to_string(),
            source: "fetch".to_string(),
        })
        .collect()
}

fn extract_axios_endpoints(script: &str) -> Vec<ApiEndpoint> {
    let re = Regex::new(r#"axios\.(\w+)\s*\(\s*['"]([^'"]+)['"]"#).expect("valid regex");
    re.captures_iter(script)
        .map(|cap| {
            let method = match cap[1].to_lowercase().as_str() {
                "post" => "POST",
                "put" => "PUT",
                "delete" => "DELETE",
                "patch" => "PATCH",
                _ => "GET",
            };
            ApiEndpoint {
                url: cap[2].to_string(),
                method: method.to_string(),
                source: "axios".to_string(),
            }
        })
        .collect()
}

fn extract_websocket_urls(script: &str) -> Vec<String> {
    let re = Regex::new(r#"new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]"#).expect("valid regex");
    re.captures_iter(script)
        .map(|cap| cap[1].to_string())
        .collect()
}

/// Analyze HTML and return an `ApiReport`.
pub fn analyze(html: &str) -> ApiReport {
    let doc = Document::from(html);

    let mut endpoints: Vec<ApiEndpoint> = Vec::new();
    let mut graphql_detected = false;
    let mut websocket_urls: Vec<String> = Vec::new();
    let mut inline_scripts: Vec<String> = Vec::new();

    for node in doc.select("script:not([src])").iter() {
        let script = node.text().to_string();
        endpoints.extend(extract_fetch_endpoints(&script));
        endpoints.extend(extract_axios_endpoints(&script));
        websocket_urls.extend(extract_websocket_urls(&script));
        if script.contains("/graphql") || script.contains("__schema") {
            graphql_detected = true;
        }
        inline_scripts.push(script);
    }

    let mut seen_urls = std::collections::HashSet::new();
    endpoints.retain(|ep| seen_urls.insert(ep.url.clone()));
    websocket_urls.dedup();

    let next_data = doc.select("script#__NEXT_DATA__").iter().next().is_some();
    let nuxt_data = html.contains("__NUXT__");

    let form_actions: Vec<String> = doc
        .select("form[action]")
        .iter()
        .filter_map(|n| {
            let action = n.attr("action")?.to_string();
            if action.is_empty() || action == "#" {
                None
            } else {
                Some(action)
            }
        })
        .collect();

    let webmcp_report = webmcp::analyze(&doc, &inline_scripts);
    let public_api_report = public_api::analyze(&doc, html);

    ApiReport {
        endpoints,
        graphql_detected,
        next_data,
        nuxt_data,
        form_actions,
        websocket_urls,
        webmcp: webmcp_report,
        public_api: public_api_report,
    }
}
