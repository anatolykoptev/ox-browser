//! Public API surface detection: OpenAPI/Swagger, well-known paths, GraphQL playground.

use dom_query::Document;
use regex::Regex;
use serde::Serialize;

/// Public API surface detection report.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PublicApiReport {
    pub detected: bool,
    pub openapi_url: Option<String>,
    pub api_links: Vec<String>,
    pub well_known: Vec<String>,
    pub hints: Vec<String>,
}

/// Detect public API surface from HTML.
pub(crate) fn analyze(doc: &Document, html: &str) -> PublicApiReport {
    let mut api_links = Vec::new();
    let mut openapi_url = None;
    let mut well_known = Vec::new();
    let mut hints = Vec::new();

    // <link rel="api|service|service-desc|describedby" href="...">
    for node in doc.select("link[rel]").iter() {
        let rel = node.attr("rel").map(|v| v.to_string().to_lowercase()).unwrap_or_default();
        if let Some(href) = node.attr("href") {
            let href = href.to_string();
            if rel == "api" || rel == "service" || rel == "service-desc" || rel == "describedby" {
                api_links.push(href);
            }
        }
    }

    // <a> links to API docs / OpenAPI / Swagger
    let api_doc_re = Regex::new(r#"(?i)(swagger|openapi|api-doc|redoc|rapidoc)"#).expect("valid");
    for node in doc.select("a[href]").iter() {
        if let Some(href) = node.attr("href") {
            let href_str = href.to_string();
            if api_doc_re.is_match(&href_str) {
                if href_str.ends_with(".json") || href_str.ends_with(".yaml") || href_str.ends_with(".yml") {
                    openapi_url = Some(href_str.clone());
                }
                api_links.push(href_str);
            }
        }
    }

    // Script content hints: OpenAPI/Swagger config objects
    let openapi_re = Regex::new(r#"(?i)(SwaggerUI|swagger-ui|openapi|"openapi"\s*:\s*"3)"#).expect("valid");
    if openapi_re.is_match(html) {
        hints.push("openapi_config_detected".into());
    }

    // Well-known paths referenced in HTML
    let wk_re = Regex::new(r#"/.well-known/(openid-configuration|oauth-authorization-server|ai-plugin\.json|mcp\.json|host-meta)"#).expect("valid");
    for cap in wk_re.captures_iter(html) {
        well_known.push(cap[0].to_string());
    }

    // GraphQL playground/explorer hints
    if html.contains("graphql-playground") || html.contains("graphiql") || html.contains("GraphiQL") {
        hints.push("graphql_playground".into());
    }

    // Deduplicate
    api_links.sort();
    api_links.dedup();
    well_known.sort();
    well_known.dedup();
    hints.sort();
    hints.dedup();

    let detected = openapi_url.is_some() || !api_links.is_empty() || !well_known.is_empty() || !hints.is_empty();

    PublicApiReport { detected, openapi_url, api_links, well_known, hints }
}
