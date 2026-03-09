//! WebMCP (W3C) detection — declarative forms + imperative JS hints.

use dom_query::Document;
use serde::Serialize;

/// WebMCP (W3C) detection report.
#[derive(Debug, Clone, Serialize, Default)]
pub struct WebMcpReport {
    pub supported: bool,
    pub declarative_tools: Vec<WebMcpTool>,
    pub imperative_detected: bool,
    pub tool_count: usize,
}

/// A WebMCP tool declared via `<form toolname="...">`.
#[derive(Debug, Clone, Serialize)]
pub struct WebMcpTool {
    pub name: String,
    pub description: String,
    pub inputs: Vec<String>,
}

/// Detect WebMCP declarative tools from `<form toolname="...">`.
pub(crate) fn extract_tools(doc: &Document) -> Vec<WebMcpTool> {
    doc.select("form[toolname]")
        .iter()
        .filter_map(|n| {
            let name = n.attr("toolname")?.to_string();
            if name.is_empty() {
                return None;
            }
            let description = n
                .attr("tooldescription")
                .map(|v| v.to_string())
                .unwrap_or_default();
            let inputs: Vec<String> = n
                .select("input[name], select[name], textarea[name]")
                .iter()
                .filter_map(|inp| inp.attr("name").map(|v| v.to_string()))
                .collect();
            Some(WebMcpTool { name, description, inputs })
        })
        .collect()
}

/// Detect imperative WebMCP usage in inline scripts.
pub(crate) fn detect_imperative(scripts: &[String]) -> bool {
    scripts.iter().any(|s| {
        s.contains("navigator.modelContext") || s.contains("modelContext.registerTool")
    })
}

/// Build a WebMcpReport from document and scripts.
pub(crate) fn analyze(doc: &Document, scripts: &[String]) -> WebMcpReport {
    let declarative_tools = extract_tools(doc);
    let imperative_detected = detect_imperative(scripts);
    let tool_count = declarative_tools.len();
    WebMcpReport {
        supported: !declarative_tools.is_empty() || imperative_detected,
        declarative_tools,
        imperative_detected,
        tool_count,
    }
}
