//! MCP protocol server for ox-browser.
//!
//! Exposes fetch, fetch_smart, analyze, and solve_cf as MCP tools
//! over Streamable HTTP transport.

pub mod tools;

use std::sync::Arc;

use axum::Router;
use ox_http::{CookieCache, CookieProvider, HttpClient};
use rmcp::handler::server::ServerHandler;
use rmcp::model::*;
use rmcp::tool_handler;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::StreamableHttpService;

use tools::OxMcpServer;

#[tool_handler]
impl ServerHandler for OxMcpServer {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(
            ServerCapabilities::builder().enable_tools().build(),
        )
        .with_server_info(
            Implementation::new("ox-browser", env!("CARGO_PKG_VERSION")),
        )
        .with_instructions(
            "Stealth HTTP client with CF bypass and tech fingerprinting",
        )
    }
}

/// Build an Axum router that serves the MCP endpoint at `/mcp`.
pub fn build_mcp_router(
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
    http_client: Arc<HttpClient>,
) -> Router {
    let server = OxMcpServer::new(provider, cache, http_client);
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    Router::new().nest_service("/mcp", service)
}
