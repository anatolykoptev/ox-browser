//! MCP protocol server for ox-browser.
//!
//! Exposes 12 tools over Streamable HTTP transport.

pub mod tools;

use std::sync::Arc;

use axum::Router;
use ox_http::{CookieCache, CookieProvider, HttpClient};
use ox_js::EndpointDefaults;
use rmcp::handler::server::ServerHandler;
use rmcp::model::*;
use rmcp::tool_handler;
use rmcp::transport::streamable_http_server::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;

use tools::OxMcpServer;

// rmcp 1.8.0's `#[tool_handler]` defaults `router` to `Self::tool_router()`,
// which rebuilds the route table on every call. We pass the pre-built,
// clone-cheap `tool_router` field instead so the table is built once at
// `OxMcpServer::new` and reused.
#[tool_handler(router = self.tool_router.clone())]
impl ServerHandler for OxMcpServer {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ox-browser", env!("CARGO_PKG_VERSION")))
            .with_instructions("Stealth HTTP client with CF bypass and tech fingerprinting")
    }
}

/// Build an Axum router that serves the MCP endpoint at `/mcp`.
///
/// `extra_allowed_hosts` are operator-supplied `Host`/`host:port` entries (from
/// `ServerSection::mcp_allowed_hosts`) ADDED to rmcp's loopback-only default
/// allowlist, so the DNS-rebinding guard (RUSTSEC-2026-0189, rmcp ≥ 1.4.0) can
/// admit non-loopback fleet consumers without weakening loopback protection.
/// Empty → rmcp default (`localhost`, `127.0.0.1`, `::1`) only.
#[allow(clippy::too_many_arguments)] // DI ctor wiring the shared dep set
pub fn build_mcp_router(
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
    http_client: Arc<HttpClient>,
    defaults: EndpointDefaults,
    media_config: ox_media::MediaConfig,
    gobrowser_proxy: Arc<ox_js::gobrowser_proxy::GoBrowserProxy>,
    extra_allowed_hosts: Vec<String>,
) -> Router {
    let server = OxMcpServer::new(
        provider,
        cache,
        http_client,
        defaults,
        media_config,
        gobrowser_proxy,
    );
    let config = if extra_allowed_hosts.is_empty() {
        StreamableHttpServerConfig::default()
    } else {
        // Start from the loopback default and ADD operator entries, so an
        // operator listing a private-network authority can never accidentally
        // drop loopback from the allowlist.
        let mut hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
        hosts.extend(extra_allowed_hosts);
        StreamableHttpServerConfig::default().with_allowed_hosts(hosts)
    };
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        config,
    );

    Router::new().nest_service("/mcp", service)
}
