//! MCP protocol server for ox-browser.
//!
//! Exposes 12 tools over Streamable HTTP transport.

pub mod tools;

use std::sync::Arc;

use axum::Router;
use ox_http::deadline::{CallOutcome, bounded, resolve_timeout, timeout_from_json};
use ox_http::{CookieCache, CookieProvider, HttpClient};
use ox_js::EndpointDefaults;
use rmcp::ErrorData as McpError;
use rmcp::RoleServer;
use rmcp::handler::server::ServerHandler;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;

use tools::OxMcpServer;

/// Tools that own an internal per-call bound producing a typed error the
/// dispatch bound cannot reproduce — `fetch` maps `DeadlineExceeded` into
/// its `FetchResult` body, `read` inside `read_pipeline::read_page`. They
/// stay outside the dispatch bound; a second outer bound would only shadow
/// their error shape. Every other tool is bounded at dispatch — including
/// `fetch_smart`, which calls `http_client.get` with no internal bound.
const INNER_BOUNDED_TOOLS: &[&str] = &["fetch", "read"];

// `call_tool`/`list_tools`/`get_tool` are written out instead of
// `#[tool_handler]` because the macro unconditionally appends its own
// `call_tool`; the dispatch bound (issue #147) needs to wrap it.
impl ServerHandler for OxMcpServer {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ox-browser", env!("CARGO_PKG_VERSION")))
            .with_instructions("Stealth HTTP client with CF bypass and tech fingerprinting")
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if INNER_BOUNDED_TOOLS.contains(&request.name.as_ref()) {
            let tcc = ToolCallContext::new(self, request, context);
            return self.tool_router.call(tcc).await;
        }
        // Bound the WHOLE tool call at dispatch — same seam as the REST
        // router layer (issue #147). `timeout`/`timeout_secs` is pulled
        // generically from `arguments`; tools that already declare the
        // field (e.g. chrome_interact forwards it to go-browser) get the
        // same clamped ceiling on the outer call.
        let caller = request.arguments.as_ref().and_then(timeout_from_json);
        let tcc = ToolCallContext::new(self, request, context);
        match bounded(resolve_timeout(caller), self.tool_router.call(tcc)).await {
            CallOutcome::Ok(r) => r,
            CallOutcome::DeadlineExceeded { secs } => {
                Ok(CallToolResult::error(vec![Content::text(format!(
                    "deadline exceeded ({secs}s per-call bound)"
                ))]))
            }
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: self.tool_router.list_all(),
            meta: None,
            next_cursor: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tool_router.get(name).cloned()
    }
}

/// Build an Axum router that serves the MCP endpoint at `/mcp`.
#[allow(clippy::too_many_arguments)] // DI ctor wiring the shared dep set
pub fn build_mcp_router(
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
    http_client: Arc<HttpClient>,
    defaults: EndpointDefaults,
    media_config: ox_media::MediaConfig,
    gobrowser_proxy: Arc<ox_js::gobrowser_proxy::GoBrowserProxy>,
) -> Router {
    let server = OxMcpServer::new(
        provider,
        cache,
        http_client,
        defaults,
        media_config,
        gobrowser_proxy,
    );
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    Router::new().nest_service("/mcp", service)
}
