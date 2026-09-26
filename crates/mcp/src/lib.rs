//! MCP protocol server for ox-browser.
//!
//! Exposes 13 tools over Streamable HTTP transport.

pub mod tools;

use std::sync::Arc;

use axum::Router;
use ox_http::deadline::{
    CHROME_PROXY_BOUND_SECS, CRAWL_BOUND_SECS, CallOutcome, MEDIA_DOWNLOAD_BOUND_SECS,
    SOLVER_CALL_BOUND_SECS, bounded, resolve_timeout_for, timeout_from_json,
};
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

/// The designed per-call bound for a dispatch-bounded tool — the deadline
/// `resolve_timeout_for` falls back to and clamps caller input at.
/// `SOLVER_CALL_BOUND_SECS` is the catch-all: these tools go through
/// `http_client`, whose middleware chain escalates to `provider.solve`
/// (configured for up to 120 s behind Byparr). `chrome_interact`'s own
/// `timeout_secs` default (30 s forwarded to go-browser) sits under the
/// proxy client's 60 s bound; `crawl` runs the whole crawl synchronously.
fn tool_default_secs(name: &str) -> u64 {
    match name {
        "chrome_interact" => CHROME_PROXY_BOUND_SECS,
        "crawl" => CRAWL_BOUND_SECS,
        "media_download" => MEDIA_DOWNLOAD_BOUND_SECS,
        _ => SOLVER_CALL_BOUND_SECS,
    }
}

/// The dispatch-level deadline decision for a tool call (issue #147):
/// `None` for tools owning an internal typed bound, otherwise the
/// caller-clamped designed bound for the tool. Extracted for tests — the
/// transport `RequestContext` cannot be constructed outside rmcp, so the
/// bound wiring itself is verified live, the decision is verified here.
fn dispatch_deadline(
    name: &str,
    args: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Option<std::time::Duration> {
    if INNER_BOUNDED_TOOLS.contains(&name) {
        return None;
    }
    Some(resolve_timeout_for(
        args.and_then(timeout_from_json),
        tool_default_secs(name),
    ))
}

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
        // Bound the WHOLE tool call at dispatch — same seam as the REST
        // router layer (issue #147). `timeout`/`timeout_secs` is pulled
        // generically from `arguments`; tools that already declare the
        // field (e.g. chrome_interact forwards it to go-browser) get the
        // same clamped ceiling on the outer call.
        let Some(deadline) = dispatch_deadline(&request.name, request.arguments.as_ref()) else {
            let tcc = ToolCallContext::new(self, request, context);
            return self.tool_router.call(tcc).await;
        };
        let tcc = ToolCallContext::new(self, request, context);
        match bounded(deadline, self.tool_router.call(tcc)).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn dispatch_deadline_skips_inner_bounded_tools() {
        assert_eq!(dispatch_deadline("fetch", None), None);
        assert_eq!(dispatch_deadline("read", None), None);
    }

    #[test]
    fn dispatch_deadline_uses_per_tool_designed_bounds() {
        assert_eq!(
            dispatch_deadline("solve_cf", None),
            Some(Duration::from_secs(SOLVER_CALL_BOUND_SECS))
        );
        assert_eq!(
            dispatch_deadline("crawl", None),
            Some(Duration::from_secs(CRAWL_BOUND_SECS))
        );
        assert_eq!(
            dispatch_deadline("chrome_interact", None),
            Some(Duration::from_secs(CHROME_PROXY_BOUND_SECS))
        );
        assert_eq!(
            dispatch_deadline("media_download", None),
            Some(Duration::from_secs(MEDIA_DOWNLOAD_BOUND_SECS))
        );
    }

    #[test]
    fn dispatch_deadline_caller_timeout_clamps_to_tool_bound() {
        let args = serde_json::json!({"timeout": 5});
        assert_eq!(
            dispatch_deadline("analyze", args.as_object()),
            Some(Duration::from_secs(5))
        );
        let args = serde_json::json!({"timeout_secs": 10});
        assert_eq!(
            dispatch_deadline("chrome_interact", args.as_object()),
            Some(Duration::from_secs(10))
        );
        // Never extend past the designed bound.
        let args = serde_json::json!({"timeout": 999});
        assert_eq!(
            dispatch_deadline("solve_cf", args.as_object()),
            Some(Duration::from_secs(SOLVER_CALL_BOUND_SECS))
        );
    }
}
