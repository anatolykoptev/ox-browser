//! MCP tool definitions and routing for ox-browser.

mod analyze;
mod fetch;
mod solve;

use std::sync::Arc;

use ox_http::{CookieCache, CookieProvider, HttpClient};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use rmcp::{tool, tool_router};

pub use analyze::AnalyzeInput;
pub use fetch::{FetchInput, FetchSmartInput};
pub use solve::SolveCfInput;

/// MCP server exposing ox-browser capabilities as tools.
#[derive(Clone)]
pub struct OxMcpServer {
    pub(crate) provider: Arc<dyn CookieProvider>,
    pub(crate) cache: Arc<CookieCache>,
    pub(crate) http_client: Arc<HttpClient>,
    pub(crate) tool_router: ToolRouter<Self>,
}

impl OxMcpServer {
    pub fn new(
        provider: Arc<dyn CookieProvider>,
        cache: Arc<CookieCache>,
        http_client: Arc<HttpClient>,
    ) -> Self {
        Self {
            provider,
            cache,
            http_client,
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl OxMcpServer {
    #[tool(
        name = "fetch",
        description = "Stealth HTTP fetch via wreq+BoringSSL with TLS fingerprint impersonation. Returns status, headers, body, and Cloudflare detection info."
    )]
    async fn fetch(
        &self,
        Parameters(input): Parameters<FetchInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_fetch(input).await
    }

    #[tool(
        name = "fetch_smart",
        description = "Smart three-tier fetch: fast wreq first, then Cloudflare detection, then headless browser solve + retry. Automatically bypasses CF challenges."
    )]
    async fn fetch_smart(
        &self,
        Parameters(input): Parameters<FetchSmartInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_fetch_smart(input).await
    }

    #[tool(
        name = "analyze",
        description = "Fetch a URL and detect its technology stack (frameworks, CMS, servers) using Wappalyzer-compatible fingerprinting. Returns technologies, meta info, and page assets."
    )]
    async fn analyze(
        &self,
        Parameters(input): Parameters<AnalyzeInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_analyze(input).await
    }

    #[tool(
        name = "solve_cf",
        description = "Solve a Cloudflare challenge (JS challenge, turnstile, managed) using a headless browser. Returns clearance cookies and user agent for subsequent requests."
    )]
    async fn solve_cf(
        &self,
        Parameters(input): Parameters<SolveCfInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_solve_cf(input).await
    }
}
