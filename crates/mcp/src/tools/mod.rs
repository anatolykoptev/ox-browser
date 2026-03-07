//! MCP tool definitions and routing for ox-browser.

mod analyze;
mod fetch;
mod image_search;
mod security;
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
pub use image_search::ImageSearchInput;
pub use security::SecurityScanInput;
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

    #[tool(
        name = "security_scan",
        description = "Passive security audit of a URL. Checks 15+ HTTP security headers, CSP (with bypass detection and A-F grading), cookies (flags, session, tracker detection), CORS, SRI coverage, third-party supply chain risk, and mixed content. Returns Mozilla Observatory-compatible score (0-135) and grade (F to A+) with detailed findings and severity levels."
    )]
    async fn security_scan(
        &self,
        Parameters(input): Parameters<SecurityScanInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_security_scan(input).await
    }

    #[tool(
        name = "image_search",
        description = "Search for images across multiple engines (bing, ddg, openverse, pexels, brave) with stealth TLS fingerprinting and proxy rotation. Default engines: bing+ddg+openverse. Pexels requires PEXELS_API_KEY env var. Brave must be requested explicitly. Returns image URLs, thumbnails, and source pages. Results are fused and deduplicated."
    )]
    async fn image_search(
        &self,
        Parameters(input): Parameters<ImageSearchInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_image_search(input).await
    }
}
