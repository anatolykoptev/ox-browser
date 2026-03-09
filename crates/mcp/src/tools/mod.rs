//! MCP tool definitions and routing for ox-browser.

mod analyze;
mod crawl;
mod fetch;
mod image_extract;
mod image_search;
mod media_download;
mod readability;
mod security;
mod site_audit;
mod solve;

use std::sync::Arc;

use ox_http::{CookieCache, CookieProvider, HttpClient};
use ox_js::EndpointDefaults;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use rmcp::{tool, tool_router};

pub use analyze::AnalyzeInput;
pub use fetch::{FetchInput, FetchSmartInput};
pub use image_extract::ImageExtractInput;
pub use media_download::MediaDownloadInput;
pub use image_search::ImageSearchInput;
pub use readability::ReadabilityInput;
pub use security::SecurityScanInput;
pub use crawl::CrawlInput;
pub use site_audit::SiteAuditInput;
pub use solve::SolveCfInput;

/// MCP server exposing ox-browser capabilities as tools.
#[derive(Clone)]
pub struct OxMcpServer {
    pub(crate) provider: Arc<dyn CookieProvider>,
    pub(crate) cache: Arc<CookieCache>,
    pub(crate) http_client: Arc<HttpClient>,
    pub(crate) defaults: EndpointDefaults,
    pub(crate) tool_router: ToolRouter<Self>,
}

impl OxMcpServer {
    pub fn new(
        provider: Arc<dyn CookieProvider>,
        cache: Arc<CookieCache>,
        http_client: Arc<HttpClient>,
        defaults: EndpointDefaults,
    ) -> Self {
        Self {
            provider,
            cache,
            http_client,
            defaults,
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
        description = "Full site intelligence analysis. Detects 7,000+ technologies via Wappalyzer fingerprinting (with categories and versions). Runs 8 intelligence modules: SEO (OG tags, JSON-LD, hreflang, score), performance (resource hints, preload, lazy loading), accessibility (alt text, ARIA, headings), content (iframes, embeds, structure), media (video/audio sources), fonts (Google/Adobe/custom), PWA (manifest, service worker), and API discovery (endpoints, GraphQL). Returns comprehensive site profile."
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
        name = "readability",
        description = "Extract article content from a URL using Mozilla Readability algorithm. Removes navigation, ads, sidebars — returns clean article text. Supports plain text or HTML output. Use for reading website content, place descriptions, blog posts, news articles."
    )]
    async fn readability(
        &self,
        Parameters(input): Parameters<ReadabilityInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_readability(input).await
    }

    #[tool(
        name = "image_extract",
        description = "Extract candidate photos from a webpage. Fetches the URL, parses all <img>, <picture>, og:image, and CSS background-image URLs. Filters out logos, icons, SVGs, GIFs, tiny images, and data URIs. Returns full-size image URLs sorted by priority (og:image first). Use for grabbing photos from a place's official website."
    )]
    async fn image_extract(
        &self,
        Parameters(input): Parameters<ImageExtractInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_image_extract(input).await
    }

    #[tool(
        name = "image_search",
        description = "Search for images across multiple engines with stealth TLS fingerprinting and proxy rotation. Default: bing+ddg+openverse. Opt-in: pexels (needs PEXELS_API_KEY), brave. Returns image URLs, thumbnails, and source pages. Results are fused and deduplicated."
    )]
    async fn image_search(
        &self,
        Parameters(input): Parameters<ImageSearchInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_image_search(input).await
    }

    #[tool(
        name = "crawl",
        description = "Site crawler with BFS, sitemap, or hybrid discovery. Starts from seed URL, discovers pages via links or sitemap.xml. Respects robots.txt, deduplicates URLs and content, converts HTML to markdown. Supports sitemap filtering, date-based filtering, and file output."
    )]
    async fn crawl(
        &self,
        Parameters(input): Parameters<CrawlInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_crawl(input).await
    }

    #[tool(
        name = "media_download",
        description = "Download video or extract images from any URL. Fetches the page, finds media (video tags, og:video, og:image, img tags, JSON-LD, inline JS), downloads files. For YouTube: parses player data for direct video URLs. Returns file paths and metadata."
    )]
    async fn media_download(
        &self,
        Parameters(input): Parameters<MediaDownloadInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_media_download(input).await
    }

    #[tool(
        name = "site_audit",
        description = "Comprehensive site audit with scores and actionable recommendations. Analyzes SEO (meta tags, OG, structured data), performance (compression, caching, lazy loading), accessibility (lang, alt text, headings, ARIA), and security (headers, CSP, cookies, CORS). Returns overall score (0-100), per-category grades (A+ to F), prioritized findings with fix instructions. Use focus parameter to narrow: \"seo\", \"performance\", \"accessibility\", \"security\", or \"all\" (default)."
    )]
    async fn site_audit(
        &self,
        Parameters(input): Parameters<SiteAuditInput>,
    ) -> Result<CallToolResult, McpError> {
        self.do_site_audit(input).await
    }
}
