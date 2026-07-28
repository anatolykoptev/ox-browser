use std::sync::Arc;
use std::time::Duration;

use crate::cookie_cache::CookieCache;
use crate::cookie_provider::CookieProvider;
use crate::profile::BrowserProfile;
use crate::proxy_pool::ProxyPool;
use crate::ratelimit_domain::DomainLimiter;
use crate::retry::RetryConfig;
use crate::solver_negcache::SolverNegCache;

/// HTTP client configuration.
///
/// New Phase 1.5 fields all default to `None`/`false`, so existing code
/// using `HttpConfig { timeout, user_agent, proxy_url, max_redirects,
/// ..Default::default() }` continues to work unchanged.
pub struct HttpConfig {
    // --- v0.1.0 fields ---
    pub timeout: Duration,
    pub user_agent: String,
    pub proxy_url: Option<String>,
    pub max_redirects: usize,

    // --- Phase 1.5 fields (all optional for backward compat) ---
    /// Browser profile for realistic headers and client hints.
    pub profile: Option<&'static BrowserProfile>,
    /// Rotating proxy pool (overrides `proxy_url` when set).
    pub proxy_pool: Option<Arc<dyn ProxyPool>>,
    /// Retry configuration for transient failures.
    pub retry: Option<RetryConfig>,
    /// Per-domain rate limiter.
    pub rate_limiter: Option<Arc<DomainLimiter>>,
    /// Enable Cloudflare challenge detection (converts CF responses to errors).
    /// Works best with retry middleware — retries use a different proxy.
    pub cloudflare_detect: bool,
    /// Enable debug logging middleware.
    pub debug: bool,
    /// Browser emulation for TLS/HTTP2 fingerprinting (wreq BoringSSL).
    /// Uses wreq::Emulation (the struct) not wreq_util::Emulation (the enum)
    /// so we can build custom emulations from scratch (tls.rs) for Chrome/Edge
    /// while still using wreq-util presets for Firefox/Safari.
    pub emulation: Option<wreq::Emulation>,
    /// External CF challenge solver. When set with `cloudflare_detect`, solver middleware auto-solves challenges.
    pub cookie_provider: Option<Arc<dyn CookieProvider>>,
    /// Cookie cache for solved CF challenges. Shared across sessions.
    pub cookie_cache: Option<Arc<CookieCache>>,
    /// Residential proxy URL for CF bypass retry.
    ///
    /// When set, the residential proxy middleware retries CF-blocked requests
    /// (except Block) through this proxy before falling back to the headless solver.
    pub residential_proxy: Option<String>,
    /// Enable quality-check middleware (converts 401/403/429/503 to CF challenge errors).
    /// Default: true. Disable for APIs where 403 is a real auth error (e.g., Twitter).
    pub quality_check: bool,
    /// Chrome render endpoint for JS-heavy fallback (e.g. "http://go-wowa:8906/api/v1/chrome/interact").
    pub chrome_render_url: Option<String>,
    /// Per-domain render mode cache (shared, thread-safe).
    pub render_cache: Option<Arc<crate::render_cache::RenderModeCache>>,
    /// Solver negative cache — shared with the solver middleware so read_pipeline
    /// can check `is_blocked` and set `RenderMode::GiveUp` instead of
    /// `RenderMode::Chrome` when the domain is on cooldown.
    pub solver_negcache: Option<Arc<SolverNegCache>>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            user_agent: format!("ox-browser/{}", env!("CARGO_PKG_VERSION")),
            proxy_url: None,
            max_redirects: 10,
            profile: None,
            proxy_pool: None,
            retry: None,
            rate_limiter: None,
            cloudflare_detect: false,
            debug: false,
            emulation: None,
            cookie_provider: None,
            cookie_cache: None,
            residential_proxy: None,
            quality_check: true,
            chrome_render_url: None,
            render_cache: None,
            solver_negcache: None,
        }
    }
}
