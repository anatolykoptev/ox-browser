use std::sync::Arc;
use std::time::Duration;

use crate::cookie_cache::CookieCache;
use crate::cookie_provider::CookieProvider;
use crate::profile::BrowserProfile;
use crate::proxy_pool::ProxyPool;
use crate::ratelimit_domain::DomainLimiter;
use crate::retry::RetryConfig;

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
    pub emulation: Option<wreq_util::Emulation>,
    /// External CF challenge solver. When set with `cloudflare_detect`, solver middleware auto-solves challenges.
    pub cookie_provider: Option<Arc<dyn CookieProvider>>,
    /// Cookie cache for solved CF challenges. Shared across sessions.
    pub cookie_cache: Option<Arc<CookieCache>>,
    /// Residential proxy URL for CF bypass retry.
    ///
    /// When set, the residential proxy middleware retries CF-blocked requests
    /// (except Block) through this proxy before falling back to the headless solver.
    pub residential_proxy: Option<String>,
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
        }
    }
}
