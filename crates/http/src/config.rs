use std::sync::Arc;
use std::time::Duration;

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
        }
    }
}
