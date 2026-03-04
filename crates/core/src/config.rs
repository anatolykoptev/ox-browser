use std::sync::Arc;
use std::time::Duration;

use ox_http::profile::BrowserProfile;
use ox_http::proxy_pool::ProxyPool;
use ox_http::retry::RetryConfig;

pub struct BrowserConfig {
    pub timeout: Duration,
    pub user_agent: String,
    pub proxy_url: Option<String>,
    pub max_redirects: usize,
    pub concurrency: usize,
    /// Browser profile for realistic headers and client hints.
    pub profile: Option<&'static BrowserProfile>,
    /// Rotating proxy pool (overrides `proxy_url` when set).
    pub proxy_pool: Option<Arc<dyn ProxyPool>>,
    /// Retry configuration for transient failures.
    pub retry: Option<RetryConfig>,
    /// Enable debug logging middleware.
    pub debug: bool,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            user_agent: format!("ox-browser/{}", env!("CARGO_PKG_VERSION")),
            proxy_url: None,
            max_redirects: 10,
            concurrency: 3,
            profile: None,
            proxy_pool: None,
            retry: None,
            debug: false,
        }
    }
}
