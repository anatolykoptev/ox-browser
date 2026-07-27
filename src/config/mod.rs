//! TOML-based runtime configuration split by responsibility.
//!
//! Priority: defaults → config.toml → env vars → CLI args.
//!
//! Each section lives in its own module:
//! - `server` — bind address, port
//! - `http` — timeout, redirects, TLS emulation
//! - `retry` — exponential backoff parameters
//! - `cache` — cookie cache TTL
//! - `proxy` — proxy URL, webshare, health tracking
//! - `solver` — Byparr/FlareSolverr challenge solver
//! - `cloudflare` — CF detection toggle
//! - `log` — log level
//! - `fetch` — default timeouts for fetch endpoints
//! - `images` — image search/extraction defaults

mod cache;
mod chrome;
mod cloudflare;
mod crawler;
mod fetch;
mod http;
mod images;
mod log;
mod media;
mod proxy;
mod ratelimit;
mod retry;
mod server;
mod solver;

pub use cache::CacheSection;
pub use chrome::ChromeSection;
pub use cloudflare::CloudflareSection;
pub use crawler::CrawlerSection;
pub use fetch::FetchSection;
pub use http::HttpSection;
pub use images::ImagesSection;
pub use log::LogSection;
pub use media::MediaSection;
pub use proxy::ProxySection;
pub use ratelimit::RatelimitSection;
pub use retry::RetrySection;
pub use server::ServerSection;
pub use solver::SolverSection;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ox_http::{
    ByparrConfig, ByparrSolver, ChallengeType, CookieCache, CookieProvider, HttpConfig,
    SolvedChallenge,
};
use serde::Deserialize;

/// Top-level configuration loaded from TOML.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub http: HttpSection,
    pub retry: RetrySection,
    pub cache: CacheSection,
    pub proxy: ProxySection,
    pub solver: SolverSection,
    pub cloudflare: CloudflareSection,
    pub log: LogSection,
    pub fetch: FetchSection,
    pub images: ImagesSection,
    pub crawler: CrawlerSection,
    pub media: MediaSection,
    pub ratelimit: RatelimitSection,
    pub chrome: ChromeSection,
}

impl ServerConfig {
    /// Load config from TOML file. Returns defaults if file doesn't exist.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            tracing::info!("no config file at {}, using defaults", path.display());
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        tracing::info!("loaded config from {}", path.display());
        Ok(config)
    }

    /// Apply CLI overrides (Some values replace config, None keeps config).
    pub fn apply_cli_overrides(
        &mut self,
        port: Option<u16>,
        byparr_url: Option<String>,
        proxy_url: Option<String>,
        debug: bool,
    ) {
        if let Some(p) = port {
            self.server.port = p;
        }
        if let Some(url) = byparr_url {
            self.solver.byparr_url = Some(url);
        }
        if let Some(url) = proxy_url {
            self.proxy.url = Some(url);
        }
        if debug {
            self.log.level = "debug".into();
        }
    }
}

/// Reports whether outbound proxy is disabled via the `PROXY_DISABLED` env var.
///
/// Truthy values (case-insensitive, whitespace-trimmed): `"1"`, `"true"`, `"yes"`, `"on"`.
/// Anything else (including unset) = proxy enabled.
pub fn proxy_disabled() -> bool {
    std::env::var("PROXY_DISABLED")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

// --- Builder functions ---

/// No-op solver used when no Byparr URL is configured.
struct NoOpProvider;

#[async_trait::async_trait]
impl CookieProvider for NoOpProvider {
    async fn solve(&self, _url: &str, _ct: ChallengeType) -> Result<SolvedChallenge, String> {
        Err("no solver configured".into())
    }
}

/// Build the cookie provider from config.
///
/// Priority: go_browser_url → byparr_url → NoOp.
///
/// When no solver is configured the NoOpProvider is selected — it only errors
/// "no solver configured" at solve time, which is a silent downgrade. To make
/// that loud we emit a `tracing::warn!` naming NoOpProvider here and set the
/// `oxbrowser_solver_configured` gauge to 0 (1 when a real solver is selected)
/// so operators scraping Prometheus can alert on it (issue #29).
pub fn build_cookie_provider(config: &ServerConfig) -> Arc<dyn CookieProvider> {
    // Highest priority: go-browser HTTP solver
    let go_browser_url = config
        .solver
        .go_browser_url
        .clone()
        .or_else(|| std::env::var("GO_BROWSER_URL").ok());
    if let Some(ref url) = go_browser_url
        && !url.is_empty()
    {
        let cfg = ox_http::solver_gobrowser::GoBrowserConfig {
            base_url: url.clone(),
            timeout: Duration::from_secs(config.solver.chromium_timeout_secs + 5),
        };
        tracing::info!(url, "using GoBrowserSolver");
        ox_http::metrics::set_gauge(&ox_http::metrics::SOLVER_CONFIGURED, 1);
        return Arc::new(ox_http::solver_gobrowser::GoBrowserSolver::new(cfg));
    }

    if let Some(ref url) = config.solver.byparr_url {
        ox_http::metrics::set_gauge(&ox_http::metrics::SOLVER_CONFIGURED, 1);
        Arc::new(ByparrSolver::new(ByparrConfig {
            base_url: url.clone(),
            timeout: Duration::from_secs(config.solver.byparr_timeout_secs),
            memory_budget_mb: config.solver.byparr_memory_mb,
        }))
    } else {
        tracing::warn!(
            "no solver configured (GO_BROWSER_URL unset and byparr_url empty) — \
             falling back to NoOpProvider; CF challenges will fail at solve time"
        );
        ox_http::metrics::set_gauge(&ox_http::metrics::SOLVER_CONFIGURED, 0);
        Arc::new(NoOpProvider)
    }
}

/// Build the cookie cache from config.
pub fn build_cookie_cache(config: &ServerConfig) -> Arc<CookieCache> {
    Arc::new(CookieCache::new(Duration::from_secs(
        config.cache.cookie_ttl_secs,
    )))
}

/// Build HttpConfig from ServerConfig.
pub fn build_http_config(config: &ServerConfig) -> HttpConfig {
    HttpConfig {
        timeout: Duration::from_secs(config.http.timeout_secs),
        max_redirects: config.http.max_redirects,
        cloudflare_detect: config.cloudflare.detect,
        debug: config.log.level == "debug",
        emulation: config.http.emulation(),
        retry: Some(config.retry.to_retry_config()),
        residential_proxy: config.proxy.residential_url.clone(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All PROXY_DISABLED env assertions live in ONE test function to avoid
    /// cross-test races (env vars are process-global).
    ///
    /// # Safety
    /// `set_var`/`remove_var` are unsafe in edition 2024 due to thread-unsafety.
    /// This is a single-threaded test binary path (cargo test serializes tests
    /// in the same binary unless `--test-threads` > 1). We accept the unsafety
    /// and run all assertions in one function to minimise the window.
    #[test]
    fn proxy_disabled_env_parsing() {
        // SAFETY: single test function, no concurrent env mutation.
        unsafe {
            // Unset → proxy enabled (false)
            std::env::remove_var("PROXY_DISABLED");
            assert!(!proxy_disabled(), "unset should be false");

            // Truthy values
            for val in &[
                "1", "true", "TRUE", "True", "yes", "YES", "Yes", "on", "ON", "On",
            ] {
                std::env::set_var("PROXY_DISABLED", val);
                assert!(proxy_disabled(), "PROXY_DISABLED={val} should be true");
            }

            // Falsy / unknown values
            for val in &[
                "0", "false", "FALSE", "no", "off", "", "garbage", "2", "enabled",
            ] {
                std::env::set_var("PROXY_DISABLED", val);
                assert!(!proxy_disabled(), "PROXY_DISABLED={val} should be false");
            }

            // Whitespace around value should be ignored
            std::env::set_var("PROXY_DISABLED", "  true  ");
            assert!(proxy_disabled(), "PROXY_DISABLED=' true ' should be true");

            // Clean up
            std::env::remove_var("PROXY_DISABLED");
        }
    }

    #[test]
    fn defaults_match_previous_hardcoded_values() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.server.port, 8901);
        assert_eq!(cfg.server.bind, "0.0.0.0");
        assert_eq!(cfg.http.timeout_secs, 20);
        assert_eq!(cfg.http.max_redirects, 10);
        assert_eq!(cfg.http.emulation, "chrome136");
        assert_eq!(cfg.retry.max_retries, 3);
        assert_eq!(cfg.retry.initial_wait_ms, 500);
        assert_eq!(cfg.retry.max_wait_ms, 10_000);
        assert_eq!(cfg.retry.multiplier, 2.0);
        assert_eq!(cfg.retry.jitter_pct, 0.3);
        assert_eq!(cfg.cache.cookie_ttl_secs, 1500);
        assert!(cfg.proxy.url.is_none());
        assert_eq!(cfg.proxy.health.failure_threshold, 0.5);
        assert_eq!(cfg.proxy.health.min_requests, 3);
        assert_eq!(cfg.proxy.health.cooldown_secs, 300);
        assert!(cfg.solver.byparr_url.is_none());
        assert_eq!(cfg.solver.byparr_timeout_secs, 60);
        assert_eq!(cfg.solver.byparr_memory_mb, 768);
        assert!(cfg.cloudflare.detect);
        assert_eq!(cfg.log.level, "info");
        assert_eq!(cfg.fetch.default_timeout_secs, 15);
        assert_eq!(cfg.fetch.smart_timeout_secs, 30);
        assert_eq!(cfg.images.default_max_results, 10);
        assert_eq!(cfg.images.default_min_width, 400);
        assert_eq!(cfg.images.min_dimension, 200);
        assert_eq!(cfg.images.rrf_k, 60.0);
    }

    #[test]
    fn parse_full_toml() {
        let toml = r#"
[server]
port = 9000
bind = "127.0.0.1"

[http]
timeout_secs = 30
max_redirects = 5
emulation = "safari18"

[retry]
max_retries = 5
initial_wait_ms = 1000
max_wait_ms = 30000
multiplier = 3.0
jitter_pct = 0.1

[cache]
cookie_ttl_secs = 3600

[proxy]
url = "http://proxy:8080"
webshare_timeout_secs = 15

[proxy.health]
failure_threshold = 0.3
min_requests = 5
cooldown_secs = 600

[solver]
byparr_url = "http://solver:8191"
byparr_timeout_secs = 120

[cloudflare]
detect = false

[log]
level = "debug"
"#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.server.port, 9000);
        assert_eq!(cfg.server.bind, "127.0.0.1");
        assert_eq!(cfg.http.timeout_secs, 30);
        assert_eq!(cfg.http.max_redirects, 5);
        assert_eq!(cfg.http.emulation, "safari18");
        assert_eq!(cfg.retry.max_retries, 5);
        assert_eq!(cfg.retry.initial_wait_ms, 1000);
        assert_eq!(cfg.cache.cookie_ttl_secs, 3600);
        assert_eq!(cfg.proxy.url.as_deref(), Some("http://proxy:8080"));
        assert_eq!(cfg.proxy.health.failure_threshold, 0.3);
        assert_eq!(cfg.solver.byparr_url.as_deref(), Some("http://solver:8191"));
        assert_eq!(cfg.solver.byparr_timeout_secs, 120);
        assert!(!cfg.cloudflare.detect);
        assert_eq!(cfg.log.level, "debug");
    }

    #[test]
    fn parse_partial_toml_uses_defaults() {
        let toml = r#"
[server]
port = 9999
"#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.server.port, 9999);
        assert_eq!(cfg.http.timeout_secs, 20);
        assert_eq!(cfg.retry.max_retries, 3);
        assert!(cfg.cloudflare.detect);
    }

    #[test]
    fn empty_toml_gives_defaults() {
        let cfg: ServerConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.server.port, 8901);
        assert_eq!(cfg.http.timeout_secs, 20);
    }

    #[test]
    fn cli_overrides_apply() {
        let mut cfg = ServerConfig::default();
        cfg.apply_cli_overrides(
            Some(3000),
            Some("http://x".into()),
            Some("http://p".into()),
            true,
        );
        assert_eq!(cfg.server.port, 3000);
        assert_eq!(cfg.solver.byparr_url.as_deref(), Some("http://x"));
        assert_eq!(cfg.proxy.url.as_deref(), Some("http://p"));
        assert_eq!(cfg.log.level, "debug");
    }

    #[test]
    fn cli_none_keeps_config() {
        let mut cfg = ServerConfig::default();
        cfg.server.port = 7777;
        cfg.apply_cli_overrides(None, None, None, false);
        assert_eq!(cfg.server.port, 7777);
    }

    #[test]
    fn build_http_config_from_defaults() {
        let cfg = ServerConfig::default();
        let http = build_http_config(&cfg);
        assert_eq!(http.timeout, Duration::from_secs(20));
        assert_eq!(http.max_redirects, 10);
        assert!(http.cloudflare_detect);
        assert!(!http.debug);
        assert!(http.retry.is_some());
    }

    #[test]
    fn load_nonexistent_file_returns_defaults() {
        let cfg = ServerConfig::load(Path::new("/nonexistent/config.toml")).unwrap();
        assert_eq!(cfg.server.port, 8901);
    }
}
