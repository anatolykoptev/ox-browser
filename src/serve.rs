//! HTTP API server startup logic, extracted to keep main.rs small.

use std::sync::Arc;
use std::time::Duration;

use ox_http::{DomainLimiter, HttpClient};
use ox_js::EndpointDefaults;

use crate::config::{self, ServerConfig};

/// Start the HTTP API server with the given configuration.
pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    let cache = config::build_cookie_cache(&config);
    let provider = config::build_cookie_provider(&config);

    let mut http_config = config::build_http_config(&config);
    if let Some(ref proxy) = config.proxy.url {
        http_config.proxy_url = Some(proxy.clone());
    }
    // Env fallback for residential proxy (e.g. RESIDENTIAL_PROXY_URL=http://host:port).
    if http_config.residential_proxy.is_none() {
        http_config.residential_proxy = std::env::var("RESIDENTIAL_PROXY_URL").ok();
    }
    http_config.cookie_provider = Some(Arc::clone(&provider));
    http_config.cookie_cache = Some(Arc::clone(&cache));

    // Per-domain rate limits.
    let domain_configs = config.ratelimit.to_domain_configs();
    if !domain_configs.is_empty() {
        http_config.rate_limiter = Some(Arc::new(DomainLimiter::new(domain_configs)));
        tracing::info!("initialized domain rate limiter with {} rules", config.ratelimit.rules.len());
    }

    // Initialize proxy pool from Webshare API if key is available.
    if let Ok(api_key) = std::env::var("WEBSHARE_API_KEY") {
        if !api_key.is_empty() {
            match ox_http::WebsharePool::new(&api_key).await {
                Ok(pool) => {
                    let health_cfg = config.proxy.health.to_health_config();
                    let healthy = ox_http::HealthyPool::new(Arc::new(pool), health_cfg);
                    http_config.proxy_pool = Some(Arc::new(healthy));
                    tracing::info!("initialized Webshare proxy pool with health tracking");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to init Webshare pool, continuing without proxies");
                }
            }
        }
    }

    let _crawler_defaults = &config.crawler;
    tracing::info!(
        "crawler defaults: depth={}, pages={}, concurrency={}",
        _crawler_defaults.default_max_depth,
        _crawler_defaults.default_max_pages,
        _crawler_defaults.default_concurrency,
    );

    let defaults = EndpointDefaults {
        fetch_timeout_secs: config.fetch.default_timeout_secs,
        smart_timeout_secs: config.fetch.smart_timeout_secs,
        image_max_results: config.images.default_max_results,
        image_min_width: config.images.default_min_width,
        reverse_max_results: 20,
    };

    let media_config = config.media.to_media_config();

    let twitter_config = ox_twitter::login::TwitterLoginConfig {
        timeout: Duration::from_secs(config.twitter.login_timeout_secs),
        max_concurrent: config.twitter.max_concurrent_logins,
        screenshot_on_error: config.twitter.screenshot_on_error,
        screenshot_dir: config.twitter.screenshot_dir.clone().into(),
        default_chrome_path: config.solver.chromium_path.clone()
            .or_else(|| std::env::var("CHROME_PATH").ok()),
        default_proxy: config.proxy.residential_url.clone()
            .or_else(|| std::env::var("RESIDENTIAL_PROXY_URL").ok()),
    };

    let http_client = Arc::new(HttpClient::new(http_config)?);
    let state = ox_js::AppState::new(
        provider,
        cache,
        http_client,
        defaults.clone(),
        media_config.clone(),
        twitter_config,
    );
    let rest_router = ox_js::router(state.clone());
    let mcp_router = ox_mcp::build_mcp_router(
        state.provider.clone(),
        state.cache.clone(),
        state.http_client.clone(),
        defaults,
        media_config,
    );
    let app = rest_router.merge(mcp_router);

    // Background task: clean up media files older than 7 days (runs every 24h)
    ox_media::cleanup::spawn_cleanup_task();

    let addr = format!("{}:{}", config.server.bind, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("ox-browser server listening on {addr} (REST + MCP)");
    axum::serve(listener, app).await?;

    Ok(())
}
