//! HTTP API server startup logic, extracted to keep main.rs small.

use std::sync::Arc;

use ox_http::HttpClient;
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

    let http_client = Arc::new(HttpClient::new(http_config)?);
    let state = ox_js::AppState {
        provider,
        cache,
        http_client,
        defaults: defaults.clone(),
        media_config: media_config.clone(),
    };
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
