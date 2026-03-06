//! HTTP API server startup logic, extracted to keep main.rs small.

use std::sync::Arc;
use std::time::Duration;

use ox_http::{
    ByparrConfig, ByparrSolver, ChallengeType, CookieCache, CookieProvider,
    HttpClient, HttpConfig, SolvedChallenge,
};
use wreq_util::Emulation;

/// No-op solver used when no Byparr URL is configured.
struct NoOpProvider;

#[async_trait::async_trait]
impl CookieProvider for NoOpProvider {
    async fn solve(
        &self,
        _url: &str,
        _ct: ChallengeType,
    ) -> Result<SolvedChallenge, String> {
        Err("no solver configured".into())
    }
}

/// Start the HTTP API server with the given configuration.
pub async fn run(
    port: u16,
    byparr_url: Option<String>,
    proxy_url: Option<String>,
    debug: bool,
) -> anyhow::Result<()> {
    let mut config = HttpConfig {
        cloudflare_detect: true,
        debug,
        emulation: Some(Emulation::Chrome136),
        ..Default::default()
    };

    if let Some(ref proxy) = proxy_url {
        config.proxy_url = Some(proxy.clone());
    }

    let cache = Arc::new(CookieCache::new(Duration::from_secs(25 * 60)));

    let provider: Arc<dyn CookieProvider> = if let Some(ref url) = byparr_url {
        Arc::new(ByparrSolver::new(ByparrConfig {
            base_url: url.clone(),
            timeout: Duration::from_secs(60),
        }))
    } else {
        Arc::new(NoOpProvider)
    };

    config.cookie_provider = Some(Arc::clone(&provider));
    config.cookie_cache = Some(Arc::clone(&cache));

    let http_client = Arc::new(HttpClient::new(config)?);
    let state = ox_js::AppState {
        provider,
        cache,
        http_client,
    };
    let app = ox_js::router(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    tracing::info!("ox-browser server listening on :{port}");
    axum::serve(listener, app).await?;

    Ok(())
}
