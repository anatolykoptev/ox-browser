//! HTTP API server startup logic, extracted to keep main.rs small.

use std::sync::Arc;
use std::time::Duration;

use ox_http::metrics::SSRF_ALLOWLIST_ENTRIES;
use ox_http::metrics::set_gauge;
use ox_http::validate_allowlist;
use ox_http::{DomainLimiter, HttpClient, cookie_cache, ratelimit_domain, solver_negcache};
use ox_js::EndpointDefaults;

use crate::config::{self, ServerConfig};

/// Start the HTTP API server with the given configuration.
pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    // SSRF allowlist startup validation (issue #28): fail fast before binding
    // any port if the operator allowlisted a private/loopback/link-local/
    // metadata IP or an unparseable entry. A security guard that silently
    // drops a bad entry gives a false sense of safety — refuse to start.
    let allowlist_count = validate_allowlist()?;
    set_gauge(&SSRF_ALLOWLIST_ENTRIES, allowlist_count as u64);
    if allowlist_count > 0 {
        tracing::info!(
            entries = allowlist_count,
            "SSRF allowlist validated: {} entries passed",
            allowlist_count
        );
    }

    let cache = config::build_cookie_cache(&config);
    let provider = config::build_cookie_provider(&config);

    let mut http_config = config::build_http_config(&config);

    if config::proxy_disabled() {
        tracing::warn!("PROXY_DISABLED set — all outbound proxy disabled, fetching direct");
        ox_http::metrics::set_gauge(&ox_http::metrics::PROXY_DISABLED, 1);
        http_config.proxy_url = None;
        http_config.residential_proxy = None;
        http_config.proxy_pool = None;
    } else {
        ox_http::metrics::set_gauge(&ox_http::metrics::PROXY_DISABLED, 0);
        if let Some(ref proxy) = config.proxy.url {
            http_config.proxy_url = Some(proxy.clone());
        }
        // Env fallback for residential proxy (e.g. RESIDENTIAL_PROXY_URL=http://host:port).
        if http_config.residential_proxy.is_none() {
            http_config.residential_proxy = std::env::var("RESIDENTIAL_PROXY_URL").ok();
        }
    }

    http_config.cookie_provider = Some(Arc::clone(&provider));
    http_config.cookie_cache = Some(Arc::clone(&cache));

    // Cookie cache TTL-based eviction (issue #17): without a periodic sweep,
    // entries accumulate per domain forever. Mirror the negcache spawn below.
    cookie_cache::spawn_eviction_task(Arc::clone(&cache), Duration::from_secs(60));

    // Chrome fallback for JS-rendered pages
    if let Ok(url) = std::env::var("GO_BROWSER_URL") {
        http_config.chrome_render_url = Some(format!("{url}/api/v1/chrome/interact"));
        http_config.chrome_render_secret = ox_http::wowa_auth::secret_from_env();
    }
    let render_cache = Arc::new(ox_http::render_cache::RenderModeCache::default());
    // Render cache TTL-based eviction (issue #18): without a periodic sweep,
    // entries accumulate per domain forever. Mirror the cookie cache spawn above.
    ox_http::render_cache::spawn_eviction_task(Arc::clone(&render_cache), Duration::from_secs(60));
    http_config.render_cache = Some(render_cache);

    // Solver negative cache — shared between the solver middleware and read_pipeline
    // so both can check is_blocked() and the pipeline can set RenderMode::GiveUp.
    let negcache = Arc::new(solver_negcache::SolverNegCache::default());
    http_config.solver_negcache = Some(Arc::clone(&negcache));
    solver_negcache::spawn_eviction_task(Arc::clone(&negcache), solver_negcache::DEFAULT_COOLDOWN);

    // Per-domain rate limits.
    let domain_configs = config.ratelimit.to_domain_configs();
    if !domain_configs.is_empty() {
        let rate_limiter = Arc::new(DomainLimiter::new(domain_configs));
        // Periodic eviction of stale per-domain entries so a long-running
        // server doesn't accumulate them forever (issue #20,
        // resource_exhaustion). Mirrors the negcache/cookie-cache spawns.
        ratelimit_domain::spawn_eviction_task(Arc::clone(&rate_limiter), Duration::from_secs(60));
        http_config.rate_limiter = Some(rate_limiter);
        tracing::info!(
            "initialized domain rate limiter with {} rules",
            config.ratelimit.rules.len()
        );
    }

    // Initialize proxy pool from Webshare API if key is available.
    // Skipped entirely when PROXY_DISABLED is set to avoid contacting the Webshare API.
    if !config::proxy_disabled()
        && let Ok(api_key) = std::env::var("WEBSHARE_API_KEY")
        && !api_key.is_empty()
    {
        match ox_http::WebsharePool::new(&api_key).await {
            Ok(pool) => {
                let health_cfg = config.proxy.health.to_health_config();
                let cooldown = health_cfg.cooldown;
                let healthy = Arc::new(ox_http::HealthyPool::new(Arc::new(pool), health_cfg));
                // Periodic eviction of stale deactivated proxy entries so a
                // long-running server doesn't accumulate rotated-out Webshare
                // proxies forever (issue #21, resource_exhaustion). Mirrors the
                // negcache/cookie-cache spawns.
                ox_http::proxy_health::spawn_eviction_task(Arc::clone(&healthy), cooldown);
                http_config.proxy_pool = Some(healthy);
                tracing::info!("initialized Webshare proxy pool with health tracking");
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to init Webshare pool, continuing without proxies");
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

    let gobrowser_url = config
        .solver
        .go_browser_url
        .clone()
        .or_else(|| std::env::var("GO_BROWSER_URL").ok())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8906".to_string());

    tracing::info!(url = %gobrowser_url, "go-browser proxy for /chrome/interact");
    let gobrowser_proxy = Arc::new(ox_js::gobrowser_proxy::GoBrowserProxy::new(
        gobrowser_url,
        &ox_http::wowa_auth::secret_from_env(),
    ));

    let http_client = Arc::new(HttpClient::new(http_config)?);
    let state = ox_js::AppState::new(
        provider,
        cache,
        http_client,
        defaults.clone(),
        media_config.clone(),
        Arc::clone(&gobrowser_proxy),
    );
    let gate = ox_js::inbound_auth::Gate::new(ox_js::inbound_auth::AuthConfig::from_env());
    let app = build_app(state, defaults, media_config, gobrowser_proxy, gate);

    // Background task: clean up media files older than 7 days (runs every 24h)
    ox_media::cleanup::spawn_cleanup_task();

    let addr = format!("{}:{}", config.server.bind, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("ox-browser server listening on {addr} (REST + MCP)");
    // ConnectInfo gives the auth gate the caller IP for its first-sighting log.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Assemble the served app: the REST router merged with the MCP router, the
/// whole thing wrapped by the inbound auth gate so every route and every
/// unmatched path goes through it (ox_js::inbound_auth). `run` and the tests
/// below both call this, so removing the gate here turns a test RED.
pub(crate) fn build_app(
    state: ox_js::AppState,
    defaults: EndpointDefaults,
    media_config: ox_media::MediaConfig,
    gobrowser_proxy: Arc<ox_js::gobrowser_proxy::GoBrowserProxy>,
    gate: ox_js::inbound_auth::Gate,
) -> axum::Router {
    let rest_router = ox_js::router(state.clone());
    let mcp_router = ox_mcp::build_mcp_router(
        state.provider.clone(),
        state.cache.clone(),
        state.http_client.clone(),
        defaults,
        media_config,
        gobrowser_proxy,
    );
    ox_js::inbound_auth::protect(rest_router.merge(mcp_router), gate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ox_js::inbound_auth::{AuthConfig, Gate, Mode};
    use tower::ServiceExt;

    struct NoSolver;

    #[async_trait::async_trait]
    impl ox_http::CookieProvider for NoSolver {
        async fn solve(
            &self,
            _url: &str,
            _ct: ox_http::ChallengeType,
            _authenticated: bool,
        ) -> Result<ox_http::SolvedChallenge, String> {
            Err("none".into())
        }
    }

    fn app() -> axum::Router {
        app_with("http://127.0.0.1:1".into(), "", Mode::Enforce)
    }

    /// The served app with go-wowa at `wowa_url`, ox-browser's outbound go-wowa
    /// secret `wowa_secret`, and the inbound gate in `mode` (inbound secret "s").
    fn app_with(wowa_url: String, wowa_secret: &str, mode: Mode) -> axum::Router {
        app_with_http(wowa_url, wowa_secret, mode, ox_http::HttpConfig::default())
    }

    /// `app_with` plus a custom HttpConfig for the shared HttpClient (used to
    /// point the /read chrome fallback at a capture server).
    fn app_with_http(
        wowa_url: String,
        wowa_secret: &str,
        mode: Mode,
        http_cfg: ox_http::HttpConfig,
    ) -> axum::Router {
        let proxy = Arc::new(ox_js::gobrowser_proxy::GoBrowserProxy::new(
            wowa_url,
            wowa_secret,
        ));
        let state = ox_js::AppState::new(
            Arc::new(NoSolver),
            Arc::new(cookie_cache::CookieCache::new(Duration::from_secs(60))),
            Arc::new(HttpClient::new(http_cfg).unwrap()),
            EndpointDefaults::default(),
            ox_media::MediaConfig::default(),
            Arc::clone(&proxy),
        );
        let gate = Gate::new(AuthConfig {
            internal_secret: "s".into(),
            mcp_token: String::new(),
            mode,
            allow_insecure: false,
        });
        build_app(
            state,
            EndpointDefaults::default(),
            ox_media::MediaConfig::default(),
            proxy,
            gate,
        )
    }

    async fn status(a: &axum::Router, method: &str, path: &str, secret: Option<&str>) -> u16 {
        let mut b = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(s) = secret {
            b = b.header("x-internal-secret", s);
        }
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;
        a.clone()
            .oneshot(b.body(axum::body::Body::from(body)).unwrap())
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    /// The real served app (REST + MCP, as `run` builds it) is gated.
    ///
    /// Falsification: drop `ox_js::inbound_auth::protect(..)` in `build_app`
    /// (return the bare merge) and the unauthenticated rows return the
    /// handlers' statuses → RED. The `/mcp` row is the MCP router itself:
    /// with the right secret it answers the initialize call (not 404),
    /// proving the merged MCP route is what the gate is in front of.
    #[tokio::test]
    async fn served_app_is_gated_including_mcp() {
        let a = app();
        for (m, p) in [
            ("POST", "/mcp"),
            ("POST", "/fetch"),
            ("GET", "/metrics"),
            ("POST", "/nope"),
        ] {
            assert_eq!(
                status(&a, m, p, None).await,
                401,
                "{m} {p} without credential"
            );
        }
        assert_eq!(status(&a, "GET", "/health", None).await, 200);
        let mcp = status(&a, "POST", "/mcp", Some("s")).await;
        assert!(
            mcp != 401 && mcp != 404,
            "authenticated POST /mcp = {mcp}, want the MCP router"
        );
    }

    async fn mcp_post(
        a: &axum::Router,
        inbound_secret: Option<&str>,
        session: Option<&str>,
        body: &str,
    ) -> axum::http::Response<axum::body::Body> {
        let mut b = axum::http::Request::post("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-06-18");
        if let Some(s) = inbound_secret {
            b = b.header("x-internal-secret", s);
        }
        if let Some(id) = session {
            b = b.header("mcp-session-id", id);
        }
        a.clone()
            .oneshot(b.body(axum::body::Body::from(body.to_owned())).unwrap())
            .await
            .unwrap()
    }

    /// Drive the MCP `chrome_interact` tool through the real served app in
    /// SOFT mode and return the request head go-wowa (a capture server)
    /// received.
    async fn mcp_chrome_interact_head(inbound_secret: Option<&str>) -> String {
        let (url, captured) = ox_http::wowa_auth::capture_one(r#"{"status":"ok"}"#).await;
        let a = app_with(url, "wowa-secret", Mode::Soft);
        let init = mcp_post(
            &a,
            inbound_secret,
            None,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
        )
        .await;
        let session = init
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let _ = axum::body::to_bytes(init.into_body(), 1 << 16).await;
        let _ = mcp_post(
            &a,
            inbound_secret,
            session.as_deref(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        )
        .await;
        let call = mcp_post(
            &a,
            inbound_secret,
            session.as_deref(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"chrome_interact","arguments":{"url":"https://example.com","actions":[]}}}"#,
        )
        .await;
        // Read the (SSE) response so the tool call runs to completion.
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            axum::body::to_bytes(call.into_body(), 1 << 20),
        )
        .await;
        tokio::time::timeout(Duration::from_secs(10), captured)
            .await
            .expect("go-wowa capture server was never called")
            .expect("capture")
    }

    /// SEC-CR-009 at the MCP call site: in soft mode an anonymous MCP
    /// `chrome_interact` reaches go-wowa WITHOUT ox-browser's secret; an
    /// authenticated one carries it.
    ///
    /// Falsification: pass `true` instead of `authenticated(&ctx.extensions)`
    /// in the `chrome_interact` tool (crates/mcp/src/tools/mod.rs) and the
    /// anonymous call is relayed with the secret → RED.
    #[tokio::test]
    async fn mcp_chrome_interact_relays_secret_only_when_authenticated() {
        let head = mcp_chrome_interact_head(Some("s")).await;
        assert!(
            head.contains("x-internal-secret: wowa-secret"),
            "authenticated: {head}"
        );
        let head = mcp_chrome_interact_head(None).await;
        assert!(
            !head.contains("x-internal-secret"),
            "anonymous relayed with the secret: {head}"
        );
    }

    /// HttpConfig whose /read chrome fallback goes to `wowa` (a capture
    /// server) with ox-browser's go-wowa secret "wowa-secret", and whose render
    /// cache already says example.com needs Chrome, so /read goes straight to
    /// the fallback.
    fn read_fallback_cfg(wowa: &str) -> ox_http::HttpConfig {
        let rc = Arc::new(ox_http::render_cache::RenderModeCache::default());
        rc.set("example.com", ox_http::render_cache::RenderMode::Chrome);
        ox_http::HttpConfig {
            chrome_render_url: Some(format!("{wowa}/api/v1/chrome/interact")),
            chrome_render_secret: "wowa-secret".into(),
            render_cache: Some(rc),
            ..Default::default()
        }
    }

    const FALLBACK_BODY: &str = r#"{"actions":[{"action":"evaluate","data":"<html><body><p>hello world</p></body></html>"}]}"#;

    async fn rest_read_fallback_head(inbound_secret: Option<&str>) -> String {
        let (wowa, captured) = ox_http::wowa_auth::capture_one(FALLBACK_BODY).await;
        let a = app_with_http(
            "http://127.0.0.1:1".into(),
            "",
            Mode::Soft,
            read_fallback_cfg(&wowa),
        );
        let mut b = axum::http::Request::post("/read").header("content-type", "application/json");
        if let Some(s) = inbound_secret {
            b = b.header("x-internal-secret", s);
        }
        let _ = a
            .oneshot(
                b.body(axum::body::Body::from(r#"{"url":"https://example.com/p"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), captured)
            .await
            .expect("the /read chrome fallback never called go-wowa")
            .expect("capture")
    }

    /// The served app whose CF `CookieProvider` is the REAL GoBrowserSolver
    /// pointed at `wowa_url` (a capture server) with ox-browser's go-wowa
    /// secret "wowa-secret".
    fn app_with_solver(wowa_url: &str) -> axum::Router {
        let provider: Arc<dyn ox_http::CookieProvider> =
            Arc::new(ox_http::solver_gobrowser::GoBrowserSolver::new(
                ox_http::solver_gobrowser::GoBrowserConfig {
                    base_url: wowa_url.into(),
                    timeout: Duration::from_secs(5),
                    internal_secret: "wowa-secret".into(),
                },
            ));
        let proxy = Arc::new(ox_js::gobrowser_proxy::GoBrowserProxy::new(
            "http://127.0.0.1:1".into(),
            "",
        ));
        let state = ox_js::AppState::new(
            provider,
            Arc::new(cookie_cache::CookieCache::new(Duration::from_secs(60))),
            Arc::new(HttpClient::new(ox_http::HttpConfig::default()).unwrap()),
            EndpointDefaults::default(),
            ox_media::MediaConfig::default(),
            Arc::clone(&proxy),
        );
        let gate = Gate::new(AuthConfig {
            internal_secret: "s".into(),
            mcp_token: String::new(),
            mode: Mode::Soft,
            allow_insecure: false,
        });
        build_app(
            state,
            EndpointDefaults::default(),
            ox_media::MediaConfig::default(),
            proxy,
            gate,
        )
    }

    /// SEC-CR-016 / ox-browser#177, REST call site: in soft mode POST /solve
    /// reaches the real GoBrowserSolver — go-wowa gets ox-browser's secret
    /// only when the inbound request carried the internal secret (the
    /// `ok_secret` marker). Anonymous and bearer-free requests get a
    /// credential-free solve.
    ///
    /// Falsification: replace `auth.is_some()` with `true` in
    /// crates/js/src/solve.rs and the anonymous /solve is relayed with the
    /// secret → RED; with `false` the authenticated row loses it → RED.
    #[tokio::test]
    async fn rest_solve_relays_secret_only_when_authenticated() {
        for (inbound, want_secret) in [(Some("s"), true), (None, false)] {
            let (wowa, captured) = ox_http::wowa_auth::capture_one(
                r#"{"status":"ok","cookies":{"cf_clearance":"t"},"user_agent":"UA"}"#,
            )
            .await;
            let a = app_with_solver(&wowa);
            let mut b =
                axum::http::Request::post("/solve").header("content-type", "application/json");
            if let Some(s) = inbound {
                b = b.header("x-internal-secret", s);
            }
            let resp = a
                .oneshot(
                    b.body(axum::body::Body::from(
                        r#"{"url":"https://example.com/p","challenge_type":"js_challenge"}"#,
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "inbound={inbound:?}");
            let head = captured.await.expect("capture");
            assert_eq!(
                head.contains("x-internal-secret: wowa-secret"),
                want_secret,
                "inbound={inbound:?}: {head}"
            );
        }
    }

    /// SEC-CR-014, REST call site: in soft mode, POST /read reaches the chrome
    /// fallback; go-wowa gets ox-browser's secret only when the inbound
    /// request carried the internal secret.
    ///
    /// Falsification: replace `auth.is_some()` with `true` in
    /// crates/js/src/read.rs and the anonymous /read is relayed with the
    /// secret → RED.
    #[tokio::test]
    async fn rest_read_fallback_relays_secret_only_when_authenticated() {
        let head = rest_read_fallback_head(Some("s")).await;
        assert!(
            head.contains("x-internal-secret: wowa-secret"),
            "authenticated: {head}"
        );
        let head = rest_read_fallback_head(None).await;
        assert!(
            !head.contains("x-internal-secret"),
            "anonymous /read relayed with the secret: {head}"
        );
    }

    async fn mcp_read_fallback_head(inbound_secret: Option<&str>) -> String {
        let (wowa, captured) = ox_http::wowa_auth::capture_one(FALLBACK_BODY).await;
        let a = app_with_http(
            "http://127.0.0.1:1".into(),
            "",
            Mode::Soft,
            read_fallback_cfg(&wowa),
        );
        let init = mcp_post(
            &a,
            inbound_secret,
            None,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
        )
        .await;
        let session = init
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let _ = axum::body::to_bytes(init.into_body(), 1 << 16).await;
        let _ = mcp_post(
            &a,
            inbound_secret,
            session.as_deref(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        )
        .await;
        let call = mcp_post(
            &a,
            inbound_secret,
            session.as_deref(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read","arguments":{"url":"https://example.com/p"}}}"#,
        )
        .await;
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            axum::body::to_bytes(call.into_body(), 1 << 20),
        )
        .await;
        tokio::time::timeout(Duration::from_secs(10), captured)
            .await
            .expect("the MCP read chrome fallback never called go-wowa")
            .expect("capture")
    }

    /// SEC-CR-014, MCP call site: the MCP `read` tool relays the secret to
    /// the chrome fallback only when the inbound request carried it.
    ///
    /// Falsification: replace `chrome_interact::authenticated(&ctx.extensions)`
    /// with `true` in the `read` tool (crates/mcp/src/tools/mod.rs) and the
    /// anonymous MCP read is relayed with the secret → RED.
    #[tokio::test]
    async fn mcp_read_fallback_relays_secret_only_when_authenticated() {
        let head = mcp_read_fallback_head(Some("s")).await;
        assert!(
            head.contains("x-internal-secret: wowa-secret"),
            "authenticated: {head}"
        );
        let head = mcp_read_fallback_head(None).await;
        assert!(
            !head.contains("x-internal-secret"),
            "anonymous MCP read relayed with the secret: {head}"
        );
    }
}
