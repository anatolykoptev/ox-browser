use std::sync::Arc;

use wreq::Client;

use crate::handler_reqwest::WreqHandler;
use crate::middleware::{Handler, MiddlewareFn, Request, chain};
use crate::middleware_cloudflare::cloudflare_detect_middleware;
use crate::middleware_hints::client_hints_middleware;
use crate::middleware_logging::logging_middleware;
use crate::middleware_ratelimit::rate_limit_middleware;
use crate::middleware_residential::residential_proxy_middleware;
use crate::middleware_retry::retry_middleware;
use crate::middleware_solver::solver_middleware;
use crate::middleware_ssrf::ssrf_middleware;
use crate::profile_hints::browser_headers;
use crate::{HttpConfig, HttpError, HttpResponse, Result};

/// HTTP client that routes requests through a middleware chain.
///
/// When no Phase 1.5 options are set, behavior is identical to v0.1.0:
/// direct wreq calls with timeout, user-agent, redirects, and cookies.
pub struct HttpClient {
    handler: Arc<dyn Handler>,
    config: HttpConfig,
}

impl HttpClient {
    /// Build the client and its middleware chain from config.
    ///
    /// Chain order (outermost first):
    /// `[logging?] -> [rate_limit?] -> [retry?] -> [solver?] -> [residential?] -> [cloudflare?] -> [quality_check] -> [client_hints] -> wreq`
    pub fn new(config: HttpConfig) -> Result<Self> {
        let client = Self::build_wreq_client(&config)?;
        // A sibling client with no proxy, used as a direct-connection fallback
        // when an upstream proxy returns HTTP 402 Payment Required.
        let direct_client = Self::build_direct_wreq_client(&config)?;
        let needs_fallback =
            config.proxy_url.is_some() || config.proxy_pool.is_some();
        let base: Arc<dyn Handler> = if let Some(ref pool) = config.proxy_pool {
            Arc::new(
                WreqHandler::with_proxy_pool(client, Arc::clone(pool))
                    .with_direct_fallback(direct_client),
            )
        } else if needs_fallback {
            Arc::new(WreqHandler::new(client).with_direct_fallback(direct_client))
        } else {
            Arc::new(WreqHandler::new(client))
        };

        let mut middlewares: Vec<MiddlewareFn> = Vec::new();

        // Outermost: SSRF protection (before any other processing).
        middlewares.push(ssrf_middleware());

        // Logging (only when debug enabled).
        if config.debug {
            middlewares.push(logging_middleware());
        }

        // Rate limiting (before retry, so retries also respect limits).
        if let Some(ref limiter) = config.rate_limiter {
            middlewares.push(rate_limit_middleware(Arc::clone(limiter)));
        }

        // Retry with exponential backoff.
        if let Some(ref retry_cfg) = config.retry {
            middlewares.push(retry_middleware(retry_cfg.clone()));
        }

        // CF solver (between retry and cloudflare_detect).
        if let (Some(provider), Some(cache)) = (&config.cookie_provider, &config.cookie_cache) {
            middlewares.push(solver_middleware(Arc::clone(provider), Arc::clone(cache)));
        }

        // Residential proxy retry (between solver and cloudflare_detect).
        // On CF error, retries once with residential IP before falling back to solver.
        if let Some(ref proxy) = config.residential_proxy {
            middlewares.push(residential_proxy_middleware(proxy.clone()));
        }

        // Cloudflare detection (inside retry so CF triggers auto-retry).
        if config.cloudflare_detect {
            middlewares.push(cloudflare_detect_middleware());
        }

        // Quality check: convert anti-bot 200s and non-CF errors (401/403/429/503)
        // to CF challenge errors so the solver middleware can handle them.
        if config.quality_check {
            middlewares.push(crate::middleware_quality::quality_check_middleware());
        }

        // Innermost middleware: auto-inject client hints.
        middlewares.push(client_hints_middleware());

        let handler = chain(middlewares, base);
        Ok(Self { handler, config })
    }

    /// Execute a GET request.
    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        let req = self.build_request("GET", url, None, None);
        self.handler.handle(req).await
    }

    /// Execute a GET request with extra headers appended after the defaults.
    pub async fn get_with_headers(
        &self,
        url: &str,
        extra_headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let mut req = self.build_request("GET", url, None, None);
        for &(k, v) in extra_headers {
            req.headers.push((k.to_owned(), v.to_owned()));
        }
        self.handler.handle(req).await
    }

    /// Execute a pre-built Request through the middleware chain.
    ///
    /// Use this when you need full control over headers (e.g., Twitter header ordering).
    pub async fn execute(&self, req: Request) -> Result<HttpResponse> {
        self.handler.handle(req).await
    }

    /// Execute a POST request with a text body and content type.
    pub async fn post(&self, url: &str, body: &str, content_type: &str) -> Result<HttpResponse> {
        let req = self.build_request(
            "POST",
            url,
            Some(body.as_bytes().to_vec()),
            Some(content_type),
        );
        self.handler.handle(req).await
    }

    /// Build a [`Request`] with profile-based or fallback headers.
    fn build_request(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
    ) -> Request {
        let mut headers = if let Some(profile) = self.config.profile {
            browser_headers(profile)
        } else {
            vec![("user-agent".to_owned(), self.config.user_agent.clone())]
        };

        if let Some(ct) = content_type {
            headers.push(("content-type".to_owned(), ct.to_owned()));
        }

        Request {
            method: method.to_owned(),
            url: url.to_owned(),
            headers,
            body,
            proxy: None,
        }
    }

    /// Expose config for pipeline consumers (e.g. Chrome fallback).
    pub fn config(&self) -> &HttpConfig {
        &self.config
    }

    /// Build the underlying wreq client from config.
    fn build_wreq_client(config: &HttpConfig) -> Result<Client> {
        let mut builder = Client::builder()
            .timeout(config.timeout)
            .redirect(wreq::redirect::Policy::limited(config.max_redirects))
            .cookie_store(true);

        // Static proxy (proxy_pool is handled per-request in WreqHandler).
        if let Some(ref proxy_url) = config.proxy_url {
            let proxy =
                wreq::Proxy::all(proxy_url).map_err(|e| HttpError::InvalidUrl(e.to_string()))?;
            builder = builder.proxy(proxy);
        }

        // Browser emulation for Chrome-identical TLS/HTTP2 fingerprints.
        if let Some(emulation) = config.emulation {
            builder = builder.emulation(emulation);
        }

        // Note: we do NOT set .user_agent() on the builder — headers are
        // managed by the middleware chain (profile headers or fallback UA).

        Ok(builder.build()?)
    }

    /// Build a wreq client identical to [`build_wreq_client`] but with no
    /// proxy. Used as the direct-connection fallback when Webshare returns
    /// HTTP 402.
    fn build_direct_wreq_client(config: &HttpConfig) -> Result<Client> {
        let mut builder = Client::builder()
            .timeout(config.timeout)
            .redirect(wreq::redirect::Policy::limited(config.max_redirects))
            .cookie_store(true)
            .no_proxy();

        if let Some(emulation) = config.emulation {
            builder = builder.emulation(emulation);
        }

        Ok(builder.build()?)
    }
}
