use std::sync::Arc;
use std::time::Duration;

use wreq::Client;

use crate::handler_reqwest::WreqHandler;
use crate::middleware::{Handler, MiddlewareFn, Request, chain};
use crate::middleware_cloudflare::cloudflare_detect_middleware;
use crate::middleware_hints::client_hints_middleware;
use crate::middleware_logging::logging_middleware;
use crate::middleware_ratelimit::rate_limit_middleware;
use crate::middleware_residential::residential_proxy_middleware;
use crate::middleware_retry::retry_middleware;
use crate::middleware_solver::{solver_middleware, solver_middleware_with_negcache};
use crate::middleware_ssrf::ssrf_middleware;
use crate::profile::{BrowserProfile, profile_to_emulation};
use crate::profile_hints::browser_headers;
use crate::ssrf_connect::{SsrfGuardedResolver, ssrf_redirect_policy};
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
        // ONE identity source of truth: when `profile` is set, derive the
        // TLS/HTTP2 Emulation from it via `profile_to_emulation`. The
        // `config.emulation` field is IGNORED when a profile is set — a
        // config naming one browser must not be able to produce another
        // browser's TLS fingerprint. When no profile is set (non-browser
        // clients like the Twitter API client), `config.emulation` is used
        // as-is for TLS fingerprinting without browser identity headers.
        let emulation = if let Some(profile) = config.profile {
            profile_to_emulation(profile)
        } else {
            config.emulation.clone()
        };

        let client = Self::build_wreq_client(&config, emulation.as_ref())?;
        // A sibling client with no proxy, used as a direct-connection fallback
        // when the upstream proxy cannot be dialled (a provable proxy-dial
        // failure — the proxy host is dead). The previous 402-triggered
        // degradation has been removed (issue #90).
        let direct_client = Self::build_direct_wreq_client(&config, emulation.as_ref())?;
        // Whether to attach the direct (no-proxy) fallback used on a provable
        // proxy-dial failure. Must cover EVERY path that can route a request
        // through an upstream proxy: the static `proxy_url`, the rotating
        // `proxy_pool`, AND the residential proxy injected per-request by the
        // residential middleware on a CF retry (`middleware_residential.rs:60`
        // sets `retry_req.proxy = Some(self.proxy_url)`). Omitting
        // `residential_proxy` left a residential-only config with no direct
        // sibling, so a dial failure during a residential CF-retry hard-failed
        // the read into a 502 instead of degrading — the May-outage gap.
        let needs_fallback = config.proxy_url.is_some()
            || config.proxy_pool.is_some()
            || config.residential_proxy.is_some();
        let client_has_static_proxy = config.proxy_url.is_some();
        let max_redirects = config.max_redirects;
        let base: Arc<dyn Handler> = if let Some(ref pool) = config.proxy_pool {
            Arc::new(
                WreqHandler::with_proxy_pool(
                    client,
                    Arc::clone(pool),
                    client_has_static_proxy,
                    max_redirects,
                )
                .with_direct_fallback(direct_client),
            )
        } else if needs_fallback {
            Arc::new(
                WreqHandler::new(client, client_has_static_proxy, max_redirects)
                    .with_direct_fallback(direct_client),
            )
        } else {
            Arc::new(WreqHandler::new(
                client,
                client_has_static_proxy,
                max_redirects,
            ))
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
        // Use the shared negcache when available so read_pipeline can check is_blocked()
        // and set RenderMode::GiveUp instead of retrying doomed solve attempts.
        if let (Some(provider), Some(cache)) = (&config.cookie_provider, &config.cookie_cache) {
            if let Some(ref nc) = config.solver_negcache {
                middlewares.push(solver_middleware_with_negcache(
                    Arc::clone(provider),
                    Arc::clone(cache),
                    Arc::clone(nc),
                ));
            } else {
                middlewares.push(solver_middleware(Arc::clone(provider), Arc::clone(cache)));
            }
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
        // ONLY when no profile is set — when a profile is set, `browser_headers()`
        // in `build_request()` provides the complete, coherent header set
        // (including sec-ch-ua). The middleware must not add headers the
        // profile didn't include (e.g. sec-ch-ua-full-version-list, which
        // real Chrome doesn't send on top-level navigation).
        if config.profile.is_none() {
            middlewares.push(client_hints_middleware());
        }

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
    /// `emulation` is the derived Emulation (from profile or config.emulation).
    fn build_wreq_client(
        config: &HttpConfig,
        emulation: Option<&wreq::Emulation>,
    ) -> Result<Client> {
        // C: wreq's `ClientBuilder` defaults `auto_sys_proxy: true`,
        // which installs a `ProxyMatcher::system()` that reads
        // `HTTP_PROXY` / `http_proxy` (and the macOS dynamic store) at
        // build time. Without `.no_proxy()`, an ambient `HTTP_PROXY` —
        // routine in Docker images and CI runners — silently proxies the
        // base client while `client_has_static_proxy` reads false. That
        // breaks the iff the `WreqHandler::new` docstring asserts: every
        // proxy counter under-reports, and the dial fallback is skipped
        // (used_proxy is false), so a dead ambient proxy hard-fails every
        // read instead of degrading. The `.no_proxy()` call inside
        // `wreq_transport_core` (when `proxy` is `None`) clears
        // `auto_sys_proxy`, making the flag a true iff and preventing
        // unlogged ambient-proxy attribution.
        wreq_transport_core(
            config.timeout,
            config.max_redirects,
            emulation,
            config.proxy_url.as_deref(),
            true,
        )
    }

    /// Build a wreq client identical to [`build_wreq_client`] but with no
    /// proxy. Used as the direct-connection fallback when the upstream proxy
    /// cannot be dialled (a provable proxy-dial failure).
    fn build_direct_wreq_client(
        config: &HttpConfig,
        emulation: Option<&wreq::Emulation>,
    ) -> Result<Client> {
        wreq_transport_core(config.timeout, config.max_redirects, emulation, None, true)
    }

    /// Test-only constructor: inject a pre-built handler and config directly,
    /// bypassing the wreq client setup. Lets integration tests drive
    /// `read_page_inner` with a mock [`Handler`] without network calls.
    #[cfg(test)]
    pub fn with_handler(handler: Arc<dyn Handler>, config: HttpConfig) -> Self {
        Self { handler, config }
    }
}

// ── Shared wreq-client construction seam ────────────────────────────────
//
// Issue #101: the media-download path (`ox-media`) built a bare `wreq::Client`
// with no browser identity, so a WAF that saw a byte-perfect Chrome fetch the
// page then saw a bare Rust client fetch the images/video from the same origin
// — a one-visitor-two-clients correlation signal. This seam is the ONE place
// the transport + identity layer is constructed, shared by `HttpClient`'s own
// builders above and by the public [`build_profiled_wreq_client`] the media
// path adopts. Duplication is what created the gap; this closes it.

/// Shared wreq client construction core: timeout, SSRF connect-time +
/// redirect-hop guards, proxy (or `.no_proxy()` to clear wreq's ambient
/// `HTTP_PROXY` default), cookie store, and TLS/HTTP2 emulation.
///
/// `proxy = None` means "no proxy" and calls `.no_proxy()` (clearing
/// `auto_sys_proxy`). `proxy = Some(url)` attaches a static proxy. Per-request
/// proxy pools / residential proxies are handled by `WreqHandler`, not here.
///
/// The Emulation controls TLS + HTTP/2 ONLY — identity headers are set
/// per-request by the caller via `browser_headers(profile)` (mirroring PR #97:
/// the emulation owns the transport fingerprint, the profile owns the headers,
/// and the two cannot diverge because there is no `.headers(...)` on the
/// Emulation). This function does NOT set `.user_agent()` on the builder.
fn wreq_transport_core(
    timeout: Duration,
    max_redirects: usize,
    emulation: Option<&wreq::Emulation>,
    proxy: Option<&str>,
    cookie_store: bool,
) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(timeout)
        // Connect-time, rebind-resistant IP guard (see crate::ssrf_connect
        // module doc) — filters DNS resolution results, not just the
        // pre-resolve middleware_ssrf check.
        .dns_resolver(SsrfGuardedResolver)
        // Refuses a redirect hop whose target is already a blocked literal IP
        // (the resolver above never sees those — wreq skips DNS resolution
        // entirely for IP-literal hosts).
        .redirect(ssrf_redirect_policy(max_redirects));

    if cookie_store {
        builder = builder.cookie_store(true);
    }

    if let Some(url) = proxy {
        let proxy = wreq::Proxy::all(url).map_err(|e| HttpError::InvalidUrl(e.to_string()))?;
        builder = builder.proxy(proxy);
    } else {
        // Clear `auto_sys_proxy` so an ambient `HTTP_PROXY` cannot silently
        // proxy a client whose caller believes is direct (see the comment in
        // `build_wreq_client` for the full invariant).
        builder = builder.no_proxy();
    }

    // Browser emulation for TLS/HTTP2 fingerprints.
    if let Some(emu) = emulation {
        builder = builder.emulation(emu.clone());
    }

    // Note: we do NOT set .user_agent() on the builder — headers are
    // managed per-request (profile headers or fallback UA).
    Ok(builder.build()?)
}

/// Build a wreq client carrying the same browser TLS/HTTP2 identity as
/// [`HttpClient`] does for a given [`BrowserProfile`].
///
/// This is the shared seam the media-download path (`ox-media`) adopts instead
/// of building a bare `wreq::Client` (issue #101). It applies
/// [`profile_to_emulation`] (TLS + HTTP/2 fingerprint) plus the SSRF
/// connect-time and redirect-hop guards, and a static proxy when `proxy_url`
/// is non-empty. It does NOT set a User-Agent or client hints on the builder —
/// the caller sets headers per-request via [`browser_headers`] (for browser
/// identity) or its own protocol UA (for the Innertube ANDROID_VR client,
/// whose Android-app identity legitimately differs from a browser's).
///
/// `max_redirects` should match the originating `HttpClient`'s config so the
/// media path behaves identically to the page-fetch path.
pub fn build_profiled_wreq_client(
    profile: &BrowserProfile,
    proxy_url: &str,
    timeout: Duration,
    max_redirects: usize,
) -> Result<Client> {
    let emulation = profile_to_emulation(profile);
    let proxy = if proxy_url.is_empty() {
        None
    } else {
        Some(proxy_url)
    };
    wreq_transport_core(timeout, max_redirects, emulation.as_ref(), proxy, false)
}
