//! Base handler that executes HTTP requests via wreq (BoringSSL).
//!
//! This is the terminal handler in the middleware chain — it converts
//! a [`Request`] into a real HTTP call and returns an [`HttpResponse`].

use std::sync::Arc;

use async_trait::async_trait;
use wreq::Client;

use crate::body_cap::read_text_capped;
use crate::middleware::{Handler, Request};
use crate::proxy_fallback::{looks_like_proxy_dial_failure, record_proxy_dial_fallback};
use crate::proxy_pool::ProxyPool;
use crate::{HttpError, HttpResponse, Result};

/// Handler that executes HTTP requests using a [`wreq::Client`].
///
/// Sits at the bottom of the middleware chain. Converts the generic
/// [`Request`] (with ordered headers) into a wreq request, sends it,
/// and builds an [`HttpResponse`] from the result.
///
/// When the upstream proxy cannot be dialled at all (connect refused / DNS /
/// TLS handshake to the proxy host), retries the request **once** through
/// [`Self::direct_client`] (no proxy). See [`crate::proxy_fallback`] for the
/// rationale. The previous response-inferred 402 degradation has been
/// removed (issue #90) — a relayed response can never attribute a plain-HTTP
/// forward-proxy failure, so any 402 surfaces to the caller unchanged.
pub struct WreqHandler {
    client: Client,
    proxy_pool: Option<Arc<dyn ProxyPool>>,
    /// Sibling client with no proxy. When `Some`, we retry on a provable
    /// proxy-dial failure (the proxy host is dead). The previous 402-triggered
    /// degradation has been removed (issue #90).
    direct_client: Option<Client>,
    /// Whether the base `client` was built with a static `proxy_url` baked in
    /// (see `HttpConfig::proxy_url`). Distinct from `direct_client.is_some()`,
    /// which is ALSO true for a residential-only config whose base client has
    /// NO proxy — the residential proxy is injected per-request by the
    /// residential middleware on a CF retry, not at the client level. Deriving
    /// "this attempt is proxied" from `direct_client.is_some()` therefore
    /// falsely reported every un-challenged first attempt of a residential-only
    /// config as proxied (F1).
    client_has_static_proxy: bool,
    /// `HttpConfig::max_redirects` — the client follows up to this many
    /// redirects internally. The dial-failure classifier is only safe when no
    /// redirect can have occurred (`max_redirects == 0`): the classifier gates
    /// on the scheme of `req.url` (the ORIGINAL caller URL), but a redirect
    /// from `http://` to `https://` makes the failing hop's scheme
    /// unobservable from outside wreq (`Error::uri()` carries the original
    /// URL, not the redirect target — verified empirically). So when redirects
    /// are enabled, an `is_proxy_connect()` hit may be a CONNECT-tunnel failure
    /// for an HTTPS origin through a HEALTHY proxy (origin unreachable), which
    /// must NOT degrade. See F2 / `looks_like_proxy_dial_failure`. The default
    /// is `10` (`HttpConfig::max_redirects`), so under the shipped
    /// configuration the dial-failure fallback is dormant — the predicate
    /// returns `false` for every request (tracking issue ox-browser#90).
    max_redirects: usize,
    /// Per-response body cap in bytes. Responses whose body exceeds this are
    /// rejected with `HttpError::BodyTooLarge` before the body is fully
    /// buffered (issue #117, resource_exhaustion). Threaded from
    /// `HttpConfig::max_body_bytes` at construction so every caller through
    /// the middleware chain inherits the cap without each remembering.
    max_body_bytes: u64,
    /// Client for Tor-bound (`.onion`) requests, built with the Tor HTTP-tunnel
    /// proxy baked in. `None` → `.onion` targets are refused. Tor-bound
    /// requests use ONLY this client: never `client`, the pool, a per-request
    /// proxy or `direct_client`.
    tor: Option<Client>,
    /// Pre-resolve DNS lookup used to vet a re-routed redirect hop (the system
    /// resolver in production; injectable for tests).
    lookup: crate::middleware_ssrf::LookupHost,
}

impl WreqHandler {
    /// Wrap an already-configured wreq client.
    ///
    /// `client_has_static_proxy` must be `true` iff the client was built with a
    /// static `proxy_url` baked in (so the FIRST attempt is proxied even when
    /// `req.proxy` is `None` and no pool is set). This iff is established by
    /// `build_wreq_client`, which calls `.proxy(...)` when `proxy_url` is
    /// `Some` and `.no_proxy()` when it is `None` — clearing wreq's
    /// `auto_sys_proxy` default so an ambient `HTTP_PROXY` cannot silently
    /// proxy the base client while the flag reads false. `max_redirects` is
    /// the configured redirect limit, used to gate the dial-failure
    /// classifier. `max_body_bytes` is the per-response body cap (issue #117).
    pub fn new(
        client: Client,
        client_has_static_proxy: bool,
        max_redirects: usize,
        max_body_bytes: u64,
    ) -> Self {
        Self {
            client,
            proxy_pool: None,
            direct_client: None,
            client_has_static_proxy,
            max_redirects,
            max_body_bytes,
            tor: None,
            lookup: crate::middleware_ssrf::system_lookup(),
        }
    }

    /// Wrap a wreq client with a rotating proxy pool.
    ///
    /// Each request picks the next proxy from the pool via
    /// wreq's per-request `RequestBuilder::proxy()`.
    pub fn with_proxy_pool(
        client: Client,
        pool: Arc<dyn ProxyPool>,
        client_has_static_proxy: bool,
        max_redirects: usize,
        max_body_bytes: u64,
    ) -> Self {
        Self {
            client,
            proxy_pool: Some(pool),
            direct_client: None,
            client_has_static_proxy,
            max_redirects,
            max_body_bytes,
            tor: None,
            lookup: crate::middleware_ssrf::system_lookup(),
        }
    }

    /// Use `lookup` instead of the system resolver for the pre-resolve check
    /// of re-routed redirect hops.
    #[must_use]
    pub fn with_lookup(mut self, lookup: crate::middleware_ssrf::LookupHost) -> Self {
        self.lookup = lookup;
        self
    }

    /// Attach the Tor client used for every `.onion` request. See
    /// [`crate::tor`].
    #[must_use]
    pub fn with_tor(mut self, tor: Client) -> Self {
        self.tor = Some(tor);
        self
    }

    /// [`Self::with_tor`] when a Tor client is configured, unchanged otherwise.
    #[must_use]
    pub fn with_tor_opt(self, tor: Option<Client>) -> Self {
        match tor {
            Some(c) => self.with_tor(c),
            None => self,
        }
    }

    /// Attach a direct (no-proxy) sibling client used as fallback when the
    /// upstream proxy cannot be dialled (a provable proxy-dial failure).
    #[must_use]
    pub fn with_direct_fallback(mut self, direct: Client) -> Self {
        self.direct_client = Some(direct);
        self
    }

    /// Run a single request attempt. When `client` is the direct sibling, no
    /// proxy is applied even if `req.proxy` or `proxy_pool` would otherwise
    /// add one.
    async fn execute_with(
        &self,
        client: &Client,
        req: &Request,
        skip_proxy: bool,
    ) -> Result<HttpResponse> {
        let mut builder = match req.method.to_uppercase().as_str() {
            "GET" => client.get(&req.url),
            "POST" => client.post(&req.url),
            "PUT" => client.put(&req.url),
            "DELETE" => client.delete(&req.url),
            "PATCH" => client.patch(&req.url),
            "HEAD" => client.head(&req.url),
            other => {
                // OPTIONS, TRACE, or any other valid HTTP method. wreq's
                // typed `Method` validates the bytes; an invalid method
                // surfaces as a request error here.
                let method = wreq::Method::from_bytes(other.as_bytes())
                    .map_err(|e| HttpError::InvalidMethod(e.to_string()))?;
                client.request(method, &req.url)
            }
        };

        if !skip_proxy {
            if let Some(ref proxy_url) = req.proxy {
                // A: a caller-supplied proxy must not name an internal
                // address. wreq skips DNS for IP-literal proxies, so the
                // connect-time SSRF resolver never sees them. validate returns
                // the CANONICAL url to dial; dialling the raw string instead
                // would reopen the url/wreq parser differential (SEC-CR-001).
                let dial = match crate::middleware_ssrf::validate_proxy_url(proxy_url) {
                    Ok(d) => d,
                    Err(e) => {
                        // A refused caller proxy (SSRF-blocked or malformed)
                        // is a fail-closed attach rejection — count it, don't
                        // degrade to direct.
                        crate::metrics::record_proxy_attach_invalid_url();
                        tracing::warn!(url = %req.url, error = %e, reason = "proxy_refused", "per-request proxy refused");
                        return Err(e);
                    }
                };
                // B: fail closed — an unparsable proxy is a misconfiguration,
                // not a silent downgrade to direct (which would egress from
                // the real IP with no proxy and no counter).
                let proxy = match build_proxy(&dial) {
                    Ok(p) => p,
                    Err(e) => {
                        crate::metrics::record_proxy_attach_invalid_url();
                        tracing::warn!(
                            url = %req.url,
                            proxy_url = %crate::middleware_ssrf::redact_proxy_userinfo(proxy_url),
                            reason = "proxy_attach_invalid_url",
                            "validated per-request proxy failed to build — failing closed, refusing to degrade to direct"
                        );
                        return Err(e);
                    }
                };
                builder = builder.proxy(proxy);
                crate::metrics::record_proxy_used();
            } else if let Some(ref pool) = self.proxy_pool {
                // C: `pool.next()` returns `None` only when the inner pool is
                // empty. Under both production wirings this is unreachable:
                //   - `serve.rs` wires `HealthyPool(WebsharePool)` —
                //     `WebsharePool::new` rejects empty proxy lists at
                //     construction, and `HealthyPool::next()` falls back to
                //     `inner.next()` even when all proxies are deactivated.
                //   - `main.rs` wires `StaticPool::new(vec![proxy_url])` with
                //     `proxy_url: Some(..)` — always non-empty.
                // An empty pool here is a construction-time bug, not a runtime
                // state. We panic loudly instead of silently degrading to
                // direct (which would leak the real IP with no proxy and no
                // counter). Wiring this branch reachable would require
                // changing `HealthyPool`'s fail-open-on-all-deactivated
                // behaviour — the same class of decision as issue #93, out of
                // scope for this PR.
                let proxy_url = pool.next().expect(
                    "proxy pool returned None — unreachable under production wiring (see comment)",
                );
                let proxy = match build_proxy(&proxy_url) {
                    Ok(p) => p,
                    Err(e) => {
                        crate::metrics::record_proxy_attach_invalid_url();
                        tracing::warn!(
                            url = %req.url,
                            proxy_url = %crate::middleware_ssrf::redact_proxy_userinfo(&proxy_url),
                            reason = "proxy_attach_invalid_url",
                            "pool-returned proxy URL is unparsable — failing closed, refusing to degrade to direct"
                        );
                        return Err(e);
                    }
                };
                builder = builder.proxy(proxy);
                crate::metrics::record_proxy_used();
            } else if self.client_has_static_proxy {
                // The proxy is baked into the base client — no per-request
                // attachment, but the request IS proxied.
                crate::metrics::record_proxy_used();
            }
        }

        tracing::debug!(
            url = %req.url,
            method = %req.method,
            proxy = ?req.proxy.as_deref().map(crate::middleware_ssrf::redact_proxy_userinfo),
            skip_proxy,
            ua = ?req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("user-agent")).map(|(_, v)| v.as_str()),
            header_count = req.headers.len(),
            "wreq: sending request"
        );

        // Apply headers in insertion order (important for fingerprinting).
        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        // Attach body if present.
        if let Some(ref body) = req.body {
            builder = builder.body(body.clone());
        }

        let resp = builder.send().await?;

        tracing::debug!(
            url = %req.url,
            status = resp.status().as_u16(),
            final_url = %resp.uri(),
            "wreq: response received"
        );

        let status = resp.status().as_u16();
        let final_url = resp.uri().to_string();
        let headers = resp.headers().clone();
        // Body cap (issue #117): stream the response body with a running-total
        // byte cap instead of `resp.text()` which reads the full body into
        // memory unbounded. Every caller through the middleware chain inherits
        // the cap — `/fetch`, `/read`, CLI, crawler, reddit, media-orchestrator
        // generic path. The media-download surface has its own per-call cap
        // (`download_to_file::max_size_bytes`) because it uses a separate wreq
        // client, not this handler.
        let body = read_text_capped(resp, self.max_body_bytes).await?;

        Ok(HttpResponse {
            status,
            url: final_url,
            headers,
            body,
        })
    }

    /// True if the first attempt would route through *some* proxy (per-request
    /// override, rotating pool, or static client-level proxy baked into the
    /// base `client` via `HttpConfig::proxy_url`). The static-client case is
    /// determined by [`Self::client_has_static_proxy`] — NOT by
    /// `direct_client.is_some()`, which is also true for a residential-only
    /// config whose base client has no proxy (the residential proxy is injected
    /// per-request on a CF retry, so an un-challenged first attempt is NOT
    /// proxied even though a direct sibling exists).
    fn first_attempt_uses_proxy(&self, req: &Request) -> bool {
        req.proxy.is_some() || self.proxy_pool.is_some() || self.client_has_static_proxy
    }
}

#[async_trait]
impl Handler for WreqHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let mut req = req;
        let mut hops = 0usize;
        loop {
            let resp = self.handle_hop(&req).await?;
            // A redirect that crosses the onion boundary is handed back by
            // both clients' redirect policies instead of being followed in
            // place; route the new URL afresh.
            let Some(next) = onion_boundary_redirect(&req, &resp) else {
                return Ok(resp);
            };
            hops += 1;
            if hops > self.max_redirects {
                return Err(HttpError::InvalidUrl(
                    "too many redirects across the onion boundary".into(),
                ));
            }
            // Redirect hops inside wreq never see the pre-resolve tier and a
            // literal-IP first request skips the resolver; vet the new hop
            // here exactly like a fresh request.
            crate::middleware_ssrf::validate_url_with(
                &next.url,
                self.tor.is_some(),
                self.lookup.as_ref(),
            )?;
            req = next;
        }
    }
}

impl WreqHandler {
    /// One routed attempt: Tor for `.onion`, the normal client otherwise.
    async fn handle_hop(&self, req: &Request) -> Result<HttpResponse> {
        let tor_bound = crate::tor::is_onion_url(&req.url);
        let used_proxy = tor_bound || self.first_attempt_uses_proxy(req);

        // B: `record_proxy_used()` is now called inside `execute_with` ONLY on
        // the branch that actually attached a proxy (or when the base client
        // has a static proxy baked in). Previously it fired here based on
        // `first_attempt_uses_proxy`, which returned true even when the proxy
        // failed to attach — the dashboard read 100% proxied while the request
        // egressed on the real IP.
        let primary = if tor_bound {
            self.execute_tor(req).await
        } else {
            self.execute_with(&self.client, req, false).await
        };

        // Observation-only 402 counter: a plain "we saw a 402 while proxied"
        // count. No scheme/attribution guess — a 402 relayed by a healthy
        // forward proxy may have originated at the origin (metered APIs,
        // x402), so this counter does NOT trigger degradation. The previous
        // attribution heuristic (is_proxy_attributed_402 / looks_like_proxy_402)
        // was removed because a relayed response can never prove proxy-side
        // attribution (issue #90).
        // Tor is not Webshare: its outcomes feed `oxbrowser_tor_*`, not the
        // proxy 402 / dial signals the operator reads as Webshare health.
        if used_proxy && !tor_bound && matches!(&primary, Ok(resp) if resp.status == 402) {
            crate::metrics::record_proxy_402();
        }

        // Detect a proxy dial failure (proxy host unreachable) regardless of
        // whether a direct fallback is wired — the counter must reflect the
        // real event so the operator sees dial failures that did NOT degrade
        // (notably HTTPS targets, where the classifier is deliberately
        // conservative — see proxy_fallback::looks_like_proxy_dial_failure).
        //
        // F4: the metric is gated on `is_proxy_connect()` ALONE (not the
        // scheme), so an HTTPS dead-proxy request bumps this counter even
        // though the degradation decision below refuses it. The gap between
        // this and `PROXY_DIAL_FALLBACK_TOTAL` is the signal #86 says needs
        // watching. The scheme gate lives ONLY on the degradation decision.
        let is_proxy_dial = used_proxy
            && !tor_bound
            && matches!(&primary, Err(HttpError::Request(e)) if e.is_proxy_connect());
        if is_proxy_dial {
            crate::metrics::record_proxy_dial();
        }

        // Decide whether to fall back. Only when:
        // 1. We actually have a direct-client sibling, AND
        // 2. The first attempt was proxied, AND
        // 3. The error is a provable proxy-dial failure (the proxy host is
        //    dead — not a response-inferred guess).
        // Tor-bound: a failure is an error, never a reason to go direct. The
        // dial-failure classifier below would otherwise be the only thing
        // standing between a Tor outage and a clearnet attempt.
        if tor_bound {
            record_tor_outcome(&primary);
            return primary;
        }
        let Some(ref direct) = self.direct_client else {
            return primary;
        };
        if !used_proxy {
            return primary;
        }

        match primary {
            // Upstream proxy unreachable (dead host / refused / DNS / TLS dial
            // to the proxy). Classified via the typed is_proxy_connect()
            // predicate gated to HTTP targets only — see
            // proxy_fallback::looks_like_proxy_dial_failure for why HTTPS is
            // deliberately excluded (the tunnel error surface is ambiguous
            // between proxy-dial and origin-unreachable-through-proxy).
            // F2: additionally gated on `max_redirects == 0` — when redirects
            // are enabled, the scheme of the failing hop is unobservable
            // (Error::uri() carries the original URL, verified empirically),
            // so an http→https redirect makes the classifier unsafe.
            Err(HttpError::Request(ref e))
                if looks_like_proxy_dial_failure(e, &req.url, self.max_redirects) =>
            {
                record_proxy_dial_fallback(&req.url);
                self.execute_with(direct, req, true).await
            }
            other => other,
        }
    }

    /// Send a `.onion` request through the Tor client, and only it. The
    /// per-request proxy, the pool and the static proxy are all skipped
    /// (`skip_proxy = true`): they are third parties that must never see an
    /// onion name, and a caller cannot redirect Tor-bound traffic elsewhere.
    async fn execute_tor(&self, req: &Request) -> Result<HttpResponse> {
        let Some(ref client) = self.tor else {
            return Err(crate::tor::refuse_requires_tor());
        };
        crate::tor::check_onion_target(true)?;
        crate::tor::record_tor_request();
        self.execute_with(client, req, true).await
    }
}

/// Count a Tor-bound failure under `oxbrowser_tor_failures_total{kind}`.
fn record_tor_outcome(res: &Result<HttpResponse>) {
    let kind = match res {
        Err(HttpError::Request(e)) if e.is_timeout() => "timeout",
        Err(HttpError::Timeout(_)) => "timeout",
        Err(HttpError::Request(e)) if e.is_proxy_connect() || e.is_connect() => "dial",
        Err(_) => "http_error",
        Ok(r) if (500..600).contains(&r.status) => "http_error",
        Ok(_) => return,
    };
    crate::metrics::record_tor_failure(kind);
}

/// If `resp` is a redirect whose target lies on the other side of the onion
/// boundary than `req`, build the request for that hop. Method/body follow
/// the usual browser rules (301/302 POST and 303 become GET) and credentials
/// bound to the old origin are dropped.
pub(crate) fn onion_boundary_redirect(req: &Request, resp: &HttpResponse) -> Option<Request> {
    if !matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let location = resp.headers.get(wreq::header::LOCATION)?.to_str().ok()?;
    let next = url::Url::parse(&resp.url).ok()?.join(location).ok()?;
    if !matches!(next.scheme(), "http" | "https") {
        return None;
    }
    let from_tor = crate::tor::is_onion_url(&req.url);
    if !crate::tor::crosses_onion_boundary(next.host_str()?, from_tor) {
        return None;
    }
    let downgrade = resp.status == 303 && !req.method.eq_ignore_ascii_case("HEAD")
        || matches!(resp.status, 301 | 302) && req.method.eq_ignore_ascii_case("POST");
    let (method, body) = if downgrade {
        ("GET".to_owned(), None)
    } else {
        (req.method.clone(), req.body.clone())
    };
    let headers = req
        .headers
        .iter()
        .filter(|(k, _)| {
            let k = k.to_ascii_lowercase();
            !matches!(
                k.as_str(),
                "authorization" | "cookie" | "proxy-authorization"
            ) && !(downgrade
                && matches!(
                    k.as_str(),
                    "content-type" | "content-length" | "transfer-encoding"
                ))
        })
        .cloned()
        .collect();
    Some(Request {
        method,
        url: next.to_string(),
        headers,
        body,
        proxy: req.proxy.clone(),
        authenticated: req.authenticated,
    })
}

/// Build a wreq proxy from a proxy URL, dialling its canonical form.
///
/// wreq re-parses the string it is given and can disagree with the url crate
/// on the same input (an empty port, a credential the parser reads as part
/// of the authority, a scheme it has no intercept for — every `socks*`
/// scheme, since wreq is built without its `socks` feature). Such a URL is
/// dialled as an HTTP proxy, fails `ProxyConnect`, and is exactly what
/// `looks_like_proxy_dial_failure` matched — the direct-fallback sibling then
/// re-sent the request from the real IP. The raw value is therefore never
/// handed to wreq: it goes through
/// [`crate::middleware_ssrf::canonicalise_proxy_url`] first, which refuses
/// what wreq cannot dial (issue #179). That does NOT vet
/// the target — pool and static proxies are operator-configured and may be
/// private (e.g. a local forward-proxy sidecar); caller proxies are vetted by
/// `validate_proxy_url` before they get here.
///
/// The wreq error is never surfaced: its Display can echo the URI including
/// `user:password@`, so the error carries only a fixed message plus the
/// redacted URL.
pub fn build_proxy(proxy_url: &str) -> Result<wreq::Proxy> {
    let invalid = || {
        HttpError::InvalidUrl(format!(
            "invalid proxy URL: {}",
            crate::middleware_ssrf::redact_proxy_userinfo(proxy_url)
        ))
    };
    let canonical =
        crate::middleware_ssrf::canonicalise_proxy_url(proxy_url).map_err(|_| invalid())?;
    wreq::Proxy::all(canonical.url.as_str()).map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware_ssrf::tests::{SMUGGLED_PROXY_ROWS, leaks_credentials};

    #[test]
    fn wreq_handler_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WreqHandler>();
    }

    /// A caller-supplied proxy that is a private IP literal must be refused
    /// before wreq dials it (wreq skips DNS for literal proxies, so the
    /// connect-time SSRF resolver never sees it).
    ///
    /// Falsification: delete the `validate_proxy_url` block in
    /// `execute_with` and the request is dialled through 127.0.0.1:9 —
    /// a connection error, not "SSRF blocked" → RED.
    ///
    /// `#[serial]`: `per_request_debug_log_redacts_valid_proxy` sets the
    /// process-wide proxy allowlist; this test must not run concurrently
    /// with it (SEC-CR-029).
    #[tokio::test]
    #[serial_test::serial]
    async fn private_literal_proxy_is_ssrf_blocked() {
        let client = crate::HttpClient::new(crate::HttpConfig::default()).expect("client");
        for proxy in [
            "http://127.0.0.1:9",
            "http://10.1.2.3:3128",
            "http://172.18.0.1:1080",
            "http://[::1]:9",
            "http://169.254.169.254:80",
            "http://localhost:9",
            "127.0.0.1:9",
        ] {
            let err = client
                .execute(crate::Request {
                    method: "GET".into(),
                    url: "http://1.1.1.1/".into(),
                    headers: vec![],
                    body: None,
                    proxy: Some(proxy.into()),
                    authenticated: false,
                })
                .await
                .expect_err("private proxy must be refused");
            assert!(
                err.to_string().contains("SSRF blocked"),
                "proxy {proxy}: got {err}"
            );
        }
    }

    /// A proxy-setup failure must not echo the proxy credentials in the
    /// returned error (wreq's own error Display includes the userinfo).
    ///
    /// Falsification: revert `build_proxy` to the pre-fix
    /// `wreq::Proxy::all(proxy_url).map_err(|e| InvalidUrl(e.to_string()))`
    /// and the password appears in the message → RED.
    #[test]
    fn build_proxy_error_does_not_leak_credentials() {
        // wreq's own error for this input is "builder error for uri
        // (<userinfo>@host)", i.e. it echoes the credentials.
        let err = build_proxy("USERTOK:S3CRETPW@example.com")
            .expect_err("scheme-less proxy with userinfo must be refused");
        let msg = err.to_string();
        assert!(!leaks_credentials(&msg), "{msg}");
    }

    /// A bare `host:port` is an http proxy; scheme-less input without a
    /// numeric port still fails closed (see proxy_402_fallback_test B).
    #[test]
    fn build_proxy_bare_host_port_only() {
        assert!(build_proxy("192.0.2.1:3128").is_ok());
        assert!(build_proxy("not-a-valid-url").is_err());
        assert!(build_proxy("host:notaport").is_err());
    }

    /// Handler-level: both build_proxy call sites must fail closed without
    /// echoing proxy credentials. The pool call site is driven here; the
    /// per-request site by `per_request_proxy_refusal_does_not_leak_credentials`.
    ///
    /// Falsification: revert either build_proxy call site to
    /// `wreq::Proxy::all(..).map_err(|e| HttpError::InvalidUrl(e.to_string()))`
    /// and the password appears in the returned error → RED. For the
    /// SEC-CR-021 rows: make `redact_proxy_userinfo` re-serialise the parsed
    /// URL (the pre-fix `set_username("***")` + `to_string()`) and the
    /// password, parsed into the fragment/path/query, appears → RED.
    #[tokio::test]
    async fn pool_proxy_error_does_not_leak_credentials() {
        use crate::proxy_pool::StaticPool;
        use std::sync::Arc;
        let mut rows = vec![
            "USERTOK:S3CRETPW@example.com",
            "ftp://USERTOK:12#S3CRETPW@127.0.0.1:21",
        ];
        rows.extend_from_slice(SMUGGLED_PROXY_ROWS);
        for entry in rows {
            let pool = Arc::new(StaticPool::new(vec![entry.to_string()]));
            let client = wreq::Client::new();
            let handler = WreqHandler::with_proxy_pool(client, pool, false, 5, 1 << 20);
            let (result, logs) = capture_logs(handler.handle(Request {
                method: "GET".into(),
                url: "http://example.com/".into(),
                headers: vec![],
                body: None,
                proxy: None,
                authenticated: false,
            }))
            .await;
            let msg = result
                .expect_err("invalid pool proxy must fail closed")
                .to_string();
            assert!(
                !leaks_credentials(&msg),
                "pool error leaked for {entry:?}: {msg}"
            );
            assert!(
                logs.contains("proxy_attach_invalid_url"),
                "pool refusal not logged: {logs}"
            );
            assert!(
                !leaks_credentials(&logs),
                "pool logs leaked for {entry:?}: {logs}"
            );
        }
    }

    /// The per-request call site: a credentialed req.proxy that is refused
    /// must not echo the credentials, on both refusal branches.
    ///
    /// - `ex ample.com` is refused by `validate_proxy_url` (illegal byte).
    /// - `a{b}.example` (SEC-CR-019) PASSES `validate_proxy_url` — the url
    ///   crate allows `{`/`}` in a domain — but `http::Uri` cannot carry it,
    ///   so `build_proxy(&dial)` fails. This is the input that reaches the
    ///   per-request `build_proxy` error branch.
    ///
    /// Falsification: make `build_proxy`'s error echo the raw URL
    /// (`format!("invalid proxy URL: {proxy_url}")`) and the `a{b}` row leaks
    /// the password → RED; with only the `ex ample` row the same mutation
    /// stays green, which is why the `a{b}` row is here. (wreq's own error
    /// for this input, "builder error: invalid uri character", happens not
    /// to echo the userinfo, so reverting the call site to surface it would
    /// not be caught by this input.)
    #[tokio::test]
    async fn per_request_proxy_refusal_does_not_leak_credentials() {
        let mut rows = vec![
            "http://USERTOK:S3CRETPW@ex ample.com:80",
            "http://USERTOK:S3CRETPW@a{b}.example:3128",
        ];
        rows.extend_from_slice(SMUGGLED_PROXY_ROWS);
        for proxy in rows {
            assert!(
                !proxy.contains('{') || crate::middleware_ssrf::validate_proxy_url(proxy).is_ok(),
                "{proxy}: must pass validation so the build_proxy branch is exercised"
            );
            let handler = WreqHandler::new(wreq::Client::new(), false, 5, 1 << 20);
            let (result, logs) = capture_logs(handler.handle(Request {
                method: "GET".into(),
                url: "http://example.com/".into(),
                headers: vec![],
                body: None,
                proxy: Some(proxy.into()),
                authenticated: false,
            }))
            .await;
            let msg = result
                .expect_err("invalid req.proxy must fail closed")
                .to_string();
            assert!(
                !leaks_credentials(&msg),
                "per-request error leaked for {proxy:?}: {msg}"
            );
            assert!(
                logs.contains("proxy"),
                "per-request refusal not logged: {logs}"
            );
            assert!(
                !leaks_credentials(&logs),
                "per-request logs leaked for {proxy:?}: {logs}"
            );
        }
    }

    /// A successful per-request proxy is DEBUG-logged through the redactor:
    /// the log must name the proxy host, never its credentials.
    ///
    /// Falsification: log `req.proxy` raw in the "wreq: sending request"
    /// debug line (handler_reqwest.rs) → RED.
    #[tokio::test]
    #[serial_test::serial]
    async fn per_request_debug_log_redacts_valid_proxy() {
        // Allowlist the loopback proxy so it passes validation; nothing
        // listens on this port (no other test uses it), so the dial fails
        // fast after the debug line.
        // SAFETY: serial test; no other thread reads the env meanwhile.
        unsafe {
            std::env::set_var(
                crate::middleware_ssrf::PROXY_ALLOWLIST_ENV,
                "127.0.0.1:59871",
            )
        };
        let handler = WreqHandler::new(wreq::Client::new(), false, 0, 1 << 20);
        let (_, logs) = capture_logs(handler.handle(Request {
            method: "GET".into(),
            url: "http://192.0.2.10/".into(),
            headers: vec![],
            body: None,
            proxy: Some("http://USERTOK:S3CRETPW@127.0.0.1:59871".into()),
            authenticated: false,
        }))
        .await;
        unsafe { std::env::remove_var(crate::middleware_ssrf::PROXY_ALLOWLIST_ENV) };
        assert!(
            logs.contains("sending request"),
            "debug line not reached: {logs}"
        );
        assert!(
            logs.contains("127.0.0.1:59871"),
            "debug log missing the proxy host: {logs}"
        );
        assert!(!leaks_credentials(&logs), "debug log leaked: {logs}");
    }

    /// Runs `fut` with a thread-local tracing subscriber that records every
    /// event and span field (all levels) into a string.
    async fn capture_logs<F: std::future::Future>(fut: F) -> (F::Output, String) {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let _guard = tracing::subscriber::set_default(LogCapture(buf.clone()));
        let out = fut.await;
        let logs = buf.lock().map(|b| b.clone()).unwrap_or_default();
        (out, logs)
    }

    struct LogCapture(std::sync::Arc<std::sync::Mutex<String>>);
    struct LogVisit(std::sync::Arc<std::sync::Mutex<String>>);

    impl tracing::field::Visit for LogVisit {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            if let Ok(mut b) = self.0.lock() {
                b.push_str(&format!("{}={v:?} ", f.name()));
            }
        }
    }

    impl tracing::Subscriber for LogCapture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, a: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            a.record(&mut LogVisit(self.0.clone()));
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, r: &tracing::span::Record<'_>) {
            r.record(&mut LogVisit(self.0.clone()));
        }
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, e: &tracing::Event<'_>) {
            e.record(&mut LogVisit(self.0.clone()));
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// SEC-CR-012 on the pool path: build_proxy refuses a scheme wreq would
    /// ignore (which would mean a direct request counted as proxied) — the
    /// `socks*` family included, since wreq is built without its `socks`
    /// feature (issue #179).
    ///
    /// Falsification: drop the ALLOWED_PROXY_SCHEMES check in
    /// `canonicalise_proxy_url` (which build_proxy calls) → RED.
    #[test]
    fn build_proxy_refuses_unknown_schemes() {
        for raw in [
            "ftp://8.8.8.8:21",
            "socks://8.8.8.8:1080",
            "socks5://8.8.8.8:1080",
            "SOCKS5://8.8.8.8:1080",
        ] {
            assert!(build_proxy(raw).is_err(), "build_proxy accepted {raw}");
        }
        assert!(build_proxy("http://8.8.8.8:3128").is_ok());
        assert!(build_proxy("https://8.8.8.8:443").is_ok());
    }

    /// Accept-and-count TCP listener answering a bare 200 to anything —
    /// counts whatever was dialled, proxy handshake or direct request.
    async fn counting_listener() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_task = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                hits_task.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        (port, hits)
    }

    /// Sets an env var for the test and restores its previous value on drop,
    /// so a panicking assertion cannot leak the override into sibling tests.
    /// Still `#[serial]` — two live guards on the same var would race.
    struct EnvGuard {
        name: &'static str,
        saved: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let saved = std::env::var_os(name);
            // SAFETY: callers are `#[serial]`; no other thread reads the var
            // between save and restore.
            unsafe { std::env::set_var(name, value) };
            Self { name, saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: paired with `set`; runs before the next serial test.
            unsafe {
                match &self.saved {
                    Some(v) => std::env::set_var(self.name, v),
                    None => std::env::remove_var(self.name),
                }
            }
        }
    }

    /// #179: a `socks5://` per-request proxy must be refused by
    /// `validate_proxy_url` before any connection is opened — wreq is built
    /// without its `socks` feature, so the URL is never a SOCKS dial: wreq
    /// treats it as an HTTP proxy, the dial fails `ProxyConnect`, and with
    /// `max_redirects = 0` `looks_like_proxy_dial_failure` matches — the
    /// direct-fallback sibling then re-sends the request from the real IP.
    /// Driven through the real `WreqHandler::handle` path once with the
    /// default redirect limit and once with `max_redirects = 0`, asserting
    /// zero connections on both the listener the proxy URL points at and a
    /// second "target" listener (the direct path).
    ///
    /// Falsification:
    /// - re-add `"socks5"` to `ALLOWED_PROXY_SCHEMES` (middleware_ssrf.rs):
    ///   the allowlisted loopback proxy validates, wreq dials it as an HTTP
    ///   proxy — the request reaches a listener or errors without the scheme
    ///   refusal → RED;
    /// - skip the `validate_proxy_url` call in `execute_with`: the refusal
    ///   then comes from `build_proxy` and is logged with reason
    ///   `proxy_attach_invalid_url`, not `proxy_refused` → RED.
    #[tokio::test]
    #[serial_test::serial]
    async fn socks5_per_request_proxy_is_refused_before_any_dial() {
        use std::sync::atomic::Ordering;

        let (proxy_port, proxy_hits) = counting_listener().await;
        let (origin_port, origin_hits) = counting_listener().await;

        // Admit the loopback proxy so that, if the scheme allowlist is
        // mutated to re-allow socks5, the URL passes the private-host veto
        // and the dial stage is genuinely exercised.
        let _env = EnvGuard::set(
            crate::middleware_ssrf::PROXY_ALLOWLIST_ENV,
            format!("127.0.0.1:{proxy_port}"),
        );
        for max_redirects in [crate::HttpConfig::default().max_redirects, 0] {
            let handler = WreqHandler::new(wreq::Client::new(), false, max_redirects, 1 << 20);
            let (result, logs) = capture_logs(handler.handle(Request {
                method: "GET".into(),
                url: format!("http://127.0.0.1:{origin_port}/test"),
                headers: vec![],
                body: None,
                proxy: Some(format!("socks5://127.0.0.1:{proxy_port}")),
                authenticated: false,
            }))
            .await;
            let err = result.expect_err("a socks5 proxy must be refused, not dialled or dropped");
            assert!(
                err.to_string().contains("unsupported proxy scheme"),
                "max_redirects={max_redirects}: expected the unsupported-scheme \
                 refusal naming the scheme, got {err}"
            );
            assert!(
                err.to_string().contains("socks5"),
                "max_redirects={max_redirects}: the refusal must name the scheme, got {err}"
            );
            assert!(
                logs.contains("proxy_refused"),
                "max_redirects={max_redirects}: the refusal must come from \
                 validate_proxy_url (reason=proxy_refused): {logs}"
            );
        }
        drop(_env);
        assert_eq!(
            proxy_hits.load(Ordering::SeqCst),
            0,
            "the socks proxy was dialled — the refusal must precede any connection"
        );
        assert_eq!(
            origin_hits.load(Ordering::SeqCst),
            0,
            "the request reached the target DIRECTLY — a real-IP leak"
        );
    }

    /// #189: the leak scenario the scheme veto exists for. `WreqHandler` is
    /// built WITH its direct-fallback sibling (the shape `HttpClient::build`
    /// produces whenever any proxy is configured) and `max_redirects = 0` —
    /// the exact precondition under which `looks_like_proxy_dial_failure`
    /// routes a failed proxy dial to the direct sibling. A `socks5://`
    /// per-request proxy must still be refused before ANY connection: no
    /// TCP to the "proxy" listener, and — the regression this guards — no
    /// TCP to the target listener (the historical real-IP egress).
    ///
    /// Falsification:
    /// - re-add `"socks5"` to `ALLOWED_PROXY_SCHEMES` (middleware_ssrf.rs):
    ///   the allowlisted loopback proxy validates, wreq dials it as an HTTP
    ///   proxy (a connection the proxy listener counts) and, if that dial
    ///   fails `ProxyConnect`, the fallback sibling re-sends to the target —
    ///   either listener's counter leaves 0, or the response is 200 → RED;
    /// - delete the `validate_proxy_url` call in `execute_with`: same
    ///   outcome via `build_proxy`'s pass → RED;
    /// - widen `looks_like_proxy_dial_failure` to `InvalidUrl` refusals: the
    ///   refusal itself becomes a fallback trigger → the target listener
    ///   counts 1 → RED.
    #[tokio::test]
    #[serial_test::serial]
    async fn socks5_per_request_proxy_with_direct_fallback_dials_nothing() {
        use std::sync::atomic::Ordering;

        let (proxy_port, proxy_hits) = counting_listener().await;
        let (origin_port, origin_hits) = counting_listener().await;

        // As above: admit the loopback proxy so a scheme-allowlist mutation
        // reaches the dial stage instead of stopping at the host veto.
        let _env = EnvGuard::set(
            crate::middleware_ssrf::PROXY_ALLOWLIST_ENV,
            format!("127.0.0.1:{proxy_port}"),
        );
        let direct = wreq::Client::builder()
            .no_proxy()
            .build()
            .expect("direct fallback client");
        let handler =
            WreqHandler::new(wreq::Client::new(), false, 0, 1 << 20).with_direct_fallback(direct);
        let result = handler
            .handle(Request {
                method: "GET".into(),
                url: format!("http://127.0.0.1:{origin_port}/test"),
                headers: vec![],
                body: None,
                proxy: Some(format!("socks5://127.0.0.1:{proxy_port}")),
                authenticated: false,
            })
            .await;
        let err = result.expect_err("a socks5 proxy must be refused, not dialled or dropped");
        assert!(
            err.to_string().contains("unsupported proxy scheme")
                && err.to_string().contains("socks5"),
            "expected the unsupported-scheme refusal naming socks5, got {err}"
        );
        assert_eq!(
            proxy_hits.load(Ordering::SeqCst),
            0,
            "the socks proxy was dialled — the refusal must precede any connection"
        );
        assert_eq!(
            origin_hits.load(Ordering::SeqCst),
            0,
            "the direct-fallback sibling reached the target — a real-IP leak"
        );
    }
}
