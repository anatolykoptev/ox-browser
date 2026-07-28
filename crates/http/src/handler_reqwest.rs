//! Base handler that executes HTTP requests via wreq (BoringSSL).
//!
//! This is the terminal handler in the middleware chain — it converts
//! a [`Request`] into a real HTTP call and returns an [`HttpResponse`].

use std::sync::Arc;

use async_trait::async_trait;
use wreq::Client;

use crate::middleware::{Handler, Request};
use crate::proxy_fallback::{
    looks_like_proxy_402, looks_like_proxy_dial_failure, record_proxy_dial_fallback,
    record_webshare_402_fallback,
};
use crate::proxy_pool::ProxyPool;
use crate::{HttpError, HttpResponse, Result};

/// Handler that executes HTTP requests using a [`wreq::Client`].
///
/// Sits at the bottom of the middleware chain. Converts the generic
/// [`Request`] (with ordered headers) into a wreq request, sends it,
/// and builds an [`HttpResponse`] from the result.
///
/// On HTTP 402 from an upstream proxy (Webshare quota exhausted), retries the
/// request **once** through [`Self::direct_client`] (no proxy). See
/// [`crate::proxy_fallback`] for the rationale.
pub struct WreqHandler {
    client: Client,
    proxy_pool: Option<Arc<dyn ProxyPool>>,
    /// Sibling client with no proxy. When `Some`, we retry on Webshare 402.
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
}

impl WreqHandler {
    /// Wrap an already-configured wreq client.
    ///
    /// `client_has_static_proxy` must be `true` iff the client was built with a
    /// static `proxy_url` baked in (so the FIRST attempt is proxied even when
    /// `req.proxy` is `None` and no pool is set). `max_redirects` is the
    /// configured redirect limit, used to gate the dial-failure classifier.
    pub fn new(client: Client, client_has_static_proxy: bool, max_redirects: usize) -> Self {
        Self {
            client,
            proxy_pool: None,
            direct_client: None,
            client_has_static_proxy,
            max_redirects,
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
    ) -> Self {
        Self {
            client,
            proxy_pool: Some(pool),
            direct_client: None,
            client_has_static_proxy,
            max_redirects,
        }
    }

    /// Attach a direct (no-proxy) sibling client used as fallback on
    /// HTTP 402 from the upstream proxy.
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
            "POST" => client.post(&req.url),
            "PUT" => client.put(&req.url),
            "DELETE" => client.delete(&req.url),
            "PATCH" => client.patch(&req.url),
            "HEAD" => client.head(&req.url),
            _ => client.get(&req.url),
        };

        if !skip_proxy {
            if let Some(ref proxy_url) = req.proxy {
                if let Ok(proxy) = wreq::Proxy::all(proxy_url) {
                    builder = builder.proxy(proxy);
                }
            } else if let Some(ref pool) = self.proxy_pool
                && let Some(proxy_url) = pool.next()
                && let Ok(proxy) = wreq::Proxy::all(&proxy_url)
            {
                builder = builder.proxy(proxy);
            }
        }

        tracing::debug!(
            url = %req.url,
            method = %req.method,
            proxy = ?req.proxy,
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
        let body = resp.text().await?;

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
        let used_proxy = self.first_attempt_uses_proxy(&req);
        if used_proxy {
            crate::metrics::record_proxy_used();
        }

        let primary = self.execute_with(&self.client, &req, false).await;

        // Detect an upstream-proxy 402 regardless of whether a direct fallback
        // is wired — the counter must reflect the real event so the operator
        // can see 402s that did NOT degrade (fallback gap).
        let is_proxy_402 = used_proxy
            && match &primary {
                Ok(resp) if resp.status == 402 => true,
                Err(HttpError::Request(e)) if looks_like_proxy_402(e) => true,
                _ => false,
            };
        if is_proxy_402 {
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
        let is_proxy_dial =
            used_proxy && matches!(&primary, Err(HttpError::Request(e)) if e.is_proxy_connect());
        if is_proxy_dial {
            crate::metrics::record_proxy_dial();
        }

        // Decide whether to fall back. Only when:
        // 1. We actually have a direct-client sibling, AND
        // 2. The first attempt was proxied, AND
        // 3. The error/response indicates upstream proxy 402.
        let Some(ref direct) = self.direct_client else {
            return primary;
        };
        if !used_proxy {
            return primary;
        }

        match primary {
            // Webshare 402 surfaced as a real HTTP response from the proxy.
            Ok(resp) if resp.status == 402 => {
                record_webshare_402_fallback(&req.url);
                self.execute_with(direct, &req, true).await
            }
            // Webshare 402 surfaced as a wrapped wreq connect error.
            Err(HttpError::Request(ref e)) if looks_like_proxy_402(e) => {
                record_webshare_402_fallback(&req.url);
                self.execute_with(direct, &req, true).await
            }
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
                self.execute_with(direct, &req, true).await
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wreq_handler_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WreqHandler>();
    }
}
