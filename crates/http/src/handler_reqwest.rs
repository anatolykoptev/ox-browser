//! Base handler that executes HTTP requests via wreq (BoringSSL).
//!
//! This is the terminal handler in the middleware chain — it converts
//! a [`Request`] into a real HTTP call and returns an [`HttpResponse`].

use std::sync::Arc;

use async_trait::async_trait;
use wreq::Client;

use crate::middleware::{Handler, Request};
use crate::proxy_fallback::{looks_like_proxy_402, record_webshare_402_fallback};
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
}

impl WreqHandler {
    /// Wrap an already-configured wreq client.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            proxy_pool: None,
            direct_client: None,
        }
    }

    /// Wrap a wreq client with a rotating proxy pool.
    ///
    /// Each request picks the next proxy from the pool via
    /// wreq's per-request `RequestBuilder::proxy()`.
    pub fn with_proxy_pool(client: Client, pool: Arc<dyn ProxyPool>) -> Self {
        Self {
            client,
            proxy_pool: Some(pool),
            direct_client: None,
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
    /// override, rotating pool, or static client-level proxy via the parent
    /// `HttpConfig`). The static-client case is implicitly true whenever
    /// `direct_client` is `Some` — `HttpClient::new` only attaches the direct
    /// fallback when a proxy is configured.
    fn first_attempt_uses_proxy(&self, req: &Request) -> bool {
        req.proxy.is_some() || self.proxy_pool.is_some() || self.direct_client.is_some()
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
