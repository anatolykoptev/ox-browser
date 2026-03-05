//! Base handler that executes HTTP requests via wreq (BoringSSL).
//!
//! This is the terminal handler in the middleware chain — it converts
//! a [`Request`] into a real HTTP call and returns an [`HttpResponse`].

use std::sync::Arc;

use async_trait::async_trait;
use wreq::Client;

use crate::middleware::{Handler, Request};
use crate::proxy_pool::ProxyPool;
use crate::{HttpResponse, Result};

/// Handler that executes HTTP requests using a [`wreq::Client`].
///
/// Sits at the bottom of the middleware chain. Converts the generic
/// [`Request`] (with ordered headers) into a wreq request, sends it,
/// and builds an [`HttpResponse`] from the result.
pub struct WreqHandler {
    client: Client,
    proxy_pool: Option<Arc<dyn ProxyPool>>,
}

impl WreqHandler {
    /// Wrap an already-configured wreq client.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            proxy_pool: None,
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
        }
    }
}

#[async_trait]
impl Handler for WreqHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let mut builder = match req.method.to_uppercase().as_str() {
            "POST" => self.client.post(&req.url),
            "PUT" => self.client.put(&req.url),
            "DELETE" => self.client.delete(&req.url),
            "PATCH" => self.client.patch(&req.url),
            "HEAD" => self.client.head(&req.url),
            _ => self.client.get(&req.url),
        };

        // Rotating proxy: pick next proxy from pool per-request.
        if let Some(ref pool) = self.proxy_pool {
            if let Some(proxy_url) = pool.next() {
                if let Ok(proxy) = wreq::Proxy::all(&proxy_url) {
                    builder = builder.proxy(proxy);
                }
            }
        }

        // Apply headers in insertion order (important for fingerprinting).
        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        // Attach body if present.
        if let Some(body) = req.body {
            builder = builder.body(body);
        }

        let resp = builder.send().await?;
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
