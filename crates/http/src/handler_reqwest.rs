//! Base handler that executes HTTP requests via reqwest.
//!
//! This is the terminal handler in the middleware chain — it converts
//! a [`Request`] into a real HTTP call and returns an [`HttpResponse`].

use async_trait::async_trait;
use reqwest::Client;

use crate::middleware::{Handler, Request};
use crate::{HttpResponse, Result};

/// Handler that executes HTTP requests using a [`reqwest::Client`].
///
/// Sits at the bottom of the middleware chain. Converts the generic
/// [`Request`] (with ordered headers) into a reqwest request, sends it,
/// and builds an [`HttpResponse`] from the result.
pub struct ReqwestHandler {
    client: Client,
}

impl ReqwestHandler {
    /// Wrap an already-configured reqwest client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Handler for ReqwestHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let mut builder = match req.method.to_uppercase().as_str() {
            "POST" => self.client.post(&req.url),
            "PUT" => self.client.put(&req.url),
            "DELETE" => self.client.delete(&req.url),
            "PATCH" => self.client.patch(&req.url),
            "HEAD" => self.client.head(&req.url),
            _ => self.client.get(&req.url),
        };

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
        let final_url = resp.url().to_string();
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
    fn reqwest_handler_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ReqwestHandler>();
    }
}
