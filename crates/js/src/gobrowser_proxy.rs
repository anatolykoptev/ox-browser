//! Proxy Chrome operations to go-browser HTTP service.

use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

/// Proxy client for forwarding requests to go-browser.
#[derive(Clone)]
pub struct GoBrowserProxy {
    base_url: String,
    client: Client,
}

impl GoBrowserProxy {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("proxy client");
        Self { base_url, client }
    }

    /// Forward a JSON POST request to go-browser.
    pub async fn forward(&self, path: &str, body: &Value) -> Result<(u16, Value), String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| format!("go-browser proxy: {e}"))?;
        let status = resp.status().as_u16();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("go-browser proxy parse: {e}"))?;
        Ok((status, body))
    }

    /// Forward a DELETE request.
    pub async fn delete(&self, path: &str) -> Result<(u16, Value), String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .delete(&url)
            .send()
            .await
            .map_err(|e| format!("go-browser proxy delete: {e}"))?;
        let status = resp.status().as_u16();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("go-browser proxy parse: {e}"))?;
        Ok((status, body))
    }
}
