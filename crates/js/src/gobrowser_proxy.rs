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
    /// `internal_secret` is sent as `X-Internal-Secret` on every forwarded
    /// request (go-wowa rejects requests without a credential); empty = none.
    pub fn new(base_url: String, internal_secret: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .default_headers(ox_http::wowa_auth::headers(internal_secret))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// go-wowa rejects requests without a credential: forwarded
    /// `/chrome/interact` calls must carry `X-Internal-Secret`.
    ///
    /// Falsification: drop the `.default_headers(...)` line in
    /// `GoBrowserProxy::new` and the captured request has no secret → RED.
    #[tokio::test]
    async fn forward_sends_internal_secret() {
        let (url, req) = ox_http::wowa_auth::capture_one(r#"{"status":"ok"}"#).await;
        let proxy = GoBrowserProxy::new(url, "s3cret");
        let (status, _) = proxy
            .forward("/api/v1/chrome/interact", &serde_json::json!({}))
            .await
            .expect("forward");
        assert_eq!(status, 200);
        let head = req.await.expect("capture");
        assert!(head.starts_with("post /api/v1/chrome/interact "), "{head}");
        assert!(head.contains("x-internal-secret: s3cret"), "{head}");
    }
}
