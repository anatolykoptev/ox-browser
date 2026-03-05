use std::sync::atomic::{AtomicUsize, Ordering};

use serde::Deserialize;

use crate::proxy_pool::ProxyPool;
use crate::HttpError;

const WEBSHARE_API_URL: &str =
    "https://proxy.webshare.io/api/v2/proxy/list/?mode=backbone&page_size=100";

/// A proxy pool backed by the Webshare.io API.
///
/// Fetches the proxy list on construction and rotates through them
/// with round-robin selection.
pub struct WebsharePool {
    proxies: Vec<String>,
    counter: AtomicUsize,
}

#[derive(Deserialize)]
struct WebshareResponse {
    results: Vec<WebshareProxy>,
}

#[derive(Deserialize)]
struct WebshareProxy {
    proxy_address: String,
    port: u16,
    username: String,
    password: String,
}

impl WebsharePool {
    /// Fetches the proxy list from the Webshare API and builds a pool.
    ///
    /// Each proxy is formatted as `http://username:password@host:port`.
    pub async fn new(api_key: &str) -> crate::Result<Self> {
        if api_key.is_empty() {
            return Err(HttpError::ProxyPool("Webshare API key is empty".into()));
        }
        let client = wreq::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        let resp = client
            .get(WEBSHARE_API_URL)
            .header("Authorization", format!("Token {api_key}"))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(HttpError::ProxyPool(format!(
                "Webshare API returned status {status}"
            )));
        }

        let body = resp.text().await?;
        let proxies = parse_webshare_response(&body)?;

        if proxies.is_empty() {
            return Err(HttpError::ProxyPool(
                "Webshare API returned no proxies".into(),
            ));
        }

        Ok(Self {
            proxies,
            counter: AtomicUsize::new(0),
        })
    }
}

/// Parses a Webshare API JSON response into proxy URL strings.
fn parse_webshare_response(body: &str) -> crate::Result<Vec<String>> {
    let response: WebshareResponse =
        serde_json::from_str(body).map_err(|e| HttpError::ProxyPool(e.to_string()))?;

    Ok(response
        .results
        .into_iter()
        .map(|p| {
            format!(
                "http://{}:{}@{}:{}",
                p.username, p.password, p.proxy_address, p.port
            )
        })
        .collect())
}

impl ProxyPool for WebsharePool {
    fn next(&self) -> Option<String> {
        if self.proxies.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.proxies.len();
        Some(self.proxies[idx].clone())
    }

    fn len(&self) -> usize {
        self.proxies.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_RESPONSE: &str = r#"{
        "count": 2,
        "results": [
            {
                "proxy_address": "1.2.3.4",
                "port": 8080,
                "username": "user1",
                "password": "pass1"
            },
            {
                "proxy_address": "5.6.7.8",
                "port": 9090,
                "username": "user2",
                "password": "pass2"
            }
        ]
    }"#;

    #[test]
    fn parse_response_builds_urls() {
        let proxies = parse_webshare_response(MOCK_RESPONSE).unwrap();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0], "http://user1:pass1@1.2.3.4:8080");
        assert_eq!(proxies[1], "http://user2:pass2@5.6.7.8:9090");
    }

    #[test]
    fn parse_empty_results() {
        let body = r#"{"count": 0, "results": []}"#;
        let proxies = parse_webshare_response(body).unwrap();
        assert!(proxies.is_empty());
    }

    #[test]
    fn parse_invalid_json() {
        let result = parse_webshare_response("not json");
        assert!(result.is_err());
    }
}
