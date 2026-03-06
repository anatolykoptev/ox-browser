//! ByparrSolver — FlareSolverr-compatible CookieProvider.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::cloudflare::ChallengeType;
use crate::cookie_provider::{CookieProvider, SolvedChallenge};

/// Configuration for connecting to a FlareSolverr-compatible service.
#[derive(Debug, Clone)]
pub struct ByparrConfig {
    pub base_url: String,
    pub timeout: Duration,
}

impl Default for ByparrConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8191".to_string(),
            timeout: Duration::from_secs(60),
        }
    }
}

// --- FlareSolverr serde types (private) ---

#[derive(Serialize)]
struct SolverRequest {
    cmd: String,
    url: String,
    #[serde(rename = "maxTimeout")]
    max_timeout: u64,
}

#[derive(Deserialize)]
struct SolverResponse {
    status: String,
    solution: Option<SolverSolution>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct SolverSolution {
    #[allow(dead_code)]
    url: String,
    cookies: Vec<SolverCookie>,
    #[serde(rename = "userAgent")]
    user_agent: String,
}

#[derive(Deserialize)]
struct SolverCookie {
    name: String,
    value: String,
}

/// Solves Cloudflare challenges via a FlareSolverr-compatible HTTP API.
pub struct ByparrSolver {
    config: ByparrConfig,
    client: wreq::Client,
}

impl ByparrSolver {
    pub fn new(config: ByparrConfig) -> Self {
        let client = wreq::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("failed to build wreq client");
        Self { config, client }
    }
}

#[async_trait]
impl CookieProvider for ByparrSolver {
    async fn solve(
        &self,
        url: &str,
        _challenge_type: ChallengeType,
    ) -> Result<SolvedChallenge, String> {
        let endpoint = format!("{}/v1", self.config.base_url);
        let body = SolverRequest {
            cmd: "request.get".to_string(),
            url: url.to_string(),
            max_timeout: self.config.timeout.as_millis() as u64,
        };

        let json_body = serde_json::to_string(&body)
            .map_err(|e| format!("byparr serialize failed: {e}"))?;

        let resp = self
            .client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .body(json_body)
            .send()
            .await
            .map_err(|e| format!("byparr request failed: {e}"))?;

        let text = resp
            .text()
            .await
            .map_err(|e| format!("byparr response read failed: {e}"))?;

        let parsed: SolverResponse = serde_json::from_str(&text)
            .map_err(|e| format!("byparr response parse failed: {e}"))?;

        if parsed.status != "ok" {
            let msg = parsed
                .message
                .unwrap_or_else(|| "unknown error".to_string());
            return Err(format!("byparr solver error: {msg}"));
        }

        let solution = parsed
            .solution
            .ok_or("byparr response missing solution")?;

        let cookies: HashMap<String, String> = solution
            .cookies
            .into_iter()
            .map(|c| (c.name, c.value))
            .collect();

        Ok(SolvedChallenge {
            cookies,
            user_agent: solution.user_agent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = ByparrConfig::default();
        assert_eq!(cfg.base_url, "http://127.0.0.1:8191");
        assert_eq!(cfg.timeout, Duration::from_secs(60));
    }

    #[test]
    fn solver_request_serializes() {
        let req = SolverRequest {
            cmd: "request.get".into(),
            url: "https://example.com".into(),
            max_timeout: 60000,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["cmd"], "request.get");
        assert_eq!(json["url"], "https://example.com");
        assert_eq!(json["maxTimeout"], 60000);
        assert!(!json.as_object().unwrap().contains_key("max_timeout"));
    }

    #[test]
    fn solver_response_deserializes_ok() {
        let json = r#"{
            "status": "ok",
            "solution": {
                "url": "https://example.com",
                "cookies": [
                    {"name": "cf_clearance", "value": "abc123"},
                    {"name": "__cflb", "value": "xyz"}
                ],
                "userAgent": "Mozilla/5.0 Test"
            },
            "message": null
        }"#;
        let resp: SolverResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "ok");
        let sol = resp.solution.unwrap();
        assert_eq!(sol.cookies.len(), 2);
        assert_eq!(sol.cookies[0].name, "cf_clearance");
        assert_eq!(sol.cookies[0].value, "abc123");
        assert_eq!(sol.user_agent, "Mozilla/5.0 Test");
    }

    #[test]
    fn solver_response_deserializes_error() {
        let json = r#"{
            "status": "error",
            "solution": null,
            "message": "Challenge not detected!"
        }"#;
        let resp: SolverResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "error");
        assert!(resp.solution.is_none());
        assert_eq!(resp.message.unwrap(), "Challenge not detected!");
    }

    #[test]
    fn byparr_solver_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ByparrSolver>();
    }
}
