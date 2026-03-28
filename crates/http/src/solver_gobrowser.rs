//! GoBrowserSolver — CookieProvider that delegates to go-browser HTTP service.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::cloudflare::ChallengeType;
use crate::cookie_provider::{CookieProvider, SolvedChallenge};

/// Configuration for the go-browser HTTP solver.
#[derive(Debug, Clone)]
pub struct GoBrowserConfig {
    pub base_url: String,
    pub timeout: Duration,
}

impl Default for GoBrowserConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8906".to_owned(),
            timeout: Duration::from_secs(35),
        }
    }
}

pub struct GoBrowserSolver {
    base_url: String,
    client: reqwest::Client,
}

#[derive(Serialize)]
struct SolveReq {
    url: String,
    challenge_type: String,
    timeout_secs: u64,
}

#[derive(Deserialize)]
struct SolveResp {
    status: String,
    cookies: Option<HashMap<String, String>>,
    error: Option<String>,
}

impl GoBrowserSolver {
    pub fn new(config: GoBrowserConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("reqwest client");
        Self {
            base_url: config.base_url,
            client,
        }
    }
}

#[async_trait]
impl CookieProvider for GoBrowserSolver {
    async fn solve(
        &self,
        url: &str,
        challenge_type: ChallengeType,
    ) -> Result<SolvedChallenge, String> {
        let ct = match challenge_type {
            ChallengeType::JsChallenge => "js_challenge",
            ChallengeType::Turnstile => "managed_challenge",
            ChallengeType::ManagedChallenge => "managed_challenge_200",
            ChallengeType::Block => return Err("block challenges not solvable".into()),
        };

        let endpoint = format!("{}/solve", self.base_url);
        let resp = self
            .client
            .post(&endpoint)
            .json(&SolveReq {
                url: url.to_owned(),
                challenge_type: ct.to_owned(),
                timeout_secs: 30,
            })
            .send()
            .await
            .map_err(|e| format!("go-browser /solve: {e}"))?;

        let body: SolveResp = resp
            .json()
            .await
            .map_err(|e| format!("go-browser /solve parse: {e}"))?;

        if body.status != "ok" {
            return Err(body.error.unwrap_or_else(|| "unknown error".into()));
        }

        Ok(SolvedChallenge {
            cookies: body.cookies.unwrap_or_default(),
            user_agent: String::new(),
            body: None,
        })
    }
}
