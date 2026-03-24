//! ByparrSolver — FlareSolverr-compatible CookieProvider.
//!
//! Limits concurrent solver requests based on available memory.
//! Each Camoufox browser spawned by byparr uses ~100 MB; the semaphore
//! ensures we never exceed the solver container's capacity.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::cloudflare::ChallengeType;
use crate::cookie_provider::{CookieProvider, SolvedChallenge};

/// Estimated memory per Camoufox browser instance in megabytes.
const BROWSER_MB: usize = 100;

/// Memory reserved for the byparr Python process itself (MB).
const OVERHEAD_MB: usize = 150;

/// Configuration for connecting to a FlareSolverr-compatible service.
#[derive(Debug, Clone)]
pub struct ByparrConfig {
    pub base_url: String,
    pub timeout: Duration,
    /// Memory budget for the solver container in megabytes.
    /// Used to calculate max concurrent browsers: (budget - overhead) / per_browser.
    /// Example: 768 MB → (768 - 150) / 100 = 6 concurrent.
    pub memory_budget_mb: usize,
}

impl Default for ByparrConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8191".to_string(),
            timeout: Duration::from_secs(60),
            memory_budget_mb: 768,
        }
    }
}

impl ByparrConfig {
    /// Calculate max concurrent browsers from memory budget.
    pub fn max_concurrent(&self) -> usize {
        let usable = self.memory_budget_mb.saturating_sub(OVERHEAD_MB);
        (usable / BROWSER_MB).max(1)
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
    /// Full page HTML returned by solver.
    response: Option<String>,
}

#[derive(Deserialize)]
struct SolverCookie {
    name: String,
    value: String,
}

/// Solves Cloudflare challenges via a FlareSolverr-compatible HTTP API.
///
/// Uses a semaphore derived from `memory_budget_mb` to limit concurrent
/// solver requests. Each request spawns a headless browser in byparr;
/// the reaper script inside the container kills browsers older than 5 min.
pub struct ByparrSolver {
    config: ByparrConfig,
    client: wreq::Client,
    semaphore: Semaphore,
}

impl ByparrSolver {
    pub fn new(config: ByparrConfig) -> Self {
        let client = wreq::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("failed to build wreq client");
        let max_concurrent = config.max_concurrent();
        tracing::info!(
            memory_budget_mb = config.memory_budget_mb,
            max_concurrent,
            "byparr solver initialized"
        );
        let semaphore = Semaphore::new(max_concurrent);
        Self {
            config,
            client,
            semaphore,
        }
    }
}

#[async_trait]
impl CookieProvider for ByparrSolver {
    async fn solve(
        &self,
        url: &str,
        _challenge_type: ChallengeType,
    ) -> Result<SolvedChallenge, String> {
        // Acquire semaphore permit — blocks if max concurrent solves are in-flight.
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| format!("byparr semaphore closed: {e}"))?;

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
            body: solution.response,
        })
    }
}

#[cfg(test)]
#[path = "solver_byparr_tests.rs"]
mod tests;
