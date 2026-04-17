//! MCP tool implementation for Cloudflare challenge solving.

use std::collections::HashMap;

use ox_http::ChallengeType;
use rmcp::ErrorData as McpError;
use rmcp::model::*;
use serde::{Deserialize, Serialize};

use rmcp::schemars;
use schemars::JsonSchema;
use url::Url;

use super::OxMcpServer;

/// Input parameters for the `solve_cf` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SolveCfInput {
    /// The URL behind a Cloudflare challenge.
    pub url: String,
    /// Challenge type: js_challenge, managed_challenge, turnstile, block.
    /// Defaults to js_challenge.
    #[serde(default = "default_challenge_type")]
    pub challenge_type: Option<String>,
}

fn default_challenge_type() -> Option<String> {
    Some("js_challenge".into())
}

#[derive(Serialize)]
struct SolveResult {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookies: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl OxMcpServer {
    /// Solve a Cloudflare challenge and return clearance cookies.
    pub(crate) async fn do_solve_cf(
        &self,
        input: SolveCfInput,
    ) -> Result<CallToolResult, McpError> {
        let ct_str = input.challenge_type.as_deref().unwrap_or("js_challenge");
        let challenge_type = match ct_str {
            "js_challenge" => ChallengeType::JsChallenge,
            "managed_challenge" | "turnstile" => ChallengeType::Turnstile,
            "managed_challenge_200" => ChallengeType::ManagedChallenge,
            "block" => {
                let r = SolveResult {
                    status: "error".into(),
                    cookies: None,
                    user_agent: None,
                    error: Some("block challenges are not solvable".into()),
                };
                let json = serde_json::to_string(&r).unwrap_or_default();
                return Ok(CallToolResult::error(vec![Content::text(json)]));
            }
            _ => ChallengeType::JsChallenge,
        };

        let domain = Url::parse(&input.url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "unknown".into());

        // Check cache first.
        if let Some(cached) = self.cache.get(&domain) {
            tracing::debug!(domain, "cache hit");
            let r = SolveResult {
                status: "ok".into(),
                cookies: Some(cached.cookies),
                user_agent: Some(cached.user_agent),
                error: None,
            };
            let json = serde_json::to_string(&r).unwrap_or_default();
            return Ok(CallToolResult::success(vec![Content::text(json)]));
        }

        match self.provider.solve(&input.url, challenge_type).await {
            Ok(solved) => {
                self.cache.put(&domain, solved.clone());
                tracing::info!(domain, "challenge solved");
                let r = SolveResult {
                    status: "ok".into(),
                    cookies: Some(solved.cookies),
                    user_agent: Some(solved.user_agent),
                    error: None,
                };
                let json = serde_json::to_string(&r).unwrap_or_default();
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => {
                tracing::warn!(domain, error = %e, "solve failed");
                let r = SolveResult {
                    status: "error".into(),
                    cookies: None,
                    user_agent: None,
                    error: Some(e),
                };
                let json = serde_json::to_string(&r).unwrap_or_default();
                Ok(CallToolResult::error(vec![Content::text(json)]))
            }
        }
    }
}
