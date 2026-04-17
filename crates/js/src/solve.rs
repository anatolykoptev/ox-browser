//! POST /solve — Cloudflare challenge solver endpoint.

use std::collections::HashMap;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use ox_http::ChallengeType;
use serde::{Deserialize, Serialize};
use url::Url;

use super::AppState;

/// Incoming solve request body.
#[derive(Deserialize)]
pub struct SolveRequest {
    pub url: String,
    #[serde(default = "default_challenge_type")]
    pub challenge_type: String,
}

fn default_challenge_type() -> String {
    "js_challenge".into()
}

/// Response returned by the /solve endpoint.
#[derive(Serialize, Deserialize)]
pub struct SolveResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookies: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn solve(
    State(state): State<AppState>,
    Json(req): Json<SolveRequest>,
) -> (StatusCode, Json<SolveResponse>) {
    let challenge_type = match req.challenge_type.as_str() {
        "js_challenge" => ChallengeType::JsChallenge,
        "managed_challenge" | "turnstile" => ChallengeType::Turnstile,
        "managed_challenge_200" => ChallengeType::ManagedChallenge,
        "block" => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SolveResponse {
                    status: "error".into(),
                    cookies: None,
                    user_agent: None,
                    error: Some("block challenges are not solvable".into()),
                }),
            );
        }
        _ => ChallengeType::JsChallenge,
    };

    let domain = match Url::parse(&req.url) {
        Ok(u) => u.host_str().unwrap_or("unknown").to_owned(),
        Err(_) => "unknown".to_owned(),
    };

    if let Some(cached) = state.cache.get(&domain) {
        tracing::debug!(domain, "cache hit");
        return (
            StatusCode::OK,
            Json(SolveResponse {
                status: "ok".into(),
                cookies: Some(cached.cookies),
                user_agent: Some(cached.user_agent),
                error: None,
            }),
        );
    }

    match state.provider.solve(&req.url, challenge_type).await {
        Ok(solved) => {
            state.cache.put(&domain, solved.clone());
            tracing::info!(domain, "challenge solved");
            (
                StatusCode::OK,
                Json(SolveResponse {
                    status: "ok".into(),
                    cookies: Some(solved.cookies),
                    user_agent: Some(solved.user_agent),
                    error: None,
                }),
            )
        }
        Err(e) => {
            tracing::warn!(domain, error = %e, "solve failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(SolveResponse {
                    status: "error".into(),
                    cookies: None,
                    user_agent: None,
                    error: Some(e),
                }),
            )
        }
    }
}
