//! Castle.io token solver for Twitter API login.
//!
//! Twitter requires a valid `x-castle-request-token` header in onboarding/task.json.
//! An external solver at castle.botwitter.com generates valid tokens given a user-agent
//! and a random CUID (16-byte hex string).

use serde::{Deserialize, Serialize};

const CASTLE_SOLVER_URL: &str = "https://castle.botwitter.com/generate-token";

#[derive(Serialize)]
struct CastleRequest<'a> {
    #[serde(rename = "userAgent")]
    user_agent: &'a str,
    cuid: &'a str,
}

#[derive(Deserialize)]
struct CastleResponse {
    success: bool,
    token: Option<String>,
    #[allow(dead_code)]
    cuid: Option<String>,
}

/// Generate a random CUID and fetch a Castle.io token from the external solver.
///
/// Returns `(cuid, token)` on success, `None` on any error.
/// Failure is non-fatal — the login flow continues without the castle token.
pub(super) async fn fetch_castle_token(
    client: &wreq::Client,
    user_agent: &str,
) -> Option<(String, String)> {
    // Generate a random 16-byte hex CUID
    let mut bytes = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut bytes);
    let cuid: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    let req = CastleRequest { user_agent, cuid: &cuid };

    let resp = client
        .post(CASTLE_SOLVER_URL)
        .json(&req)
        .send()
        .await
        .map_err(|e| tracing::warn!(error = %e, "castle solver: request failed"))
        .ok()?;

    let body: CastleResponse = resp
        .json()
        .await
        .map_err(|e| tracing::warn!(error = %e, "castle solver: parse failed"))
        .ok()?;

    if !body.success {
        tracing::warn!("castle solver: returned success=false");
        return None;
    }

    let token = body.token?;
    tracing::info!(cuid = %cuid, token_len = token.len(), "castle solver: got token");
    Some((cuid, token))
}
