//! PO Token provider — calls bgutil-pot sidecar to generate YouTube proof-of-origin tokens.

use serde::{Deserialize, Serialize};

use crate::MediaError;

/// PO Token + visitor data from bgutil-pot sidecar.
#[derive(Debug, Clone)]
pub struct PotData {
    pub po_token: String,
    pub visitor_data: String,
}

#[derive(Debug, Serialize)]
struct PotRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    content_binding: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PotResponse {
    po_token: Option<String>,
    content_binding: Option<String>,
    error: Option<String>,
}

/// Fetch a session-bound PO Token from bgutil-pot sidecar.
///
/// Calls without `content_binding` so bgutil-pot generates visitor data
/// and returns a session-bound (GVS) token. The visitor data must be
/// included in the Innertube `context.client.visitorData` field.
pub async fn fetch_pot_session(pot_url: &str) -> Result<PotData, MediaError> {
    let body = serde_json::to_string(&PotRequest {
        content_binding: None,
    })
    .map_err(|e| MediaError::FetchFailed(format!("pot serialize: {e}")))?;

    let client = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| MediaError::FetchFailed(format!("pot client: {e}")))?;

    let url = format!("{pot_url}/get_pot");
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| MediaError::FetchFailed(format!("pot request: {e}")))?;

    if !resp.status().is_success() {
        return Err(MediaError::FetchFailed(format!(
            "pot HTTP {}",
            resp.status()
        )));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| MediaError::FetchFailed(format!("pot read: {e}")))?;

    let pot_resp: PotResponse = serde_json::from_str(&body)
        .map_err(|e| MediaError::FetchFailed(format!("pot parse: {e}")))?;

    if let Some(err) = pot_resp.error {
        return Err(MediaError::FetchFailed(format!("pot error: {err}")));
    }

    let po_token = pot_resp
        .po_token
        .ok_or_else(|| MediaError::FetchFailed("pot: no token in response".into()))?;
    let visitor_data = pot_resp
        .content_binding
        .ok_or_else(|| MediaError::FetchFailed("pot: no visitor data".into()))?;

    Ok(PotData {
        po_token,
        visitor_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pot_request_no_binding_skips_field() {
        let req = PotRequest {
            content_binding: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("content_binding"));
    }

    #[test]
    fn pot_response_parses_session() {
        let json = r#"{"poToken":"tok123","contentBinding":"visitor_abc","expiresAt":"2026-01-01T00:00:00Z"}"#;
        let resp: PotResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.po_token.as_deref(), Some("tok123"));
        assert_eq!(resp.content_binding.as_deref(), Some("visitor_abc"));
        assert!(resp.error.is_none());
    }

    #[test]
    fn pot_response_parses_error() {
        let json = r#"{"error":"generation failed"}"#;
        let resp: PotResponse = serde_json::from_str(json).unwrap();
        assert!(resp.po_token.is_none());
        assert_eq!(resp.error.as_deref(), Some("generation failed"));
    }
}
