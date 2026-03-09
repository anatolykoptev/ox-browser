//! PO Token provider — calls bgutil-pot sidecar to generate YouTube proof-of-origin tokens.

use serde::{Deserialize, Serialize};

use crate::MediaError;

#[derive(Debug, Serialize)]
struct PotRequest {
    content_binding: String,
}

#[derive(Debug, Deserialize)]
struct PotResponse {
    po_token: Option<String>,
    error: Option<String>,
}

/// Fetch a PO Token from bgutil-pot sidecar for the given video ID.
///
/// Returns `Ok(token)` on success, or `Err` if the sidecar is unreachable or returns an error.
pub async fn fetch_po_token(
    pot_url: &str,
    video_id: &str,
) -> Result<String, MediaError> {
    let body = serde_json::to_string(&PotRequest {
        content_binding: video_id.to_owned(),
    })
    .map_err(|e| MediaError::FetchFailed(format!("pot serialize: {e}")))?;

    let client = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| MediaError::FetchFailed(format!("pot client: {e}")))?;

    let url = format!("{pot_url}/generate");
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

    pot_resp
        .po_token
        .ok_or_else(|| MediaError::FetchFailed("pot: no token in response".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pot_request_serializes_correctly() {
        let req = PotRequest {
            content_binding: "dQw4w9WgXcQ".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("dQw4w9WgXcQ"));
        assert!(json.contains("content_binding"));
    }

    #[test]
    fn pot_response_parses_success() {
        let json = r#"{"po_token":"abc123"}"#;
        let resp: PotResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.po_token.as_deref(), Some("abc123"));
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
