//! YouTube Innertube API client — direct player requests with PO Token support.

use crate::pot::{self, PotData};
use crate::youtube::{PlayerFormat, PlayerResponse};
use crate::{MediaConfig, MediaError};

/// Build JSON request body for the Innertube MWEB client.
/// When `pot` is provided, includes `visitorData` in client context
/// and `poToken` in `serviceIntegrityDimensions`.
pub fn build_mweb_body(video_id: &str, config: &MediaConfig, pot: Option<&PotData>) -> String {
    let visitor = pot
        .map(|p| format!(r#","visitorData":"{}""#, p.visitor_data))
        .unwrap_or_default();
    let sid = pot
        .map(|p| format!(r#","serviceIntegrityDimensions":{{"poToken":"{}"}}"#, p.po_token))
        .unwrap_or_default();

    format!(
        r#"{{"videoId":"{video_id}","context":{{"client":{{"clientName":"MWEB","clientVersion":"{}"{visitor}}}}}{sid}}}"#,
        config.mweb_version,
    )
}

/// Extract 11-char video ID from any YouTube URL format.
pub fn extract_video_id(url: &str) -> Option<&str> {
    if let Some(rest) = url
        .strip_prefix("https://youtu.be/")
        .or_else(|| url.strip_prefix("http://youtu.be/"))
    {
        return take_video_id(rest);
    }

    let path_start = url.find("youtube.com")?;
    let after_host = &url[path_start + "youtube.com".len()..];

    if after_host.starts_with("/watch") {
        return extract_param(url, "v");
    }

    for prefix in &["/embed/", "/shorts/", "/v/"] {
        if let Some(rest) = after_host.strip_prefix(prefix) {
            return take_video_id(rest);
        }
    }

    None
}

fn take_video_id(s: &str) -> Option<&str> {
    let end = s
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        .unwrap_or(s.len())
        .min(11);
    let id = &s[..end];
    if id.len() == 11 { Some(id) } else { None }
}

fn extract_param<'a>(url: &'a str, key: &str) -> Option<&'a str> {
    let query_start = url.find('?')?;
    let query = &url[query_start + 1..];
    for pair in query.split('&') {
        if let Some(val) = pair.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
            return take_video_id(val);
        }
    }
    None
}

/// Check whether a `PlayerResponse` has usable streams with direct URLs.
pub fn has_usable_streams(pr: &PlayerResponse) -> bool {
    if let Some(ref ps) = pr.playability_status {
        if ps.status != "OK" {
            return false;
        }
    }
    let Some(sd) = &pr.streaming_data else {
        return false;
    };
    let has_direct = |f: &PlayerFormat| f.url.is_some() && f.signature_cipher.is_none();
    sd.formats.iter().any(has_direct) || sd.adaptive_formats.iter().any(has_direct)
}

/// Fetch player response from YouTube Innertube API.
///
/// Strategy:
/// 1. Get session-bound PO Token + visitor data from bgutil-pot
/// 2. Try MWEB with PO Token + visitor data
/// 3. Fall back to MWEB without PO Token
pub async fn fetch_player_response(
    http_client: &ox_http::HttpClient,
    video_id: &str,
    config: &MediaConfig,
) -> Result<PlayerResponse, MediaError> {
    // Try with session-bound PO Token if bgutil-pot is configured
    if !config.pot_url.is_empty() {
        match pot::fetch_pot_session(&config.pot_url).await {
            Ok(pot_data) => {
                tracing::debug!(video_id, "got session POT, trying MWEB+POT");
                let body = build_mweb_body(video_id, config, Some(&pot_data));
                match try_innertube(http_client, &config.innertube_url, &body).await {
                    Ok(pr) if has_usable_streams(&pr) => {
                        tracing::info!(video_id, "MWEB+POT success");
                        return Ok(pr);
                    }
                    Ok(_) => tracing::debug!(video_id, "MWEB+POT: no usable streams"),
                    Err(e) => tracing::debug!(video_id, error = %e, "MWEB+POT request failed"),
                }
            }
            Err(e) => {
                tracing::warn!(video_id, error = %e, "POT session failed, trying without");
            }
        }
    }

    // Fallback: MWEB without PO Token
    let body = build_mweb_body(video_id, config, None);
    let pr = try_innertube(http_client, &config.innertube_url, &body).await?;
    if has_usable_streams(&pr) {
        tracing::info!(video_id, "MWEB (no POT) success");
        return Ok(pr);
    }

    Err(MediaError::NoVideoFound)
}

async fn try_innertube(
    http_client: &ox_http::HttpClient,
    innertube_url: &str,
    body: &str,
) -> Result<PlayerResponse, MediaError> {
    let resp = http_client
        .post(innertube_url, body, "application/json")
        .await
        .map_err(|e| MediaError::FetchFailed(format!("innertube: {e}")))?;

    if resp.status != 200 {
        return Err(MediaError::FetchFailed(format!("innertube HTTP {}", resp.status)));
    }

    let pr = serde_json::from_str::<PlayerResponse>(&resp.body)
        .map_err(|e| MediaError::FetchFailed(format!("innertube parse: {e}")))?;
    if let Some(ref ps) = pr.playability_status {
        tracing::debug!(status = %ps.status, reason = %ps.reason, "innertube playability");
    }
    Ok(pr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_video_id_all_formats() {
        assert_eq!(extract_video_id("https://www.youtube.com/watch?v=dQw4w9WgXcQ"), Some("dQw4w9WgXcQ"));
        assert_eq!(extract_video_id("https://youtu.be/dQw4w9WgXcQ"), Some("dQw4w9WgXcQ"));
        assert_eq!(extract_video_id("https://www.youtube.com/embed/dQw4w9WgXcQ"), Some("dQw4w9WgXcQ"));
        assert_eq!(extract_video_id("https://www.youtube.com/shorts/dQw4w9WgXcQ"), Some("dQw4w9WgXcQ"));
        assert_eq!(extract_video_id("https://www.youtube.com/"), None);
        assert_eq!(extract_video_id("https://example.com"), None);
    }

    #[test]
    fn build_body_mweb_no_pot() {
        let cfg = MediaConfig::default();
        let body = build_mweb_body("testid12345", &cfg, None);
        assert!(body.contains("MWEB"));
        assert!(body.contains("testid12345"));
        assert!(!body.contains("poToken"));
        assert!(!body.contains("visitorData"));
    }

    #[test]
    fn build_body_mweb_with_pot() {
        let cfg = MediaConfig::default();
        let pot = PotData {
            po_token: "tok_abc123".into(),
            visitor_data: "visitor_xyz".into(),
        };
        let body = build_mweb_body("testid12345", &cfg, Some(&pot));
        assert!(body.contains("MWEB"));
        assert!(body.contains("testid12345"));
        assert!(body.contains("tok_abc123"));
        assert!(body.contains("poToken"));
        assert!(body.contains("visitor_xyz"));
        assert!(body.contains("visitorData"));
    }

    #[test]
    fn usable_streams_with_direct_urls() {
        let json = r#"{"videoDetails":{"title":"T","author":"A","shortDescription":"","lengthSeconds":"60","viewCount":"1"},"streamingData":{"formats":[{"itag":18,"url":"https://cdn/v.mp4","mimeType":"video/mp4","width":640,"height":360,"bitrate":500000}]}}"#;
        let pr: PlayerResponse = serde_json::from_str(json).unwrap();
        assert!(has_usable_streams(&pr));
    }

    #[test]
    fn no_usable_streams_signature_cipher_only() {
        let json = r#"{"videoDetails":{"title":"T","author":"A","shortDescription":"","lengthSeconds":"60","viewCount":"1"},"streamingData":{"formats":[{"itag":18,"signatureCipher":"s=xxx&url=https://cdn/v.mp4","mimeType":"video/mp4","width":640,"height":360,"bitrate":500000}]}}"#;
        let pr: PlayerResponse = serde_json::from_str(json).unwrap();
        assert!(!has_usable_streams(&pr));
    }

    #[test]
    fn unplayable_status_returns_false() {
        let json = r#"{"videoDetails":{"title":"T","author":"","shortDescription":"","lengthSeconds":"0","viewCount":"0"},"streamingData":{"formats":[{"itag":18,"url":"https://cdn/v.mp4","mimeType":"video/mp4","width":640,"height":360,"bitrate":500000}]},"playabilityStatus":{"status":"UNPLAYABLE","reason":"blocked"}}"#;
        let pr: PlayerResponse = serde_json::from_str(json).unwrap();
        assert!(!has_usable_streams(&pr));
    }
}
