//! YouTube Innertube API client — direct player requests via ANDROID_VR.

use crate::youtube::{PlayerFormat, PlayerResponse};
use crate::{MediaConfig, MediaError};

/// Android VR User-Agent (Oculus).
const ANDROID_VR_UA: &str = "com.google.android.apps.youtube.vr.oculus/1.60.19 \
    (Linux; U; Android 12L; eureka-user Build/SQ3A.220605.009.A1) gzip";

/// Build JSON request body for the Innertube ANDROID_VR client.
/// This client returns direct URLs without signature cipher,
/// doesn't require PO Tokens, and works from datacenter IPs via proxy.
pub fn build_android_vr_body(video_id: &str, config: &MediaConfig) -> String {
    format!(
        r#"{{"videoId":"{video_id}","context":{{"client":{{"clientName":"ANDROID_VR","clientVersion":"{}","androidSdkVersion":32}}}}}}"#,
        config.android_vr_version,
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

/// Fetch player response from YouTube Innertube API using ANDROID_VR client.
///
/// ANDROID_VR doesn't require PO Tokens and returns direct stream URLs.
/// Uses wreq with proxy support since datacenter IPs are blocked by YouTube.
/// `proxy_url` overrides config proxy (used for sticky sessions).
pub async fn fetch_player_response(
    video_id: &str,
    config: &MediaConfig,
    proxy_url: &str,
) -> Result<PlayerResponse, MediaError> {
    let body = build_android_vr_body(video_id, config);
    let mut builder = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(20));

    if !proxy_url.is_empty() {
        let proxy = wreq::Proxy::all(proxy_url)
            .map_err(|e| MediaError::FetchFailed(format!("proxy: {e}")))?;
        builder = builder.proxy(proxy);
    }

    let client = builder
        .build()
        .map_err(|e| MediaError::FetchFailed(format!("innertube client: {e}")))?;

    let resp = client
        .post(&config.innertube_url)
        .header("Content-Type", "application/json")
        .header("User-Agent", ANDROID_VR_UA)
        .body(body)
        .send()
        .await
        .map_err(|e| MediaError::FetchFailed(format!("innertube: {e}")))?;

    if !resp.status().is_success() {
        return Err(MediaError::FetchFailed(format!(
            "innertube HTTP {}",
            resp.status()
        )));
    }

    let text = resp
        .text()
        .await
        .map_err(|e| MediaError::FetchFailed(format!("innertube read: {e}")))?;

    let pr = serde_json::from_str::<PlayerResponse>(&text)
        .map_err(|e| MediaError::FetchFailed(format!("innertube parse: {e}")))?;

    if let Some(ref ps) = pr.playability_status {
        tracing::debug!(status = %ps.status, reason = %ps.reason, "innertube playability");
        if ps.status == "LOGIN_REQUIRED" {
            return Err(MediaError::FetchFailed(format!(
                "YouTube bot detection: {}", ps.reason
            )));
        }
    }

    if has_usable_streams(&pr) {
        tracing::info!(video_id, "ANDROID_VR success");
        return Ok(pr);
    }

    Err(MediaError::NoVideoFound)
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
    fn build_body_android_vr() {
        let cfg = MediaConfig::default();
        let body = build_android_vr_body("testid12345", &cfg);
        assert!(body.contains("ANDROID_VR"));
        assert!(body.contains("testid12345"));
        assert!(body.contains("androidSdkVersion"));
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
