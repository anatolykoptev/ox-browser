use crate::MediaError;
use crate::youtube::{PlayerFormat, PlayerResponse};

const INNERTUBE_URL: &str = "https://www.youtube.com/youtubei/v1/player";

/// Innertube API client variants for fallback chain.
#[derive(Debug, Clone, Copy)]
pub enum InnertubeClient {
    TvEmbedded,
    MWeb,
}

/// Ordered fallback chain of clients to try.
pub const FALLBACK_CHAIN: &[InnertubeClient] = &[
    InnertubeClient::TvEmbedded,
    InnertubeClient::MWeb,
];

/// Extract 11-char video ID from any YouTube URL format.
pub fn extract_video_id(url: &str) -> Option<&str> {
    // youtu.be/ID
    if let Some(rest) = url
        .strip_prefix("https://youtu.be/")
        .or_else(|| url.strip_prefix("http://youtu.be/"))
    {
        return take_video_id(rest);
    }

    // Find the path portion after the host
    let path_start = url.find("youtube.com")?;
    let after_host = &url[path_start + "youtube.com".len()..];

    // /watch?v=ID or /watch#...?v=ID
    if after_host.starts_with("/watch") {
        return extract_param(url, "v");
    }

    // /embed/ID, /shorts/ID, /v/ID
    for prefix in &["/embed/", "/shorts/", "/v/"] {
        if let Some(rest) = after_host.strip_prefix(prefix) {
            return take_video_id(rest);
        }
    }

    None
}

/// Take up to 11 alphanumeric/dash/underscore chars as video ID.
fn take_video_id(s: &str) -> Option<&str> {
    let end = s
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        .unwrap_or(s.len())
        .min(11);
    let id = &s[..end];
    if id.len() == 11 { Some(id) } else { None }
}

/// Extract a query parameter value from a URL.
fn extract_param<'a>(url: &'a str, key: &str) -> Option<&'a str> {
    let query_start = url.find('?')?;
    let query = &url[query_start + 1..];
    for pair in query.split('&') {
        if let Some(val) = pair.strip_prefix(key).and_then(|r| r.strip_prefix('='))
        {
            return take_video_id(val);
        }
    }
    None
}

/// Build JSON request body for the Innertube API.
pub fn build_request_body(video_id: &str, client: InnertubeClient) -> String {
    match client {
        InnertubeClient::TvEmbedded => format!(
            r#"{{"videoId":"{video_id}","context":{{"client":{{"clientName":"TVHTML5_SIMPLY_EMBEDDED_PLAYER","clientVersion":"2.0","clientScreen":"EMBED"}}}}}}"#
        ),
        InnertubeClient::MWeb => format!(
            r#"{{"videoId":"{video_id}","context":{{"client":{{"clientName":"MWEB","clientVersion":"2.20240304.08.00"}}}}}}"#
        ),
    }
}

/// Check whether a `PlayerResponse` has usable streams with direct URLs.
pub fn has_usable_streams(pr: &PlayerResponse) -> bool {
    let Some(sd) = &pr.streaming_data else {
        return false;
    };
    let has_direct = |f: &PlayerFormat| f.url.is_some() && f.signature_cipher.is_none();
    sd.formats.iter().any(has_direct) || sd.adaptive_formats.iter().any(has_direct)
}

/// Try each Innertube client in the fallback chain and return the first
/// `PlayerResponse` with usable (directly downloadable) streams.
pub async fn fetch_player_response(
    http_client: &ox_http::HttpClient,
    video_id: &str,
) -> Result<PlayerResponse, MediaError> {
    for &client in FALLBACK_CHAIN {
        let body = build_request_body(video_id, client);
        let resp = http_client
            .post(INNERTUBE_URL, &body, "application/json")
            .await
            .map_err(|e| MediaError::FetchFailed(e.to_string()))?;

        if resp.status != 200 {
            tracing::debug!(
                ?client,
                status = resp.status,
                "innertube client returned non-200"
            );
            continue;
        }

        match serde_json::from_str::<PlayerResponse>(&resp.body) {
            Ok(pr) if has_usable_streams(&pr) => return Ok(pr),
            Ok(_) => {
                tracing::debug!(?client, "no usable streams");
            }
            Err(e) => {
                tracing::debug!(?client, %e, "failed to parse player response");
            }
        }
    }

    Err(MediaError::NoVideoFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_video_id_watch() {
        let url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ";
        assert_eq!(extract_video_id(url), Some("dQw4w9WgXcQ"));
    }

    #[test]
    fn extract_video_id_short_url() {
        let url = "https://youtu.be/dQw4w9WgXcQ";
        assert_eq!(extract_video_id(url), Some("dQw4w9WgXcQ"));
    }

    #[test]
    fn extract_video_id_embed() {
        let url = "https://www.youtube.com/embed/dQw4w9WgXcQ";
        assert_eq!(extract_video_id(url), Some("dQw4w9WgXcQ"));
    }

    #[test]
    fn extract_video_id_shorts() {
        let url = "https://www.youtube.com/shorts/dQw4w9WgXcQ";
        assert_eq!(extract_video_id(url), Some("dQw4w9WgXcQ"));
    }

    #[test]
    fn extract_video_id_none() {
        assert_eq!(extract_video_id("https://www.youtube.com/"), None);
        assert_eq!(extract_video_id("https://example.com"), None);
    }

    #[test]
    fn build_body_tv_embedded() {
        let body = build_request_body("testid12345", InnertubeClient::TvEmbedded);
        assert!(body.contains("TVHTML5_SIMPLY_EMBEDDED_PLAYER"));
        assert!(body.contains("testid12345"));
    }

    #[test]
    fn build_body_mweb() {
        let body = build_request_body("testid12345", InnertubeClient::MWeb);
        assert!(body.contains("MWEB"));
        assert!(body.contains("testid12345"));
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
}
