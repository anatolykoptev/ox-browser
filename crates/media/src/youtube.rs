use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

static PLAYER_RESPONSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"ytInitialPlayerResponse\s*=\s*\{").unwrap()
});

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayerResponse {
    pub video_details: VideoDetails,
    pub streaming_data: Option<StreamingData>,
    pub playability_status: Option<PlayabilityStatus>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayabilityStatus {
    pub status: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoDetails {
    pub title: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub short_description: String,
    #[serde(default)]
    pub length_seconds: String,
    #[serde(default)]
    pub view_count: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamingData {
    #[serde(default)]
    pub formats: Vec<PlayerFormat>,
    #[serde(default)]
    pub adaptive_formats: Vec<PlayerFormat>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayerFormat {
    pub itag: u32,
    pub url: Option<String>,
    pub signature_cipher: Option<String>,
    pub mime_type: String,
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
    #[serde(default)]
    pub bitrate: u64,
}

#[derive(Debug)]
pub struct YouTubeVideoInfo {
    pub title: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub duration_secs: Option<u64>,
    pub views: i64,
    pub video_url: Option<String>,
    pub audio_url: Option<String>,
    pub width: u32,
    pub height: u32,
}

/// Extract balanced JSON object starting at `start` in `s`.
fn extract_balanced_braces(s: &str, start: usize) -> Option<&str> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for i in start..bytes.len() {
        let ch = bytes[i];
        if escape {
            escape = false;
            continue;
        }
        if ch == b'\\' && in_string {
            escape = true;
            continue;
        }
        if ch == b'"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match ch {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

pub fn find_player_response(html: &str) -> Option<PlayerResponse> {
    let m = PLAYER_RESPONSE_RE.find(html)?;
    let json_start = m.start() + m.as_str().find('{').unwrap_or(0);
    let json_str = extract_balanced_braces(html, json_start)?;
    serde_json::from_str(json_str).ok()
}

fn has_direct_url(f: &PlayerFormat) -> bool {
    f.url.is_some() && f.signature_cipher.is_none()
}

fn is_video(f: &PlayerFormat) -> bool {
    f.mime_type.starts_with("video/")
}

fn is_audio(f: &PlayerFormat) -> bool {
    f.mime_type.starts_with("audio/")
}

pub fn build_video_info(pr: &PlayerResponse, max_height: u32) -> YouTubeVideoInfo {
    let vd = &pr.video_details;
    let duration = vd.length_seconds.parse::<u64>().ok();
    let views = vd.view_count.parse::<i64>().unwrap_or(0);
    let desc = if vd.short_description.is_empty() { None } else { Some(vd.short_description.clone()) };

    let mut video_url = None;
    let mut audio_url = None;
    let mut width = 0u32;
    let mut height = 0u32;

    if let Some(sd) = &pr.streaming_data {
        // Try combined formats first (video+audio in one stream)
        let best_combined = sd.formats.iter()
            .filter(|f| has_direct_url(f) && is_video(f) && f.height <= max_height)
            .max_by_key(|f| (f.height, f.bitrate));

        if let Some(f) = best_combined {
            video_url = f.url.clone();
            width = f.width;
            height = f.height;
        } else {
            // Fallback to adaptive (DASH) formats
            let best_video = sd.adaptive_formats.iter()
                .filter(|f| has_direct_url(f) && is_video(f) && f.height <= max_height)
                .max_by_key(|f| (f.height, f.bitrate));
            let best_audio = sd.adaptive_formats.iter()
                .filter(|f| has_direct_url(f) && is_audio(f))
                .max_by_key(|f| f.bitrate);

            if let Some(v) = best_video {
                video_url = v.url.clone();
                width = v.width;
                height = v.height;
            }
            if let Some(a) = best_audio {
                audio_url = a.url.clone();
            }
        }
    }

    YouTubeVideoInfo {
        title: Some(vd.title.clone()),
        author: if vd.author.is_empty() { None } else { Some(vd.author.clone()) },
        description: desc,
        duration_secs: duration,
        views,
        video_url,
        audio_url,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_player_response_combined() {
        let json = r#"{"videoDetails":{"title":"Test","author":"Author","shortDescription":"desc","lengthSeconds":"120","viewCount":"1000"},"streamingData":{"formats":[{"itag":18,"url":"https://cdn/video.mp4","mimeType":"video/mp4; codecs=\"avc1\"","width":640,"height":360,"bitrate":500000}]}}"#;
        let pr: PlayerResponse = serde_json::from_str(json).unwrap();
        let info = build_video_info(&pr, 1080);
        assert_eq!(info.title.as_deref(), Some("Test"));
        assert_eq!(info.author.as_deref(), Some("Author"));
        assert_eq!(info.duration_secs, Some(120));
        assert!(info.video_url.is_some());
        assert!(info.audio_url.is_none());
    }

    #[test]
    fn parse_player_response_dash_only() {
        let json = r#"{"videoDetails":{"title":"T","author":"A","shortDescription":"","lengthSeconds":"60","viewCount":"500"},"streamingData":{"formats":[],"adaptiveFormats":[{"itag":137,"url":"https://cdn/v.mp4","mimeType":"video/mp4; codecs=\"avc1\"","width":1920,"height":1080,"bitrate":4000000},{"itag":140,"url":"https://cdn/a.m4a","mimeType":"audio/mp4; codecs=\"mp4a\"","bitrate":128000}]}}"#;
        let pr: PlayerResponse = serde_json::from_str(json).unwrap();
        let info = build_video_info(&pr, 1080);
        assert!(info.video_url.is_some());
        assert!(info.audio_url.is_some());
        assert_eq!(info.width, 1920);
        assert_eq!(info.height, 1080);
    }

    #[test]
    fn skip_signature_cipher_urls() {
        let json = r#"{"videoDetails":{"title":"T","author":"A","shortDescription":"","lengthSeconds":"30","viewCount":"100"},"streamingData":{"formats":[{"itag":18,"signatureCipher":"s=xxx&url=https://cdn/video.mp4","mimeType":"video/mp4","width":640,"height":360,"bitrate":500000}]}}"#;
        let pr: PlayerResponse = serde_json::from_str(json).unwrap();
        let info = build_video_info(&pr, 1080);
        assert!(info.video_url.is_none());
    }

    #[test]
    fn extract_player_response_from_html() {
        let html = r#"<html><script>var ytInitialPlayerResponse = {"videoDetails":{"title":"Found","author":"Me","shortDescription":"","lengthSeconds":"10","viewCount":"1"},"streamingData":{"formats":[{"itag":18,"url":"https://cdn/v.mp4","mimeType":"video/mp4","width":640,"height":360,"bitrate":500000}]}};</script></html>"#;
        let pr = find_player_response(html);
        assert!(pr.is_some());
        assert_eq!(pr.unwrap().video_details.title, "Found");
    }

    #[test]
    fn max_height_filter() {
        let json = r#"{"videoDetails":{"title":"T","author":"A","shortDescription":"","lengthSeconds":"60","viewCount":"100"},"streamingData":{"formats":[{"itag":22,"url":"https://cdn/hd.mp4","mimeType":"video/mp4; codecs=\"avc1\"","width":1280,"height":720,"bitrate":2000000},{"itag":18,"url":"https://cdn/sd.mp4","mimeType":"video/mp4; codecs=\"avc1\"","width":640,"height":360,"bitrate":500000}]}}"#;
        let pr: PlayerResponse = serde_json::from_str(json).unwrap();
        let info = build_video_info(&pr, 480);
        assert_eq!(info.height, 360);
        assert!(info.video_url.unwrap().contains("sd.mp4"));
    }
}
