# YouTube Innertube API Bypass — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace HTML scraping with direct Innertube API calls so YouTube videos download from datacenter IPs.

**Architecture:** Current approach fetches YouTube HTML and parses `ytInitialPlayerResponse` — this fails from servers because YouTube returns `signatureCipher`-only responses to bots. New approach calls YouTube's Innertube `/youtubei/v1/player` API directly with the `TVHTML5_SIMPLY_EMBEDDED_PLAYER` client, which returns direct `url` fields without cipher. Fallback chain: `tv_embedded` → `mweb+POT` → error. The orchestrator changes from "fetch HTML → parse" to "extract video ID → call Innertube API".

**Tech Stack:** Rust, wreq, serde, ox-http (for proxy/TLS fingerprint), tokio

---

### Task 1: Add `innertube` module with client definitions and request/response types

**Files:**
- Create: `crates/media/src/innertube.rs`
- Modify: `crates/media/src/lib.rs:1-9` (add `pub mod innertube;`)

**Context:** The Innertube API is YouTube's internal API. `POST https://www.youtube.com/youtubei/v1/player` with a JSON body containing `videoId` and `context.client` returns the same `PlayerResponse` structure we already parse. The `TVHTML5_SIMPLY_EMBEDDED_PLAYER` client is a smart TV embedded player that doesn't require PO Tokens or signature decryption from datacenter IPs.

**Step 1: Write the failing test**

In `crates/media/src/innertube.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_video_id_standard() {
        assert_eq!(extract_video_id("https://www.youtube.com/watch?v=dQw4w9WgXcQ"), Some("dQw4w9WgXcQ"));
    }

    #[test]
    fn extract_video_id_short() {
        assert_eq!(extract_video_id("https://youtu.be/dQw4w9WgXcQ"), Some("dQw4w9WgXcQ"));
    }

    #[test]
    fn extract_video_id_embed() {
        assert_eq!(extract_video_id("https://www.youtube.com/embed/dQw4w9WgXcQ"), Some("dQw4w9WgXcQ"));
    }

    #[test]
    fn extract_video_id_shorts() {
        assert_eq!(extract_video_id("https://www.youtube.com/shorts/dQw4w9WgXcQ"), Some("dQw4w9WgXcQ"));
    }

    #[test]
    fn extract_video_id_none() {
        assert_eq!(extract_video_id("https://www.youtube.com/"), None);
    }

    #[test]
    fn build_innertube_body_tv_embedded() {
        let body = build_request_body("dQw4w9WgXcQ", InnertubeClient::TvEmbedded);
        assert!(body.contains("TVHTML5_SIMPLY_EMBEDDED_PLAYER"));
        assert!(body.contains("dQw4w9WgXcQ"));
    }

    #[test]
    fn build_innertube_body_mweb() {
        let body = build_request_body("abc123", InnertubeClient::MWeb);
        assert!(body.contains("MWEB"));
        assert!(body.contains("abc123"));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd . && cargo test -p ox-media innertube 2>&1 | tail -5`
Expected: compile error — module not found

**Step 3: Implement the module**

Create `crates/media/src/innertube.rs` (~100 lines):

```rust
//! YouTube Innertube API client — direct player requests bypassing HTML scraping.

use regex::Regex;
use std::sync::LazyLock;

use crate::youtube::PlayerResponse;
use crate::MediaError;

const INNERTUBE_URL: &str = "https://www.youtube.com/youtubei/v1/player";

static VIDEO_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:v=|youtu\.be/|/embed/|/shorts/|/v/)([a-zA-Z0-9_-]{11})").unwrap()
});

/// Innertube client identities for the fallback chain.
#[derive(Debug, Clone, Copy)]
pub enum InnertubeClient {
    /// Smart TV embedded player — returns direct URLs without signatureCipher.
    TvEmbedded,
    /// Mobile web client — may need PO Token for some videos.
    MWeb,
}

/// Extract 11-char video ID from any YouTube URL format.
pub fn extract_video_id(url: &str) -> Option<&str> {
    VIDEO_ID_RE.captures(url).map(|c| c.get(1).unwrap().as_str())
}

/// Build JSON request body for Innertube `/player` endpoint.
pub fn build_request_body(video_id: &str, client: InnertubeClient) -> String {
    let (client_name, client_version, client_screen) = match client {
        InnertubeClient::TvEmbedded => ("TVHTML5_SIMPLY_EMBEDDED_PLAYER", "2.0", Some("EMBED")),
        InnertubeClient::MWeb => ("MWEB", "2.20240304.08.00", None),
    };

    let screen_field = client_screen
        .map(|s| format!(r#","clientScreen":"{s}""#))
        .unwrap_or_default();

    format!(
        r#"{{"videoId":"{video_id}","context":{{"client":{{"clientName":"{client_name}","clientVersion":"{client_version}"{screen_field}}}}}}}"#
    )
}

/// Client order for the fallback chain.
pub const FALLBACK_CHAIN: &[InnertubeClient] = &[
    InnertubeClient::TvEmbedded,
    InnertubeClient::MWeb,
];

/// Call Innertube player API, trying each client in the fallback chain.
/// Returns the first PlayerResponse that has usable streaming URLs.
pub async fn fetch_player_response(
    http_client: &ox_http::HttpClient,
    video_id: &str,
) -> Result<PlayerResponse, MediaError> {
    let mut last_err = MediaError::NoVideoFound;

    for &client in FALLBACK_CHAIN {
        let body = build_request_body(video_id, client);
        tracing::debug!(?client, video_id, "trying Innertube client");

        match try_innertube_request(http_client, &body).await {
            Ok(pr) => {
                // Check if we got usable streaming data
                if has_usable_streams(&pr) {
                    tracing::info!(?client, video_id, "Innertube success");
                    return Ok(pr);
                }
                tracing::debug!(?client, "no usable streams, trying next client");
                last_err = MediaError::NoVideoFound;
            }
            Err(e) => {
                tracing::debug!(?client, error = %e, "Innertube request failed");
                last_err = e;
            }
        }
    }

    Err(last_err)
}

async fn try_innertube_request(
    http_client: &ox_http::HttpClient,
    body: &str,
) -> Result<PlayerResponse, MediaError> {
    let resp = http_client
        .post(INNERTUBE_URL, body, "application/json")
        .await
        .map_err(|e| MediaError::FetchFailed(format!("innertube: {e}")))?;

    if resp.status >= 400 {
        return Err(MediaError::FetchFailed(format!("innertube HTTP {}", resp.status)));
    }

    serde_json::from_str::<PlayerResponse>(&resp.body)
        .map_err(|e| MediaError::FetchFailed(format!("innertube parse: {e}")))
}

fn has_usable_streams(pr: &PlayerResponse) -> bool {
    if let Some(ref sd) = pr.streaming_data {
        let direct_url = |f: &crate::youtube::PlayerFormat| f.url.is_some() && f.signature_cipher.is_none();
        sd.formats.iter().any(direct_url) || sd.adaptive_formats.iter().any(direct_url)
    } else {
        false
    }
}
```

Add `pub mod innertube;` to `crates/media/src/lib.rs` after `pub mod extract;`.

**Step 4: Run tests**

Run: `cd . && cargo test -p ox-media innertube`
Expected: 7 tests pass

**Step 5: Commit**

```bash
git add crates/media/src/innertube.rs crates/media/src/lib.rs
git commit -m "feat(media): add Innertube API module with tv_embedded + mweb fallback chain"
```

---

### Task 2: Update orchestrator to use Innertube API instead of HTML scraping

**Files:**
- Modify: `crates/media/src/orchestrator.rs:17-85`

**Context:** The `download_youtube` function currently receives HTML from a GET request and calls `find_player_response(html)`. Replace this with: extract video ID → call `fetch_player_response` via Innertube API. The orchestrator's `download()` function should skip the HTML GET for YouTube entirely and go straight to Innertube.

**Step 1: Update `download()` to branch YouTube before HTML fetch**

In `orchestrator.rs`, modify `download()`:

```rust
pub async fn download(
    http_client: &ox_http::HttpClient,
    req: &MediaRequest,
) -> Result<MediaResult, MediaError> {
    let platform = detect_platform(&req.url);
    let max_bytes = (req.max_size_mb.unwrap_or(DEFAULT_MAX_SIZE_MB) * 1_048_576.0) as u64;
    info!(url = %req.url, ?platform, "starting media download");

    match platform {
        Platform::YouTube => download_youtube(http_client, &req.url, req, max_bytes).await,
        Platform::Generic => {
            let resp = http_client
                .get(&req.url)
                .await
                .map_err(|e| MediaError::FetchFailed(e.to_string()))?;
            if resp.status >= 400 {
                return Err(MediaError::FetchFailed(format!("HTTP {}", resp.status)));
            }
            download_generic(&resp.body, &resp.url, req, max_bytes).await
        }
    }
}
```

**Step 2: Rewrite `download_youtube` to use Innertube**

```rust
async fn download_youtube(
    http_client: &ox_http::HttpClient,
    url: &str,
    req: &MediaRequest,
    max_bytes: u64,
) -> Result<MediaResult, MediaError> {
    let video_id = innertube::extract_video_id(url)
        .ok_or_else(|| MediaError::FetchFailed("no video ID in URL".into()))?;

    let pr = innertube::fetch_player_response(http_client, video_id).await?;
    let info = build_video_info(&pr, req.max_height.unwrap_or(DEFAULT_MAX_HEIGHT));
    let video_url = info.video_url.as_deref().ok_or(MediaError::NoVideoFound)?;
    debug!(video_url, audio = info.audio_url.is_some(), "YouTube streams found");

    // ... rest unchanged (download + merge logic stays the same)
```

Update imports: add `use crate::innertube;` at top, remove `find_player_response` from `use crate::youtube::`.

**Step 3: Run tests**

Run: `cd . && cargo test -p ox-media`
Expected: all existing tests pass (unit tests don't hit network)

**Step 4: Commit**

```bash
git add crates/media/src/orchestrator.rs
git commit -m "feat(media): switch YouTube from HTML scraping to Innertube API"
```

---

### Task 3: Add `playability_status` handling for age-restricted and unplayable videos

**Files:**
- Modify: `crates/media/src/youtube.rs` (add PlayabilityStatus struct)
- Modify: `crates/media/src/innertube.rs` (check playability before returning)

**Context:** Innertube API returns `playabilityStatus` with `status` field. Values: `OK`, `UNPLAYABLE`, `LOGIN_REQUIRED`, `ERROR`. We need to parse this to give useful errors and decide whether to try next client.

**Step 1: Add PlayabilityStatus to PlayerResponse**

In `youtube.rs`, add to `PlayerResponse`:

```rust
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
```

**Step 2: Use playability in innertube.rs**

In `has_usable_streams`, also check playability:

```rust
fn has_usable_streams(pr: &PlayerResponse) -> bool {
    // Check playability first
    if let Some(ref ps) = pr.playability_status {
        if ps.status != "OK" {
            return false;
        }
    }
    // Then check for direct URLs
    if let Some(ref sd) = pr.streaming_data {
        let direct_url = |f: &crate::youtube::PlayerFormat| f.url.is_some() && f.signature_cipher.is_none();
        sd.formats.iter().any(direct_url) || sd.adaptive_formats.iter().any(direct_url)
    } else {
        false
    }
}
```

Add a test:

```rust
#[test]
fn playability_status_unplayable_returns_false() {
    let json = r#"{"videoDetails":{"title":"T","author":"","shortDescription":"","lengthSeconds":"0","viewCount":"0"},"streamingData":{"formats":[{"itag":18,"url":"https://cdn/v.mp4","mimeType":"video/mp4","width":640,"height":360,"bitrate":500000}]},"playabilityStatus":{"status":"UNPLAYABLE","reason":"blocked"}}"#;
    let pr: crate::youtube::PlayerResponse = serde_json::from_str(json).unwrap();
    assert!(!has_usable_streams(&pr));
}
```

**Step 3: Run tests**

Run: `cd . && cargo test -p ox-media`
Expected: all pass

**Step 4: Commit**

```bash
git add crates/media/src/youtube.rs crates/media/src/innertube.rs
git commit -m "feat(media): add playability status handling for YouTube"
```

---

### Task 4: Integration test with real YouTube URL

**Files:**
- Create: `crates/media/tests/youtube_integration.rs`

**Context:** Need an integration test that actually calls the Innertube API to verify the full flow works. Mark it `#[ignore]` so it only runs manually.

**Step 1: Write the integration test**

```rust
//! Integration test — calls real YouTube Innertube API.
//! Run with: cargo test -p ox-media --test youtube_integration -- --ignored

use ox_media::innertube::{extract_video_id, fetch_player_response};
use ox_media::youtube::build_video_info;

#[tokio::test]
#[ignore = "requires network"]
async fn innertube_returns_playable_video() {
    // "Me at the zoo" — first YouTube video, always available
    let url = "https://www.youtube.com/watch?v=jNQXAC9IVRw";
    let video_id = extract_video_id(url).expect("valid video ID");

    let config = ox_http::HttpConfig::default();
    let client = ox_http::HttpClient::new(config).expect("http client");

    let pr = fetch_player_response(&client, video_id)
        .await
        .expect("innertube should return player response");

    let info = build_video_info(&pr, 720);
    assert!(info.video_url.is_some(), "should have video URL");
    assert!(info.title.is_some(), "should have title");
    assert!(info.duration_secs.is_some(), "should have duration");
    println!("title: {:?}", info.title);
    println!("video_url: {:?}", info.video_url.as_deref().map(|u| &u[..80.min(u.len())]));
    println!("resolution: {}x{}", info.width, info.height);
}
```

**Step 2: Run the integration test**

Run: `cd . && cargo test -p ox-media --test youtube_integration -- --ignored --nocapture 2>&1 | tail -20`
Expected: PASS with printed title, URL, resolution

**Step 3: Commit**

```bash
git add crates/media/tests/youtube_integration.rs
git commit -m "test(media): add YouTube Innertube integration test"
```

---

### Task 5: Deploy and test via `/media/download` endpoint

**Files:** None (deploy + manual test)

**Step 1: Build and deploy ox-browser**

```bash
cd <deploy> && docker compose build --no-cache ox-browser && docker compose up -d --no-deps --force-recreate ox-browser
```

**Step 2: Test YouTube download**

```bash
curl -s -X POST http://127.0.0.1:8901/media/download \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.youtube.com/watch?v=jNQXAC9IVRw","media_type":"video"}' | jq .
```

Expected: JSON response with `files[0].path` pointing to downloaded mp4, `title` = "Me at the zoo", `platform` = "youtube".

**Step 3: Verify file exists**

```bash
ls -la $(curl -s -X POST http://127.0.0.1:8901/media/download \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.youtube.com/watch?v=jNQXAC9IVRw","media_type":"video"}' | jq -r '.files[0].path')
```

Expected: file exists, size > 0

**Step 4: Test from go-media (via vaelor or direct Go test)**

Ensure the go-media `oxBackend` works with the updated endpoint.
