# Media Download Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Unified `POST /media/download` endpoint that downloads video/images from any URL, replacing `/images/extract` and adding video support with YouTube-specific logic.

**Architecture:** New `crates/media/` crate with platform detection, generic HTML extraction (video + image), YouTube playerResponse parser, streaming download via wreq, DASH merge via ffmpeg. REST + MCP endpoints.

**Tech Stack:** Rust, axum, dom_query, regex, wreq (TLS fingerprint), tokio, serde, ffmpeg (subprocess)

---

### Task 1: Create `crates/media/` crate skeleton

**Files:**
- Create: `crates/media/Cargo.toml`
- Create: `crates/media/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

**Step 1: Create crate directory**

Run: `mkdir -p crates/media/src`

**Step 2: Create Cargo.toml**

```toml
[package]
name = "ox-media"
version = "0.1.0"
edition = "2024"

[dependencies]
ox-http = { path = "../http" }
dom_query = "0.11"
url = "2"
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { workspace = true }
tracing = { workspace = true }
thiserror = { workspace = true }
sha2 = "0.10"
hex = "0.4"
```

**Step 3: Create lib.rs with public types**

```rust
//! Universal media download: video + image extraction and download.

pub mod detect;
pub mod extract;

use serde::{Deserialize, Serialize};

/// Request parameters for media download.
#[derive(Debug, Deserialize)]
pub struct MediaRequest {
    pub url: String,
    #[serde(default = "default_media_type")]
    pub media_type: MediaType,
    #[serde(default = "default_max_height")]
    pub max_height: u32,
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u32,
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    #[serde(default)]
    pub proxy: bool,
    /// Minimum image width (only for image extraction).
    pub min_width: Option<u32>,
}

fn default_media_type() -> MediaType { MediaType::Auto }
fn default_max_height() -> u32 { 1080 }
fn default_max_size_mb() -> u32 { 50 }
fn default_max_results() -> usize { 1 }

#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MediaType {
    #[default]
    Auto,
    Video,
    Image,
}

/// A downloaded media file.
#[derive(Debug, Serialize)]
pub struct MediaFile {
    pub path: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub width: u32,
    #[serde(skip_serializing_if = "is_zero")]
    pub height: u32,
}

fn is_zero(v: &u32) -> bool { *v == 0 }

/// Stats for video content.
#[derive(Debug, Default, Serialize)]
pub struct MediaStats {
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub views: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub likes: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub comments: i64,
}

fn is_zero_i64(v: &i64) -> bool { *v == 0 }

/// Successful download result.
#[derive(Debug, Serialize)]
pub struct MediaResult {
    pub media_type: MediaType,
    pub files: Vec<MediaFile>,
    pub platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<MediaStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<Quality>,
    #[serde(default)]
    pub merged: bool,
}

#[derive(Debug, Serialize)]
pub struct Quality {
    pub width: u32,
    pub height: u32,
}

/// Error types for structured error responses.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "error", content = "message")]
pub enum MediaError {
    #[error("no video found: {0}")]
    NoVideoFound(String),
    #[error("no image found: {0}")]
    NoImageFound(String),
    #[error("download failed: {0}")]
    DownloadFailed(String),
    #[error("size exceeded: {0}")]
    SizeExceeded(String),
    #[error("merge failed: {0}")]
    MergeFailed(String),
    #[error("fetch failed: {0}")]
    FetchFailed(String),
}
```

**Step 4: Add to workspace**

In root `Cargo.toml`, add `"crates/media"` to `members` list.

**Step 5: Verify it compiles**

Run: `cargo check -p ox-media`
Expected: compiles with no errors

**Step 6: Commit**

```bash
git add crates/media/ Cargo.toml Cargo.lock
git commit -m "feat(media): scaffold crates/media with types"
```

---

### Task 2: Platform detection (`detect.rs`)

**Files:**
- Create: `crates/media/src/detect.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_youtube_watch() {
        assert_eq!(detect_platform("https://www.youtube.com/watch?v=abc123"), Platform::YouTube);
    }

    #[test]
    fn detect_youtube_short() {
        assert_eq!(detect_platform("https://youtube.com/shorts/abc123"), Platform::YouTube);
    }

    #[test]
    fn detect_youtu_be() {
        assert_eq!(detect_platform("https://youtu.be/abc123"), Platform::YouTube);
    }

    #[test]
    fn detect_generic() {
        assert_eq!(detect_platform("https://example.com/page"), Platform::Generic);
    }
}
```

**Step 2: Implement**

```rust
use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    YouTube,
    Generic,
}

static YOUTUBE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"https?://(?:(?:www\.|m\.|music\.)?youtube\.com/(?:watch\?|shorts/|embed/)|youtu\.be/)"
    ).unwrap()
});

pub fn detect_platform(url: &str) -> Platform {
    if YOUTUBE_RE.is_match(url) {
        return Platform::YouTube;
    }
    Platform::Generic
}
```

**Step 3: Run tests**

Run: `cargo test -p ox-media`
Expected: all pass

**Step 4: Commit**

```bash
git add crates/media/src/detect.rs
git commit -m "feat(media): platform detection (YouTube + generic)"
```

---

### Task 3: Migrate image extraction to `extract.rs`

**Files:**
- Create: `crates/media/src/extract.rs`
- Reference: `crates/imagesearch/src/extract.rs` (copy logic exactly)

**Step 1: Copy and adapt image extraction**

Move ALL logic from `crates/imagesearch/src/extract.rs` into `crates/media/src/extract.rs`. Keep the exact same:
- 4 extraction methods in same order (og:image, img, picture>source, CSS background)
- 21 SKIP_PATTERNS
- 5 SKIP_EXTENSIONS
- MIN_DIMENSION = 200
- `should_skip()`, `resolve_url()`, `parse_dimension()`, `extract_og_title()`, `best_srcset_url()`, `extract_bg_urls()`
- All dedup logic (HashSet by URL)

Change `ImageResult` references to new internal struct `ExtractedMedia`:

```rust
/// A media item extracted from HTML.
#[derive(Debug, Clone)]
pub struct ExtractedMedia {
    pub url: String,
    pub title: String,
    pub width: u32,
    pub height: u32,
    pub media_kind: MediaKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Image,
    Video,
}
```

Add video extraction methods AFTER existing image methods:

**Level 1 — HTML video tags:**
```rust
// 5. <video src> and <video><source src>
for node in doc.select("video").iter() {
    // check src attribute directly
    // also check child <source> elements
}

// 6. og:video meta
for node in doc.select("meta[property='og:video'], meta[property='og:video:secure_url']").iter() {
    // extract content
}

// 7. twitter:player:stream
for node in doc.select("meta[name='twitter:player:stream']").iter() {
    // extract content
}
```

**Level 2 — JSON-LD:**
```rust
// 8. JSON-LD VideoObject
for node in doc.select("script[type='application/ld+json']").iter() {
    // parse JSON, look for @type: VideoObject, contentUrl, embedUrl
}
```

**Level 3 — Inline JS heuristics:**
```rust
// 9. Inline script patterns for video URLs
// regex for .mp4/.m3u8/.webm URLs in JSON-like structures
```

Main function signature:
```rust
pub fn extract_media(html: &str, base_url: &str) -> Vec<ExtractedMedia>
```

Also keep `extract_images()` as a wrapper that filters to `MediaKind::Image` only (backward compat during migration).

**Step 2: Copy all 8 tests from imagesearch/extract.rs**

Add them verbatim, adjusting for new struct name. Then add video extraction tests:

```rust
#[test]
fn extract_video_tag() {
    let html = r#"<html><body><video src="https://example.com/clip.mp4"></video></body></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert!(results.iter().any(|r| r.media_kind == MediaKind::Video && r.url == "https://example.com/clip.mp4"));
}

#[test]
fn extract_og_video() {
    let html = r#"<html><head><meta property="og:video" content="https://example.com/video.mp4"/></head></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert!(results.iter().any(|r| r.media_kind == MediaKind::Video));
}

#[test]
fn extract_json_ld_video() {
    let html = r#"<html><head><script type="application/ld+json">{"@type":"VideoObject","contentUrl":"https://example.com/v.mp4","name":"Test"}</script></head></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert!(results.iter().any(|r| r.media_kind == MediaKind::Video && r.url == "https://example.com/v.mp4"));
}
```

**Step 3: Run tests**

Run: `cargo test -p ox-media`
Expected: all 11+ tests pass

**Step 4: Commit**

```bash
git add crates/media/src/extract.rs
git commit -m "feat(media): generic media extractor (video + image from HTML)"
```

---

### Task 4: YouTube parser (`youtube.rs`)

**Files:**
- Create: `crates/media/src/youtube.rs`
- Reference: `<go-media>/extract/youtube/oxbrowser.go` (port logic)

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_player_response_combined() {
        let json = r#"{"videoDetails":{"title":"Test","author":"Author","shortDescription":"desc","lengthSeconds":"120","viewCount":"1000"},"streamingData":{"formats":[{"itag":18,"url":"https://cdn/video.mp4","mimeType":"video/mp4; codecs=\"avc1\"","width":640,"height":360,"bitrate":500000}]}}"#;
        let pr: PlayerResponse = serde_json::from_str(json).unwrap();
        let info = build_video_info(&pr, "https://youtube.com/watch?v=test");
        assert_eq!(info.title.as_deref(), Some("Test"));
        assert_eq!(info.author.as_deref(), Some("Author"));
        assert_eq!(info.duration_secs, Some(120));
        assert!(info.video_url.is_some());
    }

    #[test]
    fn parse_player_response_dash_only() {
        // adaptiveFormats with separate video + audio
        let json = r#"{"videoDetails":{"title":"T","author":"A","shortDescription":"","lengthSeconds":"60","viewCount":"500"},"streamingData":{"formats":[],"adaptiveFormats":[{"itag":137,"url":"https://cdn/v.mp4","mimeType":"video/mp4; codecs=\"avc1\"","width":1920,"height":1080,"bitrate":4000000},{"itag":140,"url":"https://cdn/a.m4a","mimeType":"audio/mp4; codecs=\"mp4a\"","bitrate":128000}]}}"#;
        let pr: PlayerResponse = serde_json::from_str(json).unwrap();
        let info = build_video_info(&pr, "https://youtube.com/watch?v=test");
        assert!(info.video_url.is_some());
        assert!(info.audio_url.is_some());
    }

    #[test]
    fn skip_signature_cipher_urls() {
        let json = r#"{"videoDetails":{"title":"T","author":"A","shortDescription":"","lengthSeconds":"30","viewCount":"100"},"streamingData":{"formats":[{"itag":18,"signatureCipher":"s=xxx&url=https://cdn/video.mp4","mimeType":"video/mp4","width":640,"height":360,"bitrate":500000}]}}"#;
        let pr: PlayerResponse = serde_json::from_str(json).unwrap();
        let info = build_video_info(&pr, "https://youtube.com/watch?v=test");
        assert!(info.video_url.is_none()); // no direct URL available
    }

    #[test]
    fn extract_player_response_from_html() {
        let html = r#"<html><script>var ytInitialPlayerResponse = {"videoDetails":{"title":"Found","author":"Me","shortDescription":"","lengthSeconds":"10","viewCount":"1"},"streamingData":{"formats":[{"itag":18,"url":"https://cdn/v.mp4","mimeType":"video/mp4","width":640,"height":360,"bitrate":500000}]}};</script></html>"#;
        let pr = find_player_response(html);
        assert!(pr.is_some());
        assert_eq!(pr.unwrap().video_details.title, "Found");
    }
}
```

**Step 2: Implement**

```rust
use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

static PLAYER_RESPONSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"var\s+ytInitialPlayerResponse\s*=\s*(\{.+?\});").unwrap()
});

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayerResponse {
    pub video_details: VideoDetails,
    pub streaming_data: Option<StreamingData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoDetails {
    pub title: String,
    #[serde(default)]
    pub author: String,
    #[serde(default, rename = "shortDescription")]
    pub description: String,
    #[serde(default, rename = "lengthSeconds")]
    pub length_seconds: String,
    #[serde(default, rename = "viewCount")]
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
    pub url: Option<String>,           // direct URL (None if signatureCipher)
    pub signature_cipher: Option<String>,
    pub mime_type: String,
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
    #[serde(default)]
    pub bitrate: u64,
}

/// Extracted video info from YouTube playerResponse.
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

pub fn find_player_response(html: &str) -> Option<PlayerResponse> {
    let caps = PLAYER_RESPONSE_RE.captures(html)?;
    serde_json::from_str(caps.get(1)?.as_str()).ok()
}

pub fn build_video_info(pr: &PlayerResponse, _original_url: &str) -> YouTubeVideoInfo {
    // ... select best format with direct url, prefer combined, fallback to DASH
    // See design doc for logic: skip signatureCipher, pick highest res within max_height
}
```

**Step 3: Run tests**

Run: `cargo test -p ox-media -- youtube`
Expected: all pass

**Step 4: Commit**

```bash
git add crates/media/src/youtube.rs
git commit -m "feat(media): YouTube playerResponse parser"
```

---

### Task 5: Download module (`download.rs`)

**Files:**
- Create: `crates/media/src/download.rs`

**Step 1: Implement streaming download**

```rust
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use tokio::io::AsyncWriteExt;
use ox_http::HttpClient;

const MEDIA_DIR: &str = "/tmp/ox-browser/media";

pub fn media_path(platform: &str, url: &str, ext: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let hash = hex::encode(hasher.finalize());
    let short = &hash[..8];
    PathBuf::from(MEDIA_DIR).join(format!("{platform}_{short}.{ext}"))
}

/// Download URL to file, streaming chunks. Returns file size.
/// Checks Content-Length against max_size before downloading.
pub async fn download_to_file(
    client: &HttpClient,
    url: &str,
    dest: &Path,
    max_size_bytes: u64,
) -> Result<u64, crate::MediaError> {
    // Ensure parent dir exists
    // HEAD or GET with Content-Length check
    // Stream response body to file in chunks
    // Success flag pattern for cleanup
    // Return file size
}
```

**Step 2: Write test with mock server**

```rust
#[tokio::test]
async fn download_creates_file() {
    // Start mock HTTP server returning small MP4 bytes
    // Call download_to_file
    // Assert file exists and has correct size
    // Cleanup
}

#[tokio::test]
async fn download_rejects_oversized() {
    // Mock server with Content-Length > max_size
    // Assert SizeExceeded error
}
```

**Step 3: Run tests**

Run: `cargo test -p ox-media -- download`

**Step 4: Commit**

```bash
git add crates/media/src/download.rs
git commit -m "feat(media): streaming download with size limits"
```

---

### Task 6: DASH merge (`merge.rs`)

**Files:**
- Create: `crates/media/src/merge.rs`

**Step 1: Implement ffmpeg merge**

```rust
use std::path::Path;
use std::process::Command;

/// Merge video-only and audio-only files into single MP4 using ffmpeg.
pub fn merge_dash(video: &Path, audio: &Path, output: &Path) -> Result<(), crate::MediaError> {
    let status = Command::new("ffmpeg")
        .args(["-i", &video.display().to_string()])
        .args(["-i", &audio.display().to_string()])
        .args(["-c", "copy", "-y"])
        .arg(&output.display().to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| crate::MediaError::MergeFailed(format!("ffmpeg spawn: {e}")))?;

    if !status.success() {
        return Err(crate::MediaError::MergeFailed(
            format!("ffmpeg exit code: {}", status.code().unwrap_or(-1))
        ));
    }

    // Cleanup temp files
    let _ = std::fs::remove_file(video);
    let _ = std::fs::remove_file(audio);

    Ok(())
}
```

**Step 2: Write test (only if ffmpeg available)**

```rust
#[test]
fn merge_requires_ffmpeg() {
    // Check if ffmpeg exists, skip if not
    // Create two tiny valid video/audio files
    // Merge them
    // Assert output exists
}
```

**Step 3: Commit**

```bash
git add crates/media/src/merge.rs
git commit -m "feat(media): DASH merge via ffmpeg"
```

---

### Task 7: Cleanup background task (`cleanup.rs`)

**Files:**
- Create: `crates/media/src/cleanup.rs`

**Step 1: Implement TTL cleaner**

```rust
use std::path::Path;
use std::time::{Duration, SystemTime};

const MEDIA_DIR: &str = "/tmp/ox-browser/media";
const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600); // 7 days
const CLEANUP_INTERVAL: Duration = Duration::from_secs(24 * 3600); // 24h

/// Spawn background task that cleans up old files every 24h.
pub fn spawn_cleanup_task() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(CLEANUP_INTERVAL).await;
            cleanup_old_files(Path::new(MEDIA_DIR), MAX_AGE);
        }
    });
}

fn cleanup_old_files(dir: &Path, max_age: Duration) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                if let Ok(age) = now.duration_since(modified) {
                    if age > max_age {
                        let _ = std::fs::remove_file(entry.path());
                        tracing::debug!("cleaned up old media file: {:?}", entry.path());
                    }
                }
            }
        }
    }
}
```

**Step 2: Write test**

```rust
#[test]
fn cleanup_removes_old_files() {
    // Create temp dir with old and new files
    // Run cleanup_old_files with max_age = 0
    // Assert all files removed
}
```

**Step 3: Commit**

```bash
git add crates/media/src/cleanup.rs
git commit -m "feat(media): TTL cleanup for old media files (7 days)"
```

---

### Task 8: Orchestrator — `lib.rs` download function

**Files:**
- Modify: `crates/media/src/lib.rs`

**Step 1: Implement main `download()` function**

Wire together all modules: detect → fetch page → extract → download → merge → return result.

```rust
pub async fn download(
    http_client: &ox_http::HttpClient,
    req: &MediaRequest,
) -> Result<MediaResult, MediaError> {
    let platform = detect::detect_platform(&req.url);

    // 1. Fetch page HTML
    let resp = http_client.get(&req.url).await
        .map_err(|e| MediaError::FetchFailed(e.to_string()))?;

    // 2. Extract media based on platform
    let extracted = match platform {
        detect::Platform::YouTube => extract_youtube(&resp.body, &req),
        detect::Platform::Generic => extract_generic(&resp.body, &req),
    };

    // 3. Filter by media_type
    // 4. Download files
    // 5. DASH merge if needed
    // 6. Build MediaResult
}
```

**Step 2: Write integration test with mock HTTP**

```rust
#[tokio::test]
async fn download_generic_video_from_html() {
    // Mock server serving HTML with <video src="...">
    // Mock server serving the video file
    // Call download()
    // Assert file exists, MediaResult correct
}
```

**Step 3: Commit**

```bash
git add crates/media/src/lib.rs
git commit -m "feat(media): orchestrator download function"
```

---

### Task 9: REST endpoint `POST /media/download`

**Files:**
- Create: `crates/js/src/media_download.rs`
- Modify: `crates/js/src/lib.rs` (add route)
- Modify: `crates/js/Cargo.toml` (add ox-media dep)

**Step 1: Create endpoint handler**

```rust
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::AppState;
use ox_media::{MediaRequest, MediaResult, MediaError};

pub async fn media_download(
    State(state): State<AppState>,
    Json(req): Json<MediaRequest>,
) -> Result<Json<MediaResult>, (StatusCode, Json<serde_json::Value>)> {
    match ox_media::download(&state.http_client, &req).await {
        Ok(result) => Ok(Json(result)),
        Err(e) => {
            let status = match &e {
                MediaError::SizeExceeded(_) => StatusCode::PAYLOAD_TOO_LARGE,
                MediaError::FetchFailed(_) => StatusCode::BAD_GATEWAY,
                _ => StatusCode::UNPROCESSABLE_ENTITY,
            };
            Err((status, Json(serde_json::json!({
                "error": e.to_string()
            }))))
        }
    }
}
```

**Step 2: Add route in lib.rs**

Add `.route("/media/download", post(media_download::media_download))` to router.

**Step 3: Build and verify**

Run: `cargo build`
Expected: compiles

**Step 4: Commit**

```bash
git add crates/js/src/media_download.rs crates/js/src/lib.rs crates/js/Cargo.toml
git commit -m "feat: POST /media/download REST endpoint"
```

---

### Task 10: MCP tool `media_download`

**Files:**
- Create: `crates/mcp/src/tools/media_download.rs`
- Modify: `crates/mcp/src/tools/mod.rs` (register tool, remove image_extract)
- Modify: `crates/mcp/Cargo.toml` (add ox-media dep)

**Step 1: Create MCP tool**

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MediaDownloadInput {
    /// URL of page containing video or images.
    pub url: String,
    /// Type of media to extract: "auto", "video", or "image".
    #[serde(default)]
    pub media_type: Option<String>,
    /// Maximum video height (default: 1080).
    pub max_height: Option<u32>,
    /// Maximum file size in MB (default: 50).
    pub max_size_mb: Option<u32>,
    /// Maximum number of files to return (default: 1).
    pub max_results: Option<usize>,
    /// Minimum image width filter.
    pub min_width: Option<u32>,
}
```

Tool description: `"Download video or extract images from any URL. Fetches the page, finds media (video tags, og:video, og:image, img tags, JSON-LD, inline JS), downloads files. For YouTube: parses player data for direct video URLs. Returns file paths and metadata."`

**Step 2: Remove `image_extract` tool registration, replace with `media_download`**

Keep `image_search` tool unchanged.

**Step 3: Build and verify**

Run: `cargo build`

**Step 4: Commit**

```bash
git add crates/mcp/src/tools/media_download.rs crates/mcp/src/tools/mod.rs crates/mcp/Cargo.toml
git commit -m "feat: media_download MCP tool (replaces image_extract)"
```

---

### Task 11: Deprecate `/images/extract`

**Files:**
- Modify: `crates/js/src/lib.rs` (remove route)
- Delete: `crates/js/src/image_extract.rs`
- Delete: `crates/mcp/src/tools/image_extract.rs`

**Step 1: Remove `/images/extract` route from router**

Keep `/images/search` — it's a different feature (multi-engine search).

**Step 2: Delete old files**

```bash
rm crates/js/src/image_extract.rs
rm crates/mcp/src/tools/image_extract.rs
```

**Step 3: Update imports and verify compilation**

Run: `cargo build`

**Step 4: Commit**

```bash
git add -A
git commit -m "refactor: remove /images/extract (replaced by /media/download)"
```

---

### Task 12: Start cleanup task on server boot

**Files:**
- Modify: `src/main.rs` or server startup code

**Step 1: Call `ox_media::cleanup::spawn_cleanup_task()` during server init**

Add after router creation, before `axum::serve`.

**Step 2: Verify server starts**

Run: `cargo run -- serve`
Expected: starts without error, log shows no cleanup issues

**Step 3: Commit**

```bash
git add src/
git commit -m "feat: spawn media cleanup background task on startup"
```

---

### Task 13: Update consumers (go-media ox-browser extractor)

**Files:**
- Modify: `<go-media>/extract/youtube/oxbrowser.go`

**Step 1: Update ox-browser extractor to call `/media/download` instead of `/fetch-smart`**

Replace manual HTML fetch + playerResponse parsing with single call:
```go
resp, err := http.Post(e.baseURL+"/media/download", "application/json", body)
```

Parse response into `*media.Media` with file path, metadata, stats.

**Step 2: Run go-media tests**

Run: `cd <go-media> && GOWORK=off go test ./...`

**Step 3: Commit in go-media repo**

---

### Task 14: Deploy and test

**Step 1: Build and deploy ox-browser**

```bash
cd <deploy>
docker compose build --no-cache ox-browser
docker compose up -d --no-deps --force-recreate ox-browser
```

**Step 2: Test video download**

```bash
curl -s -X POST http://127.0.0.1:8901/media/download \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "media_type": "video"}'
```

**Step 3: Test image extraction (backward compat)**

```bash
curl -s -X POST http://127.0.0.1:8901/media/download \
  -H "Content-Type: application/json" \
  -d '{"url": "https://piter.now/some-article", "media_type": "image", "max_results": 5}'
```

**Step 4: Deploy updated go-media**

```bash
cd <go-media> && git tag v0.3.0 && git push origin v0.3.0
```

**Step 5: Test end-to-end**

Send a YouTube URL to the `/media/download` endpoint, verify video arrives with metadata.

**Step 6: Commit and tag ox-browser**

```bash
cd .
git tag v0.8.0
git push origin v0.8.0
```
