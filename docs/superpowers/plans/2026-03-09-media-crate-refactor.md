# Media Crate Refactor — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce complexity, enforce ≤200 line limit, DRY shared code across media crate.

**Architecture:** Extract shared wreq client builder into `crates/media/src/http.rs`, split `build_video_info` stream selection into dedicated function, move tests from `extract/mod.rs` into `extract/tests.rs`, extract `MediaResult` builders from orchestrator, introduce `ExtractContext` to reduce parameter passing in extract functions, add `PlatformDownloader` trait for extensible platform support.

**Tech Stack:** Rust, wreq, tokio, serde, dom_query

---

## Chunk 1: Shared HTTP client + youtube split

### Task 1: Extract shared wreq client builder into `http.rs`

**Why:** `download.rs:46-55` and `innertube.rs:90-101` duplicate the same wreq Client builder pattern (proxy setup, timeout, build + error mapping).

**Files:**
- Create: `crates/media/src/http.rs`
- Modify: `crates/media/src/lib.rs` (add `pub mod http;`)
- Modify: `crates/media/src/download.rs:46-55`
- Modify: `crates/media/src/innertube.rs:90-101`

- [ ] **Step 1: Create `http.rs` with `build_client` function**

```rust
//! Shared HTTP client builder with proxy support.

use std::time::Duration;

use crate::MediaError;

/// Build a wreq client with optional proxy and timeout.
pub fn build_client(
    proxy_url: &str,
    timeout: Duration,
    error_context: &str,
) -> Result<wreq::Client, MediaError> {
    let mut builder = wreq::Client::builder().timeout(timeout);
    if !proxy_url.is_empty() {
        let proxy = wreq::Proxy::all(proxy_url)
            .map_err(|e| MediaError::DownloadFailed(format!("{error_context} proxy: {e}")))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| MediaError::DownloadFailed(format!("{error_context} client: {e}")))
}
```

- [ ] **Step 2: Register module in `lib.rs`**

Add `pub mod http;` after `pub mod extract;` line in `crates/media/src/lib.rs`.

- [ ] **Step 3: Update `download.rs` to use `build_client`**

Replace lines 46-55 in `download.rs`:

```rust
// OLD:
    let mut builder = wreq::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT);
    if !proxy_url.is_empty() {
        let proxy = wreq::Proxy::all(proxy_url)
            .map_err(|e| MediaError::DownloadFailed(format!("proxy: {e}")))?;
        builder = builder.proxy(proxy);
    }
    let client = builder
        .build()
        .map_err(|e| MediaError::DownloadFailed(format!("client: {e}")))?;

// NEW:
    let client = crate::http::build_client(proxy_url, DOWNLOAD_TIMEOUT, "download")?;
```

- [ ] **Step 4: Update `innertube.rs` to use `build_client`**

Replace lines 90-101 in `innertube.rs`:

```rust
// OLD:
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

// NEW:
    let client = crate::http::build_client(proxy_url, std::time::Duration::from_secs(20), "innertube")?;
```

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ox-browser && cargo test -p ox-media`
Expected: All existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/media/src/http.rs crates/media/src/lib.rs crates/media/src/download.rs crates/media/src/innertube.rs
git commit -m "refactor(media): extract shared wreq client builder into http.rs"
```

---

### Task 2: Split `build_video_info` — extract `select_streams`

**Why:** `build_video_info` has cyclomatic complexity 14 (limit 15). Split stream selection logic into its own function.

**Files:**
- Modify: `crates/media/src/youtube.rs:82-141`

- [ ] **Step 1: Add `StreamSelection` struct and `select_streams` function**

Insert before `build_video_info` (after `is_audio` fn, line 80):

```rust
/// Selected video+audio stream URLs with dimensions.
struct StreamSelection {
    video_url: Option<String>,
    audio_url: Option<String>,
    width: u32,
    height: u32,
}

/// Pick best video (+ optional audio) streams from streaming data.
/// Prefers DASH adaptive if it offers higher resolution than combined.
fn select_streams(sd: &StreamingData, max_height: u32) -> StreamSelection {
    let best_combined = sd.formats.iter()
        .filter(|f| has_direct_url(f) && is_video(f) && f.height <= max_height)
        .max_by_key(|f| (f.height, f.bitrate));

    let best_adaptive = sd.adaptive_formats.iter()
        .filter(|f| has_direct_url(f) && is_video(f) && f.height <= max_height)
        .max_by_key(|f| (f.height, f.bitrate));

    let combined_h = best_combined.map_or(0, |f| f.height);
    let adaptive_h = best_adaptive.map_or(0, |f| f.height);

    if adaptive_h > combined_h {
        let (video_url, width, height) = best_adaptive
            .map(|v| (v.url.clone(), v.width, v.height))
            .unwrap_or_default();
        let audio_url = sd.adaptive_formats.iter()
            .filter(|f| has_direct_url(f) && is_audio(f))
            .max_by_key(|f| f.bitrate)
            .and_then(|a| a.url.clone());
        StreamSelection { video_url, audio_url, width, height }
    } else if let Some(f) = best_combined {
        StreamSelection {
            video_url: f.url.clone(), audio_url: None,
            width: f.width, height: f.height,
        }
    } else {
        StreamSelection { video_url: None, audio_url: None, width: 0, height: 0 }
    }
}
```

- [ ] **Step 2: Simplify `build_video_info` to use `select_streams`**

Replace the body of `build_video_info` (lines 82-141):

```rust
pub fn build_video_info(pr: &PlayerResponse, max_height: u32) -> YouTubeVideoInfo {
    let empty_vd = VideoDetails {
        title: String::new(), author: String::new(),
        short_description: String::new(), length_seconds: String::new(),
        view_count: String::new(),
    };
    let vd = pr.video_details.as_ref().unwrap_or(&empty_vd);

    let streams = pr.streaming_data.as_ref()
        .map(|sd| select_streams(sd, max_height))
        .unwrap_or(StreamSelection { video_url: None, audio_url: None, width: 0, height: 0 });

    YouTubeVideoInfo {
        title: Some(vd.title.clone()),
        author: if vd.author.is_empty() { None } else { Some(vd.author.clone()) },
        description: if vd.short_description.is_empty() { None } else { Some(vd.short_description.clone()) },
        duration_secs: vd.length_seconds.parse::<u64>().ok(),
        views: vd.view_count.parse::<i64>().unwrap_or(0),
        video_url: streams.video_url,
        audio_url: streams.audio_url,
        width: streams.width,
        height: streams.height,
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cd ~/src/ox-browser && cargo test -p ox-media`
Expected: All 4 youtube tests pass (combined, dash_only, signature_cipher, max_height).

- [ ] **Step 4: Commit**

```bash
git add crates/media/src/youtube.rs
git commit -m "refactor(media): split build_video_info, extract select_streams (complexity 14→7)"
```

---

## Chunk 2: Orchestrator cleanup + extract tests

### Task 3: Extract `MediaResult` builders from orchestrator

**Why:** `orchestrator.rs` is 192 lines (limit 200). The `MediaResult` construction blocks in `download_youtube` and `download_generic` are verbose. Move them to `impl MediaResult` constructors.

**Files:**
- Modify: `crates/media/src/lib.rs` (add `impl MediaResult`)
- Modify: `crates/media/src/orchestrator.rs`

- [ ] **Step 1: Add builder methods to `MediaResult` in `lib.rs`**

Add after the `MediaResult` struct definition (after line 118):

```rust
impl MediaResult {
    /// Build result for a YouTube download.
    pub fn youtube(
        file: MediaFile, title: Option<String>, author: Option<String>,
        description: Option<String>, duration_secs: Option<f64>,
        views: i64, width: u32, height: u32, merged: bool,
    ) -> Self {
        Self {
            media_type: MediaType::Video,
            files: vec![file],
            platform: Some("youtube".into()),
            title, author, description, duration_secs,
            stats: Some(MediaStats { views: Some(views), likes: None, comments: None }),
            quality: Some(Quality { width, height }),
            merged,
        }
    }

    /// Build result for a generic download.
    pub fn generic(files: Vec<MediaFile>, title: Option<String>, media_type: MediaType) -> Self {
        Self {
            media_type,
            files,
            platform: Some("generic".into()),
            title,
            author: None, description: None, duration_secs: None,
            stats: None, quality: None, merged: false,
        }
    }
}
```

- [ ] **Step 2: Simplify `download_youtube` in orchestrator**

Replace lines 71-87 (the `Ok(MediaResult { ... })` block):

```rust
    info!(path = %final_path.display(), size = final_size, merged, "YouTube download complete");
    let file = MediaFile {
        path: final_path.to_string_lossy().into_owned(),
        size_bytes: final_size,
        width: Some(info.width),
        height: Some(info.height),
    };
    Ok(MediaResult::youtube(
        file, info.title, info.author, info.description,
        info.duration_secs.map(|s| s as f64), info.views,
        info.width, info.height, merged,
    ))
```

- [ ] **Step 3: Simplify `download_generic` in orchestrator**

Replace lines 135-152 (the title extraction + `Ok(MediaResult { ... })` block):

```rust
    let doc = Document::from(html);
    let title = crate::extract::helpers::extract_og_title(&doc);
    let first_kind = items.first().map(|i| i.media_kind);
    let result_type = if first_kind == Some(MediaKind::Video) { MediaType::Video } else { MediaType::Image };
    let title = if title.is_empty() { None } else { Some(title) };
    info!(count = files.len(), "generic download complete");
    Ok(MediaResult::generic(files, title, result_type))
```

- [ ] **Step 4: Run tests**

Run: `cd ~/src/ox-browser && cargo test -p ox-media`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/media/src/lib.rs crates/media/src/orchestrator.rs
git commit -m "refactor(media): extract MediaResult builders, slim orchestrator"
```

---

### Task 4: Move extract tests to separate file

**Why:** `extract/mod.rs` is 214 lines (exceeds 200 limit). Tests account for 144 lines (70-213). Moving them to `extract/tests.rs` brings `mod.rs` to ~70 lines.

**Files:**
- Create: `crates/media/src/extract/tests.rs`
- Modify: `crates/media/src/extract/mod.rs`

- [ ] **Step 1: Create `extract/tests.rs`**

Move the entire `#[cfg(test)] mod tests { ... }` block (lines 70-213 of `extract/mod.rs`) into a new file `crates/media/src/extract/tests.rs`:

```rust
use super::*;

#[test]
fn extract_og_image() {
    // ... (exact copy of existing test)
}

// ... all 13 tests, exact copies
```

- [ ] **Step 2: Replace test block in `mod.rs` with module reference**

Remove lines 70-213 from `extract/mod.rs` and replace with:

```rust
#[cfg(test)]
mod tests;
```

- [ ] **Step 3: Run tests**

Run: `cd ~/src/ox-browser && cargo test -p ox-media`
Expected: All 13 extract tests pass.

- [ ] **Step 4: Verify line counts**

Run: `wc -l crates/media/src/extract/mod.rs`
Expected: ~72 lines (well under 200).

- [ ] **Step 5: Commit**

```bash
git add crates/media/src/extract/tests.rs crates/media/src/extract/mod.rs
git commit -m "refactor(media): move extract tests to separate file (214→72 lines)"
```

---

## Chunk 3: ExtractContext + PlatformDownloader trait

### Task 5: Introduce `ExtractContext` to reduce parameter passing

**Why:** Every extract function takes 5 identical params: `(doc, base_url, base, seen, results)`. This is a code smell — bundle them into a context struct.

**Files:**
- Modify: `crates/media/src/extract/mod.rs`
- Modify: `crates/media/src/extract/image.rs`
- Modify: `crates/media/src/extract/video.rs`

- [ ] **Step 1: Add `ExtractContext` struct to `extract/mod.rs`**

Add after imports, before `ExtractedMedia`:

```rust
/// Shared context for all extraction methods.
pub(crate) struct ExtractContext<'a> {
    pub doc: &'a Document,
    pub base_url: &'a str,
    pub base: &'a Option<Url>,
    pub seen: HashSet<String>,
    pub results: Vec<ExtractedMedia>,
}

impl<'a> ExtractContext<'a> {
    fn new(doc: &'a Document, base_url: &'a str, base: &'a Option<Url>) -> Self {
        Self { doc, base_url, base, seen: HashSet::new(), results: Vec::new() }
    }
}
```

- [ ] **Step 2: Update `extract_media` to use `ExtractContext`**

```rust
pub fn extract_media(html: &str, base_url: &str) -> Vec<ExtractedMedia> {
    let doc = Document::from(html);
    let base = Url::parse(base_url).ok();
    let mut ctx = ExtractContext::new(&doc, base_url, &base);

    image::extract_images(&mut ctx);
    video::extract_videos(&mut ctx);

    ctx.results
}
```

- [ ] **Step 3: Update `image.rs` — change all functions to take `&mut ExtractContext`**

Change signatures from 5 params to `ctx: &mut ExtractContext`:

```rust
pub(crate) fn extract_images(ctx: &mut ExtractContext) {
    extract_og_images(ctx);
    extract_img_tags(ctx);
    extract_picture_sources(ctx);
    extract_bg_images(ctx);
}

fn extract_og_images(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("meta[property='og:image']").iter() {
        if let Some(content) = node.attr("content") {
            let url = resolve_url(content.as_ref(), ctx.base);
            if !url.is_empty() && ctx.seen.insert(url.clone()) && !should_skip(&url) {
                ctx.results.push(ExtractedMedia {
                    url,
                    source: ctx.base_url.to_string(),
                    title: extract_og_title(ctx.doc),
                    width: 0, height: 0,
                    media_kind: MediaKind::Image,
                });
            }
        }
    }
}

fn extract_img_tags(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("img").iter() {
        let src = node.attr("src").map(|s| s.to_string());
        let srcset = node.attr("srcset").map(|s| s.to_string());
        let alt = node.attr("alt").map(|s| s.to_string()).unwrap_or_default();
        let w = parse_dimension(&node.attr("width").unwrap_or_default());
        let h = parse_dimension(&node.attr("height").unwrap_or_default());

        let best_url = best_srcset_url(&srcset, ctx.base)
            .or_else(|| src.map(|s| resolve_url(&s, ctx.base)))
            .unwrap_or_default();

        if best_url.is_empty() || !ctx.seen.insert(best_url.clone()) { continue; }
        if should_skip(&best_url) { continue; }
        if (w > 0 && w < MIN_DIMENSION) && (h > 0 && h < MIN_DIMENSION) { continue; }

        ctx.results.push(ExtractedMedia {
            url: best_url, source: ctx.base_url.to_string(),
            title: alt, width: w, height: h,
            media_kind: MediaKind::Image,
        });
    }
}

fn extract_picture_sources(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("picture > source[srcset]").iter() {
        let srcset = node.attr("srcset").map(|s| s.to_string());
        if let Some(url) = best_srcset_url(&srcset, ctx.base) {
            if !url.is_empty() && ctx.seen.insert(url.clone()) && !should_skip(&url) {
                ctx.results.push(ExtractedMedia {
                    url, source: ctx.base_url.to_string(),
                    title: String::new(), width: 0, height: 0,
                    media_kind: MediaKind::Image,
                });
            }
        }
    }
}

fn extract_bg_images(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("[style]").iter() {
        if let Some(style) = node.attr("style") {
            for url in extract_bg_urls(style.as_ref(), ctx.base) {
                if ctx.seen.insert(url.clone()) && !should_skip(&url) {
                    ctx.results.push(ExtractedMedia {
                        url, source: ctx.base_url.to_string(),
                        title: String::new(), width: 0, height: 0,
                        media_kind: MediaKind::Image,
                    });
                }
            }
        }
    }
}
```

- [ ] **Step 4: Update `video.rs` — change all functions to take `&mut ExtractContext`**

Change signatures from 5 params to `ctx: &mut ExtractContext`:

```rust
use super::{ExtractContext, ExtractedMedia, resolve_url, video_media};

pub(crate) fn extract_videos(ctx: &mut ExtractContext) {
    extract_video_tags(ctx);
    extract_og_video(ctx);
    extract_twitter_player(ctx);
    extract_json_ld_video(ctx);
    extract_inline_js_video(ctx);
}

fn push_video(raw: &str, ctx: &mut ExtractContext, title: &str) {
    let url = resolve_url(raw, ctx.base);
    if !url.is_empty() && ctx.seen.insert(url.clone()) {
        ctx.results.push(video_media(url, title.to_string(), ctx.base_url));
    }
}

fn extract_video_tags(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("video").iter() {
        if let Some(src) = node.attr("src") {
            push_video(src.as_ref(), ctx, "");
        }
        for source in node.select("source").iter() {
            if let Some(src) = source.attr("src") {
                push_video(src.as_ref(), ctx, "");
            }
        }
    }
}

fn extract_og_video(ctx: &mut ExtractContext) {
    let sel = "meta[property='og:video'], meta[property='og:video:secure_url']";
    for node in ctx.doc.select(sel).iter() {
        if let Some(content) = node.attr("content") {
            push_video(content.as_ref(), ctx, "");
        }
    }
}

fn extract_twitter_player(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("meta[name='twitter:player:stream']").iter() {
        if let Some(content) = node.attr("content") {
            push_video(content.as_ref(), ctx, "");
        }
    }
}

fn extract_json_ld_video(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("script[type='application/ld+json']").iter() {
        let text = node.text();
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        walk_json_ld(&value, ctx);
    }
}

fn walk_json_ld(value: &serde_json::Value, ctx: &mut ExtractContext) {
    match value {
        serde_json::Value::Object(obj) => {
            if obj.get("@type").and_then(|t| t.as_str()) == Some("VideoObject") {
                let raw = obj.get("contentUrl").or_else(|| obj.get("embedUrl"))
                    .and_then(|v| v.as_str()).unwrap_or_default();
                let title = obj.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                push_video(raw, ctx, title);
            }
            if let Some(graph) = obj.get("@graph") {
                walk_json_ld(graph, ctx);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr { walk_json_ld(item, ctx); }
        }
        _ => {}
    }
}

fn extract_inline_js_video(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("script").iter() {
        let stype = node.attr("type").unwrap_or_default();
        if !stype.as_ref().is_empty() && stype.as_ref() != "text/javascript" { continue; }
        let text = node.text();
        for cap in VIDEO_URL_RE.captures_iter(&text) {
            if let Some(m) = cap.get(1) {
                push_video(m.as_str(), ctx, "");
            }
        }
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ox-browser && cargo test -p ox-media`
Expected: All 13 extract tests pass unchanged (API `extract_media(html, base_url)` is the same).

- [ ] **Step 6: Commit**

```bash
git add crates/media/src/extract/mod.rs crates/media/src/extract/image.rs crates/media/src/extract/video.rs
git commit -m "refactor(media): introduce ExtractContext, reduce 5-param functions to 1"
```

---

### Task 6: Add `PlatformDownloader` trait for extensible platform dispatch

**Why:** `orchestrator.rs` uses match on `Platform` enum — adding Instagram or TikTok means modifying orchestrator. Trait-based dispatch is cleaner and open for extension.

**Files:**
- Create: `crates/media/src/platform.rs`
- Create: `crates/media/src/platform_youtube.rs`
- Create: `crates/media/src/platform_generic.rs`
- Modify: `crates/media/src/orchestrator.rs` (slim down to dispatcher)
- Modify: `crates/media/src/lib.rs` (add modules)
- Modify: `crates/media/src/detect.rs` (return boxed trait instead of enum)

- [ ] **Step 1: Create `platform.rs` with the trait**

```rust
//! Platform abstraction for media downloads.

use crate::{MediaConfig, MediaError, MediaRequest, MediaResult};

/// Trait for platform-specific download logic.
#[async_trait::async_trait]
pub trait PlatformDownloader: Send + Sync {
    /// Download media from this platform.
    async fn download(
        &self,
        url: &str,
        req: &MediaRequest,
        max_bytes: u64,
        config: &MediaConfig,
    ) -> Result<MediaResult, MediaError>;
}
```

Note: Add `async-trait = "0.1"` to `crates/media/Cargo.toml` dependencies.

- [ ] **Step 2: Create `platform_youtube.rs`**

Move `download_youtube` logic from `orchestrator.rs` into this file:

```rust
//! YouTube platform downloader via Innertube API.

use tracing::{debug, info};

use crate::download::{download_to_file, media_path};
use crate::innertube;
use crate::merge::merge_dash;
use crate::platform::PlatformDownloader;
use crate::youtube::build_video_info;
use crate::{MediaConfig, MediaError, MediaFile, MediaRequest, MediaResult};

pub struct YouTubeDownloader;

#[async_trait::async_trait]
impl PlatformDownloader for YouTubeDownloader {
    async fn download(
        &self,
        url: &str,
        req: &MediaRequest,
        max_bytes: u64,
        config: &MediaConfig,
    ) -> Result<MediaResult, MediaError> {
        let video_id = innertube::extract_video_id(url)
            .ok_or_else(|| MediaError::FetchFailed("no video ID in URL".into()))?;

        let proxy = &config.proxy_url;
        let pr = innertube::fetch_player_response(video_id, config, proxy).await?;
        let info = build_video_info(&pr, req.max_height.unwrap_or(config.default_max_height));
        let video_url = info.video_url.as_deref().ok_or(MediaError::NoVideoFound)?;
        debug!(video_url, audio = info.audio_url.is_some(), "YouTube streams found");

        let video_dest = media_path("yt", url, "mp4");
        let video_size = download_to_file(video_url, &video_dest, max_bytes, proxy).await?;

        let (final_path, final_size, merged) = if let Some(ref audio_url) = info.audio_url {
            let audio_dest = media_path("yt", &format!("{url}_audio"), "m4a");
            download_to_file(audio_url, &audio_dest, max_bytes, proxy).await?;
            let merged_dest = media_path("yt", &format!("{url}_merged"), "mp4");
            merge_dash(&video_dest, &audio_dest, &merged_dest)
                .map_err(|e| MediaError::MergeFailed(e.to_string()))?;
            let size = tokio::fs::metadata(&merged_dest)
                .await
                .map_err(|e| MediaError::DownloadFailed(format!("stat merged: {e}")))?
                .len();
            (merged_dest, size, true)
        } else {
            (video_dest, video_size, false)
        };

        info!(path = %final_path.display(), size = final_size, merged, "YouTube download complete");
        let file = MediaFile {
            path: final_path.to_string_lossy().into_owned(),
            size_bytes: final_size,
            width: Some(info.width),
            height: Some(info.height),
        };
        Ok(MediaResult::youtube(
            file, info.title, info.author, info.description,
            info.duration_secs.map(|s| s as f64), info.views,
            info.width, info.height, merged,
        ))
    }
}
```

- [ ] **Step 3: Create `platform_generic.rs`**

Move `download_generic` + `url_extension` from `orchestrator.rs`:

```rust
//! Generic platform downloader — extract media from HTML.

use dom_query::Document;
use tracing::{debug, info};

use crate::download::{download_to_file, media_path};
use crate::extract::{extract_media, MediaKind};
use crate::platform::PlatformDownloader;
use crate::{MediaConfig, MediaError, MediaFile, MediaRequest, MediaResult, MediaType};

pub struct GenericDownloader {
    pub html: String,
    pub base_url: String,
}

#[async_trait::async_trait]
impl PlatformDownloader for GenericDownloader {
    async fn download(
        &self,
        _url: &str,
        req: &MediaRequest,
        max_bytes: u64,
        config: &MediaConfig,
    ) -> Result<MediaResult, MediaError> {
        let mut items = extract_media(&self.html, &self.base_url);

        match req.media_type {
            MediaType::Video => items.retain(|m| m.media_kind == MediaKind::Video),
            MediaType::Image => items.retain(|m| m.media_kind == MediaKind::Image),
            MediaType::Auto => {}
        }
        if let Some(min_w) = req.min_width {
            items.retain(|m| m.width == 0 || m.width >= min_w);
        }
        if items.is_empty() {
            return match req.media_type {
                MediaType::Image => Err(MediaError::NoImageFound),
                _ => Err(MediaError::NoVideoFound),
            };
        }

        items.sort_by(|a, b| {
            let rank = |k: MediaKind| if k == MediaKind::Video { 0u8 } else { 1 };
            rank(a.media_kind).cmp(&rank(b.media_kind)).then_with(|| {
                let area = |m: &crate::extract::ExtractedMedia| (m.width as u64) * (m.height as u64);
                area(b).cmp(&area(a))
            })
        });
        items.truncate(req.max_results.unwrap_or(config.default_max_results));
        debug!(count = items.len(), "downloading generic media items");

        let mut files = Vec::with_capacity(items.len());
        for item in &items {
            let ext = url_extension(&item.url, item.media_kind);
            let dest = media_path("generic", &item.url, ext);
            let size = download_to_file(&item.url, &dest, max_bytes, "").await?;
            files.push(MediaFile {
                path: dest.to_string_lossy().into_owned(),
                size_bytes: size,
                width: if item.width > 0 { Some(item.width) } else { None },
                height: if item.height > 0 { Some(item.height) } else { None },
            });
        }

        let doc = Document::from(self.html.as_str());
        let title = crate::extract::helpers::extract_og_title(&doc);
        let first_kind = items.first().map(|i| i.media_kind);
        let result_type = if first_kind == Some(MediaKind::Video) { MediaType::Video } else { MediaType::Image };
        let title = if title.is_empty() { None } else { Some(title) };
        info!(count = files.len(), "generic download complete");
        Ok(MediaResult::generic(files, title, result_type))
    }
}

fn url_extension(url: &str, kind: MediaKind) -> &str {
    let path = url.split('?').next().unwrap_or(url);
    if let Some(dot) = path.rfind('.') {
        let ext = &path[dot + 1..];
        if !ext.is_empty() && ext.len() <= 5 && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
            return ext;
        }
    }
    match kind {
        MediaKind::Video => "mp4",
        MediaKind::Image => "jpg",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_extension_from_path() {
        assert_eq!(url_extension("https://example.com/video.mp4", MediaKind::Video), "mp4");
        assert_eq!(url_extension("https://example.com/photo.webp", MediaKind::Image), "webp");
        assert_eq!(url_extension("https://example.com/img.jpg?w=800", MediaKind::Image), "jpg");
    }

    #[test]
    fn url_extension_fallback() {
        assert_eq!(url_extension("https://example.com/media", MediaKind::Video), "mp4");
        assert_eq!(url_extension("https://example.com/media", MediaKind::Image), "jpg");
    }

    #[test]
    fn url_extension_ignores_long() {
        assert_eq!(url_extension("https://example.com/file.toolong", MediaKind::Video), "mp4");
    }
}
```

- [ ] **Step 4: Slim `orchestrator.rs` to pure dispatcher**

Replace entire orchestrator content:

```rust
//! Orchestrator: detect platform, dispatch to platform-specific downloader.

use tracing::info;

use crate::detect::{detect_platform, Platform};
use crate::platform_generic::GenericDownloader;
use crate::platform_youtube::YouTubeDownloader;
use crate::{MediaConfig, MediaError, MediaRequest, MediaResult};

/// Main entry point: detect platform, dispatch download.
pub async fn download(
    http_client: &ox_http::HttpClient,
    req: &MediaRequest,
    config: &MediaConfig,
) -> Result<MediaResult, MediaError> {
    let platform = detect_platform(&req.url);
    let max_bytes = (req.max_size_mb.unwrap_or(config.default_max_size_mb) * 1_048_576.0) as u64;
    info!(url = %req.url, ?platform, "starting media download");

    use crate::platform::PlatformDownloader;
    match platform {
        Platform::YouTube => {
            YouTubeDownloader.download(&req.url, req, max_bytes, config).await
        }
        Platform::Generic => {
            let resp = http_client
                .get(&req.url)
                .await
                .map_err(|e| MediaError::FetchFailed(e.to_string()))?;
            if resp.status >= 400 {
                return Err(MediaError::FetchFailed(format!("HTTP {}", resp.status)));
            }
            let downloader = GenericDownloader {
                html: resp.body.clone(),
                base_url: resp.url.clone(),
            };
            downloader.download(&req.url, req, max_bytes, config).await
        }
    }
}
```

- [ ] **Step 5: Register new modules in `lib.rs`**

Add to `crates/media/src/lib.rs`:

```rust
pub mod platform;
pub mod platform_generic;
pub mod platform_youtube;
```

- [ ] **Step 6: Add `async-trait` dependency**

Run: `cd ~/src/ox-browser && cargo add async-trait --package ox-media`

- [ ] **Step 7: Run tests**

Run: `cd ~/src/ox-browser && cargo test -p ox-media`
Expected: All tests pass. The 3 `url_extension` tests now live in `platform_generic.rs`.

- [ ] **Step 8: Commit**

```bash
git add crates/media/
git commit -m "refactor(media): add PlatformDownloader trait, split orchestrator into platform modules"
```

---

## Final verification

- [ ] **Run full test suite:** `cd ~/src/ox-browser && cargo test -p ox-media`
- [ ] **Run clippy:** `cd ~/src/ox-browser && cargo clippy -p ox-media -- -D warnings`
- [ ] **Check line counts:** `wc -l crates/media/src/*.rs crates/media/src/extract/*.rs`
- [ ] **Verify no file exceeds 200 lines**
