# Media Download — Universal Video/Image Downloader

## Overview

New unified `POST /media/download` endpoint in ox-browser that replaces `/images/extract` and adds video download capability. Handles any URL — detects platform, extracts media URLs from HTML/JS, downloads files with TLS fingerprinting and proxy support.

## API

```
POST /media/download
{
  "url": "https://...",
  "media_type": "auto",       // "auto" | "video" | "image"
  "max_height": 1080,         // optional, quality filter
  "max_size_mb": 50,          // optional, size limit
  "max_results": 1,           // optional, for images can be >1
  "proxy": true               // optional, use proxy pool
}
```

### Response (video)
```json
{
  "media_type": "video",
  "files": [{"path": "/tmp/ox-browser/media/yt_abc123.mp4", "size_bytes": 12000000}],
  "platform": "youtube",
  "title": "...",
  "author": "...",
  "description": "...",
  "duration_secs": 213,
  "stats": {"views": 1000000, "likes": 50000},
  "quality": {"width": 1280, "height": 720},
  "merged": false
}
```

### Response (image)
```json
{
  "media_type": "image",
  "files": [
    {"path": "/tmp/ox-browser/media/img_a1b2.jpg", "size_bytes": 250000, "width": 1200, "height": 800},
    {"path": "/tmp/ox-browser/media/img_c3d4.jpg", "size_bytes": 180000, "width": 800, "height": 600}
  ],
  "platform": "generic",
  "title": "Page title"
}
```

### Error Response
```json
{
  "error": "no_video_found",
  "message": "No downloadable video URLs found on page",
  "details": {"platform": "youtube", "tried": ["html_tags", "og_meta", "inline_js", "player_response"], "cf_detected": false}
}
```

Error types: `no_video_found`, `no_image_found`, `download_failed`, `size_exceeded`, `merge_failed`, `fetch_failed`.

## Architecture

### New crate: `crates/media/`

```
crates/media/
├── lib.rs          — pub download(url, opts) → MediaResult
├── detect.rs       — platform detection + media_type auto-detect
├── extract.rs      — generic: <video>, og:video, <img>, og:image, JSON-LD, inline JS
├── youtube.rs      — YouTube playerResponse parser
├── download.rs     — streaming download via wreq
├── merge.rs        — DASH merge via ffmpeg
└── cleanup.rs      — TTL cleaner (7 days, tokio background task)
```

### Data Flow

```
POST /media/download
  → detect platform (URL regex)
  → fetch page via fetch-smart (CF bypass if needed)
  → extract media URLs:
      YouTube → parse ytInitialPlayerResponse from <script>
      Generic → <video>, og:video, og:image, <img>, twitter:player, JSON-LD, inline JS
  → filter by media_type, max_height, max_size
  → download files via wreq (TLS fingerprint, proxy, streaming to disk)
  → if DASH (separate video+audio) → ffmpeg merge
  → return file paths + metadata
```

### Generic Video Extraction (priority order)

**Level 1 — HTML tags:**
- `<video src>` and `<video><source src>`
- `<meta property="og:video">`
- `<meta property="og:video:secure_url">`
- `<meta name="twitter:player:stream">`

**Level 2 — JSON-LD:**
- `<script type="application/ld+json">` → `contentUrl`, `embedUrl`, `@type: VideoObject`
- Also provides: title, description, duration, author

**Level 3 — Inline JS heuristics:**
- Regex in `<script>` blocks: JSON objects with URLs ending `.mp4`, `.m3u8`, `.webm`
- Patterns: `"video_url":`, `"playbackUrl":`, `"stream_url":`, `"sources":[`
- YouTube-specific: `ytInitialPlayerResponse` (in youtube.rs)

### Image Extraction (migrated from imagesearch crate)

Preserves ALL existing `/images/extract` functionality:
- `<img>` tags with size filtering (min_width, min_height)
- `<meta property="og:image">`
- `<picture><source>` elements
- CSS background images
- JSON-LD `image` property
- Deduplication and ranking by size/position

### YouTube Specifics

- Parse `ytInitialPlayerResponse` from inline `<script>`
- Extract `videoDetails` (title, author, viewCount) + `streamingData` (formats, adaptiveFormats)
- v1: only formats with direct `url` (skip signatureCipher)
- v2 future: JS decipher via Boa (Rust JS engine)
- Bot detection mitigation: Chrome TLS fingerprint, proxy rotation, cookie persistence

### DASH Merge

- Separate video-only + audio-only streams → `ffmpeg -i video -i audio -c copy output.mp4`
- Via `std::process::Command`
- Temp files cleaned up after merge

### Download

- Streaming via wreq — chunked write to file, no full buffer in RAM
- Content-Length pre-check for max_size_mb
- 120s timeout
- Partial file cleanup on error (success flag pattern)
- File naming: `{platform}_{hash8}.{ext}` where hash = SHA256(url)[:8]

### File Management

```
/tmp/ox-browser/media/           — all downloaded media
├── yt_abc123.mp4                 — final video
├── yt_abc123_video.mp4           — temp DASH video-only (cleaned after merge)
├── yt_abc123_audio.m4a           — temp DASH audio-only (cleaned after merge)
└── img_def456.jpg                — downloaded image
```

- TTL cleaner: tokio background task, runs every 24h, deletes files older than 7 days
- ox-browser does not delete files on request — client responsibility

### Migration

- `/images/extract` → deprecated, replaced by `/media/download` with `media_type: "image"`
- `/images/search` → stays as-is (searches across engines, not page extraction)
- MCP tool `image_extract` → replaced by `media_download`
- MCP tool `image_search` → stays
- go-media ox-browser extractor → calls `/media/download` instead of `/fetch-smart` + manual parsing

## Testing

- Unit: detect platform, parse HTML tags, parse og:video/og:image, parse playerResponse, format selection
- Integration: mock HTTP server → full pipeline → files on disk
- Migration: verify all existing image_extract test cases pass through new endpoint
- No live YouTube tests (unstable)
