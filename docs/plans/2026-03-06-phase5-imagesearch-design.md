# Phase 4.6: Image Search Engine

**Date:** 2026-03-06
**Status:** Planned
**Depends on:** Phase 2 (HTTP client + CF bypass)

## Goal

Add image search capability to ox-browser: scrape image results from Bing, DDG, Yandex, and Brave
using the existing stealth HTTP infrastructure (wreq+BoringSSL, proxy rotation, CF bypass, rate limiting).

Expose via REST (`POST /images/search`) and MCP tool (`image_search`).

## Why ox-browser (not Go)

- **wreq + BoringSSL** — Chrome-identical TLS/HTTP2 fingerprint (Go tls-client is emulation)
- **Middleware chain** — retry, rate limit, CF detect/solve already wired
- **Proxy pool** — Webshare rotation with health tracking
- **Rust regex/serde** — 10x faster parsing than Go for large HTML responses
- All infrastructure exists — we're adding ~500 LOC of parsing logic on top

## Architecture

New crate: `ox-imagesearch` (parallel to `ox-intelligence`, `ox-security`).

```
ox-imagesearch/src/
├── lib.rs          — ImageResult, ImageEngine trait, ImageSearchEngine
├── bing.rs         — Bing /images/async endpoint parser
├── ddg.rs          — DDG vqd token + /i.js image API
├── yandex.rs       — Yandex /images/search?format=json
├── brave.rs        — Brave Images HTML scraper
└── fusion.rs       — Parallel execution + WRR merge + dedup
```

### ImageResult

```rust
pub struct ImageResult {
    pub url: String,          // full-size image URL
    pub thumbnail: String,    // thumbnail URL
    pub source: String,       // page URL where image found
    pub title: String,
    pub width: u32,
    pub height: u32,
    pub engine: String,       // "bing" | "ddg" | "yandex" | "brave"
}
```

### ImageEngine trait

```rust
#[async_trait]
pub trait ImageEngine: Send + Sync {
    async fn search(
        &self, client: &HttpClient, query: &str, max: usize,
    ) -> Result<Vec<ImageResult>>;
    fn name(&self) -> &str;
}
```

All engines receive the shared `HttpClient` (with full middleware chain).

### Engines

**Bing Images** (`/images/async`):
- URL: `https://www.bing.com/images/async?q={query}&first={offset}&count=35&mmasync=1`
- Parse: regex `m="(.*?)"` → JSON decode `{murl, turl, purl, t, desc}`
- Most stable image scraping endpoint (used by icrawler 914 stars, imdoto)

**DDG Images** (`/i.js`):
- Step 1: GET `duckduckgo.com/?q={}&iax=images&ia=images` → extract vqd token
- Step 2: GET `/i.js?l=ru-ru&o=json&q={}&vqd={}&f=,,,,,&p=1`
- Parse: JSON `{results: [{image, thumbnail, url, title, width, height}]}`

**Yandex Images** (`/images/search`):
- URL: `https://yandex.ru/images/search?rpt=image&format=json&text={query}`
- Parse: JSON or regex `img_url=` extraction
- Rate limit: aggressive, needs proxy rotation

**Brave Images** (`/images`):
- URL: `https://search.brave.com/images?q={query}`
- Parse: goquery-style HTML scraping via dom_query
- CF protected — benefits from solver middleware

### Fusion

```rust
pub struct ImageSearchEngine {
    engines: Vec<Box<dyn ImageEngine>>,
}

impl ImageSearchEngine {
    pub async fn search(&self, client: &HttpClient, query: &str, max: usize) -> Vec<ImageResult> {
        // 1. Parallel: tokio::spawn per engine
        // 2. Collect all results (ignore per-engine errors)
        // 3. WRR merge: dedup by URL, accumulate rank scores
        // 4. Sort by fused score, truncate to max
    }
}
```

### REST endpoint

```
POST /images/search
{
  "query": "кот на крыше",
  "engines": ["bing", "ddg"],  // optional, default: all
  "max_results": 10             // optional, default: 10
}
→ {
  "images": [...],
  "engines_used": ["bing", "ddg"],
  "elapsed_ms": 450
}
```

### MCP tool

```
tool: image_search
input: { query, engines?, max_results? }
output: JSON with images array
```

## Integration with go-imagefy

go-imagefy adds `OxBrowserProvider` (~60 LOC):
- Implements `SearchProvider` interface
- POST to `http://ox-browser:8901/images/search`
- Converts `ImageResult` → `ImageCandidate`

go-imagefy validation pipeline (license, dedup, LLM classification) runs on results.
ox-browser handles scraping, go-imagefy handles validation.

## Estimated effort

| File | LOC | Description |
|------|-----|-------------|
| `lib.rs` | 40 | Types + trait + engine struct |
| `bing.rs` | 90 | Bing parser |
| `ddg.rs` | 100 | DDG vqd + images parser |
| `yandex.rs` | 80 | Yandex parser |
| `brave.rs` | 80 | Brave HTML parser |
| `fusion.rs` | 60 | Parallel + WRR |
| `js/image_search.rs` | 60 | REST endpoint |
| `mcp/tools/image_search.rs` | 50 | MCP tool |
| Tests | 250 | Unit tests per engine + fusion |
| **Total** | ~810 | |
