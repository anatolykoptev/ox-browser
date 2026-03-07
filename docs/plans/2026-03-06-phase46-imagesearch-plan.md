# Image Search Engine Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add multi-engine image search (Bing, DDG, Yandex, Brave) to ox-browser, expose via REST + MCP. Then wire into go-imagefy as primary search provider, replacing Go-based DDG scraper.

**Architecture:** New `ox-imagesearch` Rust crate with `ImageEngine` trait, 4 engine implementations, WRR fusion. go-imagefy gets `OxBrowserProvider` that calls `POST /images/search`. go-imagefy validation pipeline (license, dedup, LLM) unchanged.

**Tech Stack:** Rust (ox-browser: wreq, serde, regex, dom_query, tokio), Go (go-imagefy: net/http, encoding/json)

**Repos:** `~/src/ox-browser`, `~/src/go-imagefy`, `~/src/go-wp`

---

## Task 1: ox-imagesearch crate scaffold

**Files:**
- Create: `crates/imagesearch/Cargo.toml`
- Create: `crates/imagesearch/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

**Step 1: Create Cargo.toml**

```toml
# crates/imagesearch/Cargo.toml
[package]
name = "ox-imagesearch"
version.workspace = true
edition.workspace = true

[dependencies]
ox-http = { path = "../http" }
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
regex = "1"
tokio.workspace = true
tracing.workspace = true
thiserror.workspace = true
urlencoding = "2"

[dev-dependencies]
tokio = { version = "1", features = ["full", "test-util"] }
```

**Step 2: Create lib.rs with types + trait**

```rust
// crates/imagesearch/src/lib.rs
pub mod bing;
pub mod ddg;
pub mod fusion;

use async_trait::async_trait;
use ox_http::HttpClient;
use serde::{Deserialize, Serialize};

/// A single image search result from any engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageResult {
    pub url: String,
    pub thumbnail: String,
    pub source: String,
    pub title: String,
    pub width: u32,
    pub height: u32,
    pub engine: String,
}

/// Errors from image search operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http: {0}")]
    Http(#[from] ox_http::HttpError),
    #[error("parse: {0}")]
    Parse(String),
    #[error("no results")]
    NoResults,
}

pub type Result<T> = std::result::Result<T, Error>;

/// An image search engine that can query for images.
#[async_trait]
pub trait ImageEngine: Send + Sync {
    async fn search(&self, client: &HttpClient, query: &str, max: usize) -> Result<Vec<ImageResult>>;
    fn name(&self) -> &str;
}
```

**Step 3: Add to workspace**

In root `Cargo.toml`, add `"crates/imagesearch"` to `[workspace] members`.

**Step 4: Verify it compiles**

Run: `cd ~/src/ox-browser && cargo check -p ox-imagesearch`
Expected: compiles with no errors

**Step 5: Commit**

```bash
git add crates/imagesearch/ Cargo.toml Cargo.lock
git commit -m "feat(imagesearch): scaffold ox-imagesearch crate with ImageEngine trait"
```

---

## Task 2: Bing Images engine

**Files:**
- Create: `crates/imagesearch/src/bing.rs`
- Test: inline `#[cfg(test)]` module

**Reference:** Bing `/images/async` endpoint returns HTML with embedded JSON in `m="..."` attributes. Each `m` value is a JSON object with `murl` (full URL), `turl` (thumbnail), `purl` (page URL), `t` (title), `desc` fields.

**Step 1: Write Bing parser test**

```rust
// At bottom of crates/imagesearch/src/bing.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bing_html_extracts_images() {
        let html = r#"<div class="imgpt"><a m="{&quot;murl&quot;:&quot;https://example.com/photo.jpg&quot;,&quot;turl&quot;:&quot;https://th.bing.com/th1.jpg&quot;,&quot;purl&quot;:&quot;https://example.com/page&quot;,&quot;t&quot;:&quot;Nice Photo&quot;,&quot;desc&quot;:&quot;A nice photo&quot;}"></a></div><div class="imgpt"><a m="{&quot;murl&quot;:&quot;https://other.com/cat.png&quot;,&quot;turl&quot;:&quot;https://th.bing.com/th2.jpg&quot;,&quot;purl&quot;:&quot;https://other.com/cats&quot;,&quot;t&quot;:&quot;Cat&quot;,&quot;desc&quot;:&quot;A cat&quot;}"></a></div>"#;
        let results = parse_bing_html(html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].url, "https://example.com/photo.jpg");
        assert_eq!(results[0].thumbnail, "https://th.bing.com/th1.jpg");
        assert_eq!(results[0].source, "https://example.com/page");
        assert_eq!(results[0].title, "Nice Photo");
        assert_eq!(results[0].engine, "bing");
        assert_eq!(results[1].url, "https://other.com/cat.png");
    }

    #[test]
    fn parse_bing_html_empty_input() {
        assert!(parse_bing_html("").is_empty());
        assert!(parse_bing_html("<html><body>no images</body></html>").is_empty());
    }

    #[test]
    fn parse_bing_html_malformed_json() {
        let html = r#"<a m="{not valid json}"></a>"#;
        assert!(parse_bing_html(html).is_empty());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd ~/src/ox-browser && cargo test -p ox-imagesearch -- bing`
Expected: FAIL — `parse_bing_html` not found

**Step 3: Implement Bing engine**

```rust
// crates/imagesearch/src/bing.rs
use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

use crate::{Error, ImageEngine, ImageResult, Result};
use ox_http::HttpClient;

const BING_IMAGES_URL: &str = "https://www.bing.com/images/async";

/// Bing Images search via the /images/async endpoint.
pub struct BingImages;

#[async_trait]
impl ImageEngine for BingImages {
    async fn search(&self, client: &HttpClient, query: &str, max: usize) -> Result<Vec<ImageResult>> {
        let count = max.min(35);
        let url = format!(
            "{}?q={}&first=0&count={}&mmasync=1",
            BING_IMAGES_URL,
            urlencoding::encode(query),
            count,
        );
        let resp = client.get(&url).await?;
        if resp.status != 200 {
            return Err(Error::Parse(format!("bing status {}", resp.status)));
        }
        let mut results = parse_bing_html(&resp.body);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "bing"
    }
}

static M_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"m="(\{[^"]*\})""#).expect("bing m-attr regex")
});

#[derive(Deserialize)]
struct BingMAttr {
    murl: Option<String>,
    turl: Option<String>,
    purl: Option<String>,
    t: Option<String>,
}

fn parse_bing_html(html: &str) -> Vec<ImageResult> {
    let decoded = html.replace("&quot;", "\"").replace("&amp;", "&");
    let mut results = Vec::new();

    for cap in M_ATTR_RE.captures_iter(&decoded) {
        let json_str = &cap[1];
        let Ok(attr) = serde_json::from_str::<BingMAttr>(json_str) else {
            continue;
        };
        let Some(murl) = attr.murl.filter(|u| !u.is_empty()) else {
            continue;
        };
        results.push(ImageResult {
            url: murl,
            thumbnail: attr.turl.unwrap_or_default(),
            source: attr.purl.unwrap_or_default(),
            title: attr.t.unwrap_or_default(),
            width: 0,
            height: 0,
            engine: "bing".into(),
        });
    }
    results
}
```

**Step 4: Run tests**

Run: `cd ~/src/ox-browser && cargo test -p ox-imagesearch -- bing`
Expected: 3 tests PASS

**Step 5: Commit**

```bash
git add crates/imagesearch/src/bing.rs
git commit -m "feat(imagesearch): add Bing Images engine with /images/async parser"
```

---

## Task 3: DDG Images engine

**Files:**
- Create: `crates/imagesearch/src/ddg.rs`

**Reference:** Two-step: 1) GET `duckduckgo.com/?q=X&iax=images&ia=images` → extract `vqd=TOKEN` via regex. 2) GET `/i.js?l=ru-ru&o=json&q=X&vqd=TOKEN` → JSON `{results: [{image, thumbnail, url, title, width, height}]}`.

**Step 1: Write DDG parser tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_vqd_token() {
        let html = r#"<script>nrj('/d.js?q=cats&vqd=4-123456789-abc&kl=ru-ru')</script>"#;
        assert_eq!(parse_vqd(html), Some("4-123456789-abc".into()));
    }

    #[test]
    fn extract_vqd_missing() {
        assert_eq!(parse_vqd("<html>no token</html>"), None);
    }

    #[test]
    fn parse_ddg_json_results() {
        let json = r#"{"results":[{"image":"https://img.com/a.jpg","thumbnail":"https://th.com/a.jpg","url":"https://page.com/a","title":"Cat photo","width":800,"height":600},{"image":"https://img.com/b.jpg","thumbnail":"https://th.com/b.jpg","url":"https://page.com/b","title":"Dog photo","width":1024,"height":768}]}"#;
        let results = parse_ddg_json(json);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].url, "https://img.com/a.jpg");
        assert_eq!(results[0].width, 800);
        assert_eq!(results[0].engine, "ddg");
    }

    #[test]
    fn parse_ddg_json_empty() {
        assert!(parse_ddg_json("{}").is_empty());
        assert!(parse_ddg_json(r#"{"results":[]}"#).is_empty());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd ~/src/ox-browser && cargo test -p ox-imagesearch -- ddg`

**Step 3: Implement DDG engine**

```rust
// crates/imagesearch/src/ddg.rs
use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

use crate::{Error, ImageEngine, ImageResult, Result};
use ox_http::HttpClient;

const DDG_BASE: &str = "https://duckduckgo.com";

pub struct DdgImages;

#[async_trait]
impl ImageEngine for DdgImages {
    async fn search(&self, client: &HttpClient, query: &str, max: usize) -> Result<Vec<ImageResult>> {
        let token_url = format!(
            "{}/?q={}&iax=images&ia=images",
            DDG_BASE,
            urlencoding::encode(query),
        );
        let token_resp = client.get(&token_url).await?;
        let vqd = parse_vqd(&token_resp.body)
            .ok_or_else(|| Error::Parse("vqd token not found".into()))?;

        let images_url = format!(
            "{}/i.js?l=ru-ru&o=json&q={}&vqd={}&f=,,,,,&p=1",
            DDG_BASE,
            urlencoding::encode(query),
            urlencoding::encode(&vqd),
        );
        let images_resp = client.get(&images_url).await?;
        let mut results = parse_ddg_json(&images_resp.body);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "ddg"
    }
}

static VQD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"vqd=([0-9a-f-]+)").expect("vqd regex")
});

fn parse_vqd(html: &str) -> Option<String> {
    VQD_RE.captures(html).map(|c| c[1].to_owned())
}

#[derive(Deserialize)]
struct DdgResponse {
    #[serde(default)]
    results: Vec<DdgResult>,
}

#[derive(Deserialize)]
struct DdgResult {
    #[serde(default)]
    image: String,
    #[serde(default)]
    thumbnail: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    width: u32,
    #[serde(default)]
    height: u32,
}

fn parse_ddg_json(body: &str) -> Vec<ImageResult> {
    let Ok(resp) = serde_json::from_str::<DdgResponse>(body) else {
        return Vec::new();
    };
    resp.results
        .into_iter()
        .filter(|r| !r.image.is_empty())
        .map(|r| ImageResult {
            url: r.image,
            thumbnail: r.thumbnail,
            source: r.url,
            title: r.title,
            width: r.width,
            height: r.height,
            engine: "ddg".into(),
        })
        .collect()
}
```

**Step 4: Run tests**

Run: `cd ~/src/ox-browser && cargo test -p ox-imagesearch -- ddg`
Expected: 4 tests PASS

**Step 5: Commit**

```bash
git add crates/imagesearch/src/ddg.rs
git commit -m "feat(imagesearch): add DDG Images engine with vqd+i.js parser"
```

---

## Task 4: Fusion engine (parallel + WRR merge)

**Files:**
- Create: `crates/imagesearch/src/fusion.rs`

**Step 1: Write fusion tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuse_wrr_dedup_by_url() {
        let set_a = vec![
            ImageResult { url: "https://a.com/1.jpg".into(), engine: "bing".into(), ..Default::default() },
            ImageResult { url: "https://a.com/2.jpg".into(), engine: "bing".into(), ..Default::default() },
        ];
        let set_b = vec![
            ImageResult { url: "https://a.com/1.jpg".into(), engine: "ddg".into(), title: "DDG title".into(), ..Default::default() },
            ImageResult { url: "https://b.com/3.jpg".into(), engine: "ddg".into(), ..Default::default() },
        ];
        let fused = fuse_wrr(vec![set_a, set_b]);
        assert_eq!(fused.len(), 3);
        // URL 1.jpg appears in both → highest score → first
        assert_eq!(fused[0].url, "https://a.com/1.jpg");
    }

    #[test]
    fn fuse_wrr_empty() {
        assert!(fuse_wrr(vec![]).is_empty());
        assert!(fuse_wrr(vec![vec![]]).is_empty());
    }
}
```

**Step 2: Add Default derive to ImageResult (in lib.rs)**

Add `#[derive(Default)]` to `ImageResult`.

**Step 3: Implement fusion**

```rust
// crates/imagesearch/src/fusion.rs
use std::collections::HashMap;
use std::sync::Arc;

use tokio::task::JoinSet;
use tracing;

use crate::{ImageEngine, ImageResult};
use ox_http::HttpClient;

const RRF_K: f64 = 60.0;

/// Multi-engine image search with parallel execution and WRR fusion.
pub struct ImageSearchEngine {
    engines: Vec<Arc<dyn ImageEngine>>,
}

impl ImageSearchEngine {
    pub fn new(engines: Vec<Arc<dyn ImageEngine>>) -> Self {
        Self { engines }
    }

    /// Search all engines in parallel and fuse results.
    pub async fn search(&self, client: &HttpClient, query: &str, max: usize) -> Vec<ImageResult> {
        let mut set = JoinSet::new();

        for engine in &self.engines {
            let engine = Arc::clone(engine);
            let client_ref = client.clone();
            let query = query.to_owned();
            set.spawn(async move {
                match engine.search(&client_ref, &query, max).await {
                    Ok(results) => results,
                    Err(e) => {
                        tracing::warn!(engine = engine.name(), error = %e, "image search failed");
                        Vec::new()
                    }
                }
            });
        }

        let mut all_sets = Vec::new();
        while let Some(Ok(results)) = set.join_next().await {
            all_sets.push(results);
        }

        let mut fused = fuse_wrr(all_sets);
        fused.truncate(max);
        fused
    }
}

/// Weighted Reciprocal Rank Fusion — merge results from multiple engines,
/// dedup by URL, accumulate rank-based scores.
pub fn fuse_wrr(result_sets: Vec<Vec<ImageResult>>) -> Vec<ImageResult> {
    if result_sets.is_empty() {
        return Vec::new();
    }

    let mut scores: HashMap<String, (ImageResult, f64)> = HashMap::new();
    let mut order: Vec<String> = Vec::new();

    for set in &result_sets {
        for (rank, r) in set.iter().enumerate() {
            if r.url.is_empty() {
                continue;
            }
            let rrf = 1.0 / (RRF_K + rank as f64);
            if let Some(entry) = scores.get_mut(&r.url) {
                entry.1 += rrf;
            } else {
                order.push(r.url.clone());
                scores.insert(r.url.clone(), (r.clone(), rrf));
            }
        }
    }

    let mut merged: Vec<(ImageResult, f64)> = order
        .into_iter()
        .filter_map(|url| scores.remove(&url))
        .collect();
    merged.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    merged.into_iter().map(|(r, _)| r).collect()
}
```

**Step 4: Make HttpClient cloneable**

Check if `HttpClient` already derives `Clone`. If not, the fusion code needs `Arc<HttpClient>` instead. The `search` signature should take `&HttpClient`. Since `handler` is `Arc<dyn Handler>`, clone works on the `Arc`. We may need to wrap with `Arc<HttpClient>` — adjust accordingly during implementation.

**Step 5: Run tests**

Run: `cd ~/src/ox-browser && cargo test -p ox-imagesearch -- fusion`
Expected: 2 tests PASS

**Step 6: Commit**

```bash
git add crates/imagesearch/src/fusion.rs crates/imagesearch/src/lib.rs
git commit -m "feat(imagesearch): add parallel fusion engine with WRR merge"
```

---

## Task 5: REST endpoint for image search

**Files:**
- Create: `crates/js/src/image_search.rs`
- Modify: `crates/js/src/lib.rs` (add module + route)
- Modify: `crates/js/Cargo.toml` (add `ox-imagesearch` dep)

**Step 1: Add dep to Cargo.toml**

In `crates/js/Cargo.toml`, add: `ox-imagesearch = { path = "../imagesearch" }`

**Step 2: Create image_search.rs**

```rust
// crates/js/src/image_search.rs
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_imagesearch::{ImageResult, ImageSearchEngine};
use serde::{Deserialize, Serialize};

use super::AppState;

#[derive(Deserialize)]
pub struct ImageSearchRequest {
    pub query: String,
    #[serde(default = "default_max")]
    pub max_results: usize,
    #[serde(default)]
    pub engines: Vec<String>,
}

fn default_max() -> usize {
    10
}

#[derive(Serialize)]
pub struct ImageSearchResponse {
    pub images: Vec<ImageResult>,
    pub engines_used: Vec<String>,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn image_search(
    State(state): State<AppState>,
    Json(req): Json<ImageSearchRequest>,
) -> (StatusCode, Json<ImageSearchResponse>) {
    let start = Instant::now();

    let search_engine = build_search_engine(&req.engines);
    let engine_names: Vec<String> = search_engine_names(&req.engines);

    let results = search_engine.search(&state.http_client, &req.query, req.max_results).await;

    (
        StatusCode::OK,
        Json(ImageSearchResponse {
            images: results,
            engines_used: engine_names,
            elapsed_ms: start.elapsed().as_millis() as u64,
            error: None,
        }),
    )
}

fn build_search_engine(requested: &[String]) -> ImageSearchEngine {
    use ox_imagesearch::{bing::BingImages, ddg::DdgImages};
    let mut engines: Vec<Arc<dyn ox_imagesearch::ImageEngine>> = Vec::new();

    let use_all = requested.is_empty();
    if use_all || requested.iter().any(|e| e == "bing") {
        engines.push(Arc::new(BingImages));
    }
    if use_all || requested.iter().any(|e| e == "ddg") {
        engines.push(Arc::new(DdgImages));
    }
    ImageSearchEngine::new(engines)
}

fn search_engine_names(requested: &[String]) -> Vec<String> {
    if requested.is_empty() {
        vec!["bing".into(), "ddg".into()]
    } else {
        requested.clone().to_vec()
    }
}
```

**Step 3: Add route to lib.rs**

In `crates/js/src/lib.rs`:
- Add `mod image_search;`
- Add `.route("/images/search", post(image_search::image_search))` to the router

**Step 4: Verify compilation**

Run: `cd ~/src/ox-browser && cargo check -p ox-js`

**Step 5: Commit**

```bash
git add crates/js/ crates/imagesearch/
git commit -m "feat(js): add POST /images/search REST endpoint"
```

---

## Task 6: MCP tool for image search

**Files:**
- Create: `crates/mcp/src/tools/image_search.rs`
- Modify: `crates/mcp/src/tools/mod.rs` (add module + tool registration)
- Modify: `crates/mcp/Cargo.toml` (add `ox-imagesearch` dep)

**Step 1: Add dep**

In `crates/mcp/Cargo.toml`, add: `ox-imagesearch = { path = "../imagesearch" }`

**Step 2: Create MCP tool handler**

```rust
// crates/mcp/src/tools/image_search.rs
use std::sync::Arc;
use std::time::Instant;

use ox_imagesearch::{bing::BingImages, ddg::DdgImages, fusion::ImageSearchEngine, ImageEngine};
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};

use rmcp::schemars;
use schemars::JsonSchema;

use super::OxMcpServer;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImageSearchInput {
    /// Search query for images.
    pub query: String,
    /// Engines to use: "bing", "ddg". Default: all.
    #[serde(default)]
    pub engines: Vec<String>,
    /// Maximum results to return. Default: 10.
    #[serde(default = "default_max")]
    pub max_results: usize,
}

fn default_max() -> usize {
    10
}

#[derive(Serialize)]
struct ImageSearchResult {
    images: Vec<ox_imagesearch::ImageResult>,
    engines_used: Vec<String>,
    elapsed_ms: u64,
}

impl OxMcpServer {
    pub(crate) async fn do_image_search(
        &self,
        input: ImageSearchInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();

        let mut engines: Vec<Arc<dyn ImageEngine>> = Vec::new();
        let use_all = input.engines.is_empty();
        if use_all || input.engines.iter().any(|e| e == "bing") {
            engines.push(Arc::new(BingImages));
        }
        if use_all || input.engines.iter().any(|e| e == "ddg") {
            engines.push(Arc::new(DdgImages));
        }

        let engine_names: Vec<String> = engines.iter().map(|e| e.name().to_owned()).collect();
        let search = ImageSearchEngine::new(engines);
        let images = search.search(&self.http_client, &input.query, input.max_results).await;

        let result = ImageSearchResult {
            images,
            engines_used: engine_names,
            elapsed_ms: start.elapsed().as_millis() as u64,
        };
        let json = serde_json::to_string(&result)
            .unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
```

**Step 3: Register tool in mod.rs**

In `crates/mcp/src/tools/mod.rs`:
- Add `mod image_search;`
- Add `pub use image_search::ImageSearchInput;`
- Add new `#[tool]` block in `#[tool_router] impl OxMcpServer`:

```rust
#[tool(
    name = "image_search",
    description = "Search for images across multiple engines (Bing, DDG) with stealth TLS fingerprinting and proxy rotation. Returns image URLs, thumbnails, and source pages. Results are fused and deduplicated across engines."
)]
async fn image_search(
    &self,
    Parameters(input): Parameters<ImageSearchInput>,
) -> Result<CallToolResult, McpError> {
    self.do_image_search(input).await
}
```

**Step 4: Verify compilation + test**

Run: `cd ~/src/ox-browser && cargo check -p ox-mcp && cargo test -p ox-imagesearch`

**Step 5: Commit**

```bash
git add crates/mcp/ crates/imagesearch/
git commit -m "feat(mcp): add image_search MCP tool (6th tool)"
```

---

## Task 7: Build and deploy ox-browser

**Step 1: Run all tests**

Run: `cd ~/src/ox-browser && cargo test`
Expected: all tests pass (existing 220+ and new ~9)

**Step 2: Run clippy**

Run: `cd ~/src/ox-browser && cargo clippy --workspace -- -D warnings`

**Step 3: Deploy**

```bash
cd ~/deploy/krolik-server && docker compose build --no-cache ox-browser && docker compose up -d --no-deps --force-recreate ox-browser
```

**Step 4: Smoke test REST endpoint**

```bash
curl -s -X POST http://127.0.0.1:8901/images/search \
  -H 'Content-Type: application/json' \
  -d '{"query":"кот на крыше","max_results":3}' | jq .
```

Expected: JSON with `images` array, `engines_used`, `elapsed_ms`

**Step 5: Commit tag**

```bash
git tag v0.4.6
```

---

## Task 8: go-imagefy — OxBrowserProvider

**Files:**
- Create: `~/src/go-imagefy/provider_ox.go`
- Create: `~/src/go-imagefy/provider_ox_test.go`

**Step 1: Write failing test**

```go
// provider_ox_test.go
package imagefy

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestOxBrowserProvider_Search(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/images/search" {
            t.Errorf("unexpected path: %s", r.URL.Path)
        }
        if r.Method != http.MethodPost {
            t.Errorf("unexpected method: %s", r.Method)
        }
        var req struct {
            Query      string   `json:"query"`
            MaxResults int      `json:"max_results"`
            Engines    []string `json:"engines"`
        }
        json.NewDecoder(r.Body).Decode(&req)
        if req.Query != "test query" {
            t.Errorf("unexpected query: %s", req.Query)
        }

        resp := map[string]any{
            "images": []map[string]any{
                {"url": "https://img.com/1.jpg", "thumbnail": "https://th.com/1.jpg", "source": "https://page.com/1", "title": "Image 1", "engine": "bing"},
                {"url": "https://img.com/2.jpg", "thumbnail": "https://th.com/2.jpg", "source": "https://page.com/2", "title": "Image 2", "engine": "ddg"},
            },
            "engines_used": []string{"bing", "ddg"},
            "elapsed_ms":   150,
        }
        json.NewEncoder(w).Encode(resp)
    }))
    defer srv.Close()

    p := &OxBrowserProvider{BaseURL: srv.URL, Client: srv.Client()}
    results, err := p.Search(context.Background(), "test query", SearchOpts{})
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(results) != 2 {
        t.Fatalf("expected 2 results, got %d", len(results))
    }
    if results[0].ImgURL != "https://img.com/1.jpg" {
        t.Errorf("unexpected url: %s", results[0].ImgURL)
    }
    if results[1].Source != "https://page.com/2" {
        t.Errorf("unexpected source: %s", results[1].Source)
    }
}

func TestOxBrowserProvider_Name(t *testing.T) {
    p := &OxBrowserProvider{}
    if p.Name() != "ox-browser" {
        t.Errorf("unexpected name: %s", p.Name())
    }
}

func TestOxBrowserProvider_ServerDown(t *testing.T) {
    p := &OxBrowserProvider{BaseURL: "http://127.0.0.1:1", Client: &http.Client{}}
    _, err := p.Search(context.Background(), "test", SearchOpts{})
    if err == nil {
        t.Fatal("expected error for unreachable server")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd ~/src/go-imagefy && go test -run OxBrowser -v`
Expected: FAIL — `OxBrowserProvider` not defined

**Step 3: Implement OxBrowserProvider**

```go
// provider_ox.go
package imagefy

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
)

// OxBrowserProvider searches images via ox-browser REST API.
// Delegates scraping to Rust backend (wreq+BoringSSL, proxy rotation, CF bypass).
type OxBrowserProvider struct {
    BaseURL    string       // e.g. "http://ox-browser:8901"
    Engines    []string     // e.g. ["bing", "ddg"]; empty = all
    MaxResults int          // default: 10
    Client     *http.Client // optional (nil = http.DefaultClient)
}

// Name returns the provider name.
func (p *OxBrowserProvider) Name() string { return "ox-browser" }

type oxSearchRequest struct {
    Query      string   `json:"query"`
    MaxResults int      `json:"max_results"`
    Engines    []string `json:"engines,omitempty"`
}

type oxImageResult struct {
    URL       string `json:"url"`
    Thumbnail string `json:"thumbnail"`
    Source    string `json:"source"`
    Title     string `json:"title"`
    Width     int    `json:"width"`
    Height    int    `json:"height"`
    Engine    string `json:"engine"`
}

type oxSearchResponse struct {
    Images []oxImageResult `json:"images"`
}

// Search calls ox-browser POST /images/search and converts results to ImageCandidate.
func (p *OxBrowserProvider) Search(ctx context.Context, query string, _ SearchOpts) ([]ImageCandidate, error) {
    maxResults := p.MaxResults
    if maxResults <= 0 {
        maxResults = 10
    }
    reqBody, _ := json.Marshal(oxSearchRequest{
        Query:      query,
        MaxResults: maxResults,
        Engines:    p.Engines,
    })

    url := p.BaseURL + "/images/search"
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
    if err != nil {
        return nil, fmt.Errorf("ox-browser: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")

    client := p.Client
    if client == nil {
        client = http.DefaultClient
    }
    resp, err := client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("ox-browser request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("ox-browser status %d", resp.StatusCode)
    }

    var oxResp oxSearchResponse
    if err := json.NewDecoder(resp.Body).Decode(&oxResp); err != nil {
        return nil, fmt.Errorf("ox-browser decode: %w", err)
    }

    candidates := make([]ImageCandidate, 0, len(oxResp.Images))
    for _, img := range oxResp.Images {
        if img.URL == "" || IsLogoOrBanner(img.URL) {
            continue
        }
        license := CheckLicense(img.URL, img.Source)
        if license == LicenseBlocked {
            continue
        }
        candidates = append(candidates, ImageCandidate{
            ImgURL:    img.URL,
            Thumbnail: img.Thumbnail,
            Source:    img.Source,
            Title:     img.Title,
            License:   license,
        })
    }
    return candidates, nil
}
```

**Step 4: Run tests**

Run: `cd ~/src/go-imagefy && go test -run OxBrowser -v`
Expected: 3 tests PASS

**Step 5: Commit**

```bash
cd ~/src/go-imagefy && git add provider_ox.go provider_ox_test.go
git commit -m "feat: add OxBrowserProvider for Rust-based image search"
```

---

## Task 9: go-imagefy — parallel gatherCandidates

**Files:**
- Modify: `~/src/go-imagefy/search.go:88-99` (gatherCandidates)

**Step 1: Modify gatherCandidates**

Replace the sequential loop with parallel goroutines:

```go
func (cfg *Config) gatherCandidates(ctx context.Context, providers []SearchProvider, query string, opts SearchOpts) []ImageCandidate {
    if len(providers) == 1 {
        results, err := providers[0].Search(ctx, query, opts)
        if err != nil {
            slog.Warn("imagefy: provider search failed", "provider", providers[0].Name(), "error", err.Error())
            return nil
        }
        return results
    }

    var mu sync.Mutex
    var all []ImageCandidate
    var wg sync.WaitGroup

    for _, p := range providers {
        wg.Add(1)
        go func(p SearchProvider) {
            defer wg.Done()
            results, err := p.Search(ctx, query, opts)
            if err != nil {
                slog.Warn("imagefy: provider search failed", "provider", p.Name(), "error", err.Error())
                return
            }
            mu.Lock()
            all = append(all, results...)
            mu.Unlock()
        }(p)
    }
    wg.Wait()
    return all
}
```

**Step 2: Run existing tests**

Run: `cd ~/src/go-imagefy && go test ./... -count=1`
Expected: all existing tests pass (parallel change is backward-compatible)

**Step 3: Commit**

```bash
cd ~/src/go-imagefy && git add search.go
git commit -m "perf: parallelize gatherCandidates across providers"
```

---

## Task 10: go-imagefy — FallbackProvider

**Files:**
- Create: `~/src/go-imagefy/orchestrator.go`
- Create: `~/src/go-imagefy/orchestrator_test.go`

**Step 1: Write test**

```go
// orchestrator_test.go
package imagefy

import (
    "context"
    "errors"
    "testing"
)

type failingProvider struct{ name string }

func (f *failingProvider) Search(context.Context, string, SearchOpts) ([]ImageCandidate, error) {
    return nil, errors.New("down")
}
func (f *failingProvider) Name() string { return f.name }

type staticProvider struct {
    name    string
    results []ImageCandidate
}

func (s *staticProvider) Search(context.Context, string, SearchOpts) ([]ImageCandidate, error) {
    return s.results, nil
}
func (s *staticProvider) Name() string { return s.name }

func TestFallbackProvider_FirstSucceeds(t *testing.T) {
    p := &FallbackProvider{Providers: []SearchProvider{
        &staticProvider{name: "a", results: []ImageCandidate{{ImgURL: "http://a.jpg"}}},
        &staticProvider{name: "b", results: []ImageCandidate{{ImgURL: "http://b.jpg"}}},
    }}
    res, err := p.Search(context.Background(), "q", SearchOpts{})
    if err != nil {
        t.Fatal(err)
    }
    if len(res) != 1 || res[0].ImgURL != "http://a.jpg" {
        t.Errorf("expected result from first provider, got %v", res)
    }
}

func TestFallbackProvider_FirstFails(t *testing.T) {
    p := &FallbackProvider{Providers: []SearchProvider{
        &failingProvider{name: "broken"},
        &staticProvider{name: "backup", results: []ImageCandidate{{ImgURL: "http://backup.jpg"}}},
    }}
    res, err := p.Search(context.Background(), "q", SearchOpts{})
    if err != nil {
        t.Fatal(err)
    }
    if len(res) != 1 || res[0].ImgURL != "http://backup.jpg" {
        t.Errorf("expected fallback result, got %v", res)
    }
}

func TestFallbackProvider_AllFail(t *testing.T) {
    p := &FallbackProvider{Providers: []SearchProvider{
        &failingProvider{name: "a"},
        &failingProvider{name: "b"},
    }}
    _, err := p.Search(context.Background(), "q", SearchOpts{})
    if err == nil {
        t.Fatal("expected error when all providers fail")
    }
}
```

**Step 2: Run test (should fail)**

Run: `cd ~/src/go-imagefy && go test -run Fallback -v`

**Step 3: Implement**

```go
// orchestrator.go
package imagefy

import (
    "context"
    "errors"
    "fmt"
)

// FallbackProvider tries providers in order, returning the first successful result.
type FallbackProvider struct {
    Providers []SearchProvider
}

// Name returns the orchestrator name.
func (f *FallbackProvider) Name() string { return "fallback" }

// Search tries each provider sequentially, returning the first success.
func (f *FallbackProvider) Search(ctx context.Context, query string, opts SearchOpts) ([]ImageCandidate, error) {
    var errs []error
    for _, p := range f.Providers {
        results, err := p.Search(ctx, query, opts)
        if err == nil {
            return results, nil
        }
        errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
    }
    return nil, fmt.Errorf("all providers failed: %w", errors.Join(errs...))
}
```

**Step 4: Run tests**

Run: `cd ~/src/go-imagefy && go test -run Fallback -v`
Expected: 3 tests PASS

**Step 5: Run full suite**

Run: `cd ~/src/go-imagefy && go test ./... -count=1`

**Step 6: Commit + tag**

```bash
cd ~/src/go-imagefy && git add orchestrator.go orchestrator_test.go
git commit -m "feat: add FallbackProvider orchestrator"
```

---

## Task 11: go-wp — update imageadapter + fix upload.go

**Files:**
- Modify: `~/src/go-wp/internal/imageadapter/adapter.go`
- Modify: `~/src/go-wp/internal/wptools/media/upload.go` (fix http.DefaultClient)

**Step 1: Update imageadapter**

In `adapter.go`, change `Init` to add OxBrowserProvider as primary, keep DDG as fallback, add Pexels:

```go
func Init(/* existing params + */ oxBrowserURL string, pexelsAPIKey string) {
    imagefyCfgOnce.Do(func() {
        var providers []imagefy.SearchProvider

        // Primary: ox-browser (Rust, stealth scraping)
        if oxBrowserURL != "" {
            providers = append(providers, &imagefy.OxBrowserProvider{
                BaseURL:    oxBrowserURL,
                Engines:    []string{"bing", "ddg"},
                MaxResults: 15,
                Client:     httpClient,
            })
        }

        // Openverse: CC/public-domain images
        providers = append(providers, &imagefy.OpenverseProvider{
            HTTPClient: httpClient,
        })

        // Pexels (if API key configured)
        if pexelsAPIKey != "" {
            providers = append(providers, &imagefy.PexelsProvider{
                APIKey:     pexelsAPIKey,
                HTTPClient: httpClient,
            })
        }

        // Fallback: DDG via go-stealth proxy
        ddgClient := stealthClient
        if ddgClient == nil {
            ddgClient = httpClient
        }
        providers = append(providers, &imagefy.DDGImageProvider{
            HTTPClient: ddgClient,
        })

        imagefyCfg = &imagefy.Config{
            Cache:         &goeCacheAdapter{c: cache, ttl: cacheTTL},
            Classifier:    &goeLLMClassifier{llm: llm},
            StealthClient: stealthClient,
            HTTPClient:    httpClient,
            Providers:     providers,
            OnImageSearch: func() { metrics.Incr("image_searches") },
        }
    })
}
```

**Step 2: Update Init callers**

Find where `imageadapter.Init()` is called (likely `wpserver/register.go`) and pass the new params:
- `os.Getenv("OX_BROWSER_URL")` (e.g. `http://ox-browser:8901`)
- `os.Getenv("PEXELS_API_KEY")`

**Step 3: Fix upload.go**

In `upload.go`, find where `http.DefaultClient` is used for downloading images and replace with the stealth client from the package-level var. The stealth client should be passed through the same mechanism as other clients.

**Step 4: Add env vars to docker-compose**

In `~/deploy/krolik-server/docker-compose.yml`, add to go-wp service:
```yaml
environment:
  - OX_BROWSER_URL=http://ox-browser:8901
  - PEXELS_API_KEY=${PEXELS_API_KEY}
```

**Step 5: Test compilation**

Run: `cd ~/src/go-wp && go build ./...`

**Step 6: Deploy and test**

```bash
cd ~/deploy/krolik-server && docker compose build --no-cache go-wp && docker compose up -d --no-deps --force-recreate go-wp
```

Test via MCP: `wp_image action=resolve query="кот на крыше" max_results=3`

**Step 7: Commit**

```bash
cd ~/src/go-wp && git add internal/imageadapter/ internal/wptools/media/
git commit -m "feat: wire ox-browser as primary image search provider, add Pexels, fix upload proxy"
```

---

## Summary

| Task | Repo | What | Est. LOC |
|------|------|------|----------|
| 1 | ox-browser | Crate scaffold | 40 |
| 2 | ox-browser | Bing engine | 90 |
| 3 | ox-browser | DDG engine | 100 |
| 4 | ox-browser | Fusion + WRR | 70 |
| 5 | ox-browser | REST endpoint | 60 |
| 6 | ox-browser | MCP tool | 60 |
| 7 | ox-browser | Build + deploy | — |
| 8 | go-imagefy | OxBrowserProvider | 80 |
| 9 | go-imagefy | Parallel gather | 20 |
| 10 | go-imagefy | FallbackProvider | 30 |
| 11 | go-wp | Wire + fix | 40 |

**Total new code:** ~590 LOC + ~350 LOC tests
