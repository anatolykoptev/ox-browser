# Reverse Image Search Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add reverse image search to ox-browser — submit image URL, get list of pages where image appears. Primary use: detect "laundered" stock photos.

**Architecture:** New `ox-reverse` crate with `ReverseEngine` trait (mirrors `ImageEngine`). Two engines: Google Lens (URL mode) and Yandex Images (URL mode). Fusion collects results from both, deduplicates, checks domains against stock photo list. REST `POST /images/reverse` + MCP `reverse_image_search` tool.

**Tech Stack:** Rust, wreq+BoringSSL, dom_query, regex, serde, async-trait, tokio JoinSet.

---

### Task 1: Create ox-reverse crate with types and trait

**Files:**
- Create: `crates/reverse/Cargo.toml`
- Create: `crates/reverse/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

**Step 1: Create Cargo.toml**

```toml
[package]
name = "ox-reverse"
version = "0.1.0"
edition = "2024"

[dependencies]
ox-http = { path = "../http" }
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
regex = "1"
tokio = { version = "1", features = ["rt"] }
url = "2"
dom_query = "0.14"
tracing = "0.1"

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

**Step 2: Create lib.rs with core types and trait**

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A single match from reverse image search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseMatch {
    /// URL of the page where the image was found.
    pub page_url: String,
    /// Page title.
    pub title: String,
    /// Thumbnail URL (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<String>,
    /// Domain extracted from page_url.
    pub domain: String,
    /// Which engine found this match.
    pub engine: String,
}

/// Aggregated result from reverse image search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseResult {
    /// All matching pages.
    pub matches: Vec<ReverseMatch>,
    /// Whether any match domain is a known stock photo site.
    pub is_stock: bool,
    /// Stock domains found (empty if is_stock=false).
    pub stock_domains: Vec<String>,
    /// Engines that were used.
    pub engines_used: Vec<String>,
    /// Search time in milliseconds.
    pub elapsed_ms: u64,
}

/// Trait for reverse image search engines.
#[async_trait]
pub trait ReverseEngine: Send + Sync {
    /// Search for pages containing the image at the given URL.
    async fn search(
        &self,
        client: &ox_http::HttpClient,
        image_url: &str,
        max: usize,
    ) -> Result<Vec<ReverseMatch>>;

    /// Engine name for logging and response metadata.
    fn name(&self) -> &str;
}

/// Stock photo domains to check against reverse search results.
const STOCK_DOMAINS: &[&str] = &[
    "shutterstock", "gettyimages", "istockphoto", "adobestock",
    "depositphotos", "dreamstime", "123rf", "alamy", "bigstockphoto",
    "stocksy", "pond5", "masterfile", "superstock", "agefotostock",
    "colourbox", "yayimages", "vectorstock", "freepik", "canstockphoto",
    "loriimages", "fotobank",
];

/// Check if a domain matches any known stock photo site.
pub fn is_stock_domain(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    STOCK_DOMAINS.iter().any(|s| lower.contains(s))
}

#[derive(Debug)]
pub enum Error {
    Http(ox_http::HttpError),
    Parse(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "http: {e}"),
            Self::Parse(msg) => write!(f, "parse: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ox_http::HttpError> for Error {
    fn from(e: ox_http::HttpError) -> Self {
        Self::Http(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

mod google_lens;
mod yandex;
mod fusion;

pub use fusion::ReverseSearchEngine;
pub use google_lens::GoogleLens;
pub use yandex::YandexImages;
```

**Step 3: Add to workspace**

In root `Cargo.toml`, add `"crates/reverse"` to `[workspace] members`.

**Step 4: Verify it compiles**

```bash
cargo check -p ox-reverse
```

Expected: compile errors for missing modules (google_lens, yandex, fusion) — that's fine, we create them next.

**Step 5: Commit**

```bash
git add crates/reverse/ Cargo.toml
git commit -m "feat(reverse): add ox-reverse crate with types and trait"
```

---

### Task 2: Implement Google Lens engine

**Files:**
- Create: `crates/reverse/src/google_lens.rs`

**Step 1: Write the engine**

Google Lens URL-mode flow:
1. `GET https://lens.google.com/uploadbyurl?url={encoded}&hl=en&gl=us`
2. Response is HTML with `AF_initDataCallback` script tags containing nested JSON arrays
3. Parse matching page URLs, titles, thumbnails from the JSON data

Key parsing:
- Find `AF_initDataCallback({key: 'ds:1', data:...})` in script tags
- Data is nested arrays — results at specific indices (fragile, needs offline fixtures)
- Fallback: use dom_query to find result links in rendered HTML

```rust
use async_trait::async_trait;
use dom_query::Document;
use regex::Regex;
use std::sync::LazyLock;

use crate::{Error, Result, ReverseEngine, ReverseMatch};

pub struct GoogleLens;

static AF_DATA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"AF_initDataCallback\(\{[^}]*key:\s*'ds:1'[^}]*data:(\[[\s\S]*?\])\s*\}\)"#)
        .expect("valid regex")
});

#[async_trait]
impl ReverseEngine for GoogleLens {
    async fn search(
        &self,
        client: &ox_http::HttpClient,
        image_url: &str,
        max: usize,
    ) -> Result<Vec<ReverseMatch>> {
        let url = format!(
            "https://lens.google.com/uploadbyurl?url={}&hl=en&gl=us",
            urlencoding::encode(image_url)
        );

        let resp = client.get(&url).await?;
        let html = &resp.body;

        let mut results = parse_lens_html(html);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "google_lens"
    }
}
```

Parse results from HTML using two strategies:
1. Try `AF_initDataCallback` JSON extraction
2. Fallback: DOM links with `data-action-url` or result containers

**Step 2: Add unit tests with offline HTML fixture**

Save a real Google Lens response HTML as test fixture, write tests for parsing.

**Step 3: Verify**

```bash
cargo test -p ox-reverse -- google_lens
```

**Step 4: Commit**

```bash
git add crates/reverse/src/google_lens.rs
git commit -m "feat(reverse): add Google Lens engine (URL mode)"
```

---

### Task 3: Implement Yandex Images engine

**Files:**
- Create: `crates/reverse/src/yandex.rs`

**Step 1: Write the engine**

Yandex URL-only flow:
1. `GET https://yandex.com/images/search/?rpt=imageview&url={image_url}`
2. Must include Client Hints headers (Yandex blocks without them)
3. Parse HTML: find elements with `data-bem` attribute containing `serp-item` JSON
4. Extract page URLs, titles from the parsed JSON

Required headers:
```
sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="131"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-site: same-origin
sec-fetch-mode: navigate
device-memory: 8
ect: 4g
```

**Step 2: Add unit tests with offline HTML fixture**

**Step 3: Verify**

```bash
cargo test -p ox-reverse -- yandex
```

**Step 4: Commit**

```bash
git add crates/reverse/src/yandex.rs
git commit -m "feat(reverse): add Yandex Images engine (URL mode)"
```

---

### Task 4: Implement fusion orchestrator

**Files:**
- Create: `crates/reverse/src/fusion.rs`

**Step 1: Write fusion**

Simpler than imagesearch fusion — no WRR needed, just:
1. Run engines in parallel via `JoinSet`
2. Deduplicate by `page_url`
3. Check domains against `STOCK_DOMAINS`
4. Build `ReverseResult`

```rust
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;

use crate::{is_stock_domain, ReverseEngine, ReverseMatch, ReverseResult};

pub struct ReverseSearchEngine {
    engines: Vec<Arc<dyn ReverseEngine>>,
}

impl ReverseSearchEngine {
    pub fn new(engines: Vec<Arc<dyn ReverseEngine>>) -> Self {
        Self { engines }
    }

    pub async fn search(
        &self,
        client: Arc<ox_http::HttpClient>,
        image_url: &str,
        max: usize,
    ) -> ReverseResult {
        let start = Instant::now();
        let engine_names: Vec<String> = self.engines.iter().map(|e| e.name().to_owned()).collect();

        let mut set = JoinSet::new();
        for engine in &self.engines {
            let engine = Arc::clone(engine);
            let client = Arc::clone(&client);
            let url = image_url.to_owned();
            set.spawn(async move {
                match engine.search(&client, &url, max).await {
                    Ok(results) => results,
                    Err(e) => {
                        tracing::warn!(engine = engine.name(), error = %e, "reverse search failed");
                        Vec::new()
                    }
                }
            });
        }

        let mut all = Vec::new();
        while let Some(Ok(results)) = set.join_next().await {
            all.extend(results);
        }

        // Dedup by page_url
        let mut seen = std::collections::HashSet::new();
        all.retain(|m| seen.insert(m.page_url.clone()));
        all.truncate(max);

        // Check stock domains
        let mut stock_domains = Vec::new();
        for m in &all {
            if is_stock_domain(&m.domain) && !stock_domains.contains(&m.domain) {
                stock_domains.push(m.domain.clone());
            }
        }

        ReverseResult {
            is_stock: !stock_domains.is_empty(),
            matches: all,
            stock_domains,
            engines_used: engine_names,
            elapsed_ms: start.elapsed().as_millis() as u64,
        }
    }
}
```

**Step 2: Add unit tests**

**Step 3: Verify**

```bash
cargo test -p ox-reverse
```

**Step 4: Commit**

```bash
git add crates/reverse/src/fusion.rs
git commit -m "feat(reverse): add fusion orchestrator with stock detection"
```

---

### Task 5: Add REST endpoint

**Files:**
- Create: `crates/js/src/reverse_search.rs`
- Modify: `crates/js/src/lib.rs` (add route)

**Step 1: Write REST handler**

```rust
// POST /images/reverse
// {"url": "https://example.com/photo.jpg", "engines": ["google_lens", "yandex"], "max_results": 20}
```

Follow the same pattern as `image_search.rs`:
- Deserialize request
- Build engine list
- Call `ReverseSearchEngine::search`
- Return `ReverseResult` as JSON

**Step 2: Register route**

In `crates/js/src/lib.rs`, add:
```rust
.route("/images/reverse", post(reverse_search::reverse_search))
```

**Step 3: Verify**

```bash
cargo build --workspace
```

**Step 4: Commit**

```bash
git add crates/js/src/reverse_search.rs crates/js/src/lib.rs
git commit -m "feat(reverse): add POST /images/reverse REST endpoint"
```

---

### Task 6: Add MCP tool

**Files:**
- Create: `crates/mcp/src/tools/reverse_search.rs`
- Modify: `crates/mcp/src/tools/mod.rs` (register tool)

**Step 1: Write MCP tool**

Follow `image_search.rs` pattern — `ReverseSearchInput` struct with JsonSchema, `do_reverse_search` method on `OxMcpServer`.

**Step 2: Register in mod.rs**

Add `#[tool(name = "reverse_image_search", ...)]` to `#[tool_router]` impl.

**Step 3: Verify**

```bash
cargo build --workspace
```

**Step 4: Commit**

```bash
git add crates/mcp/src/tools/reverse_search.rs crates/mcp/src/tools/mod.rs
git commit -m "feat(reverse): add reverse_image_search MCP tool"
```

---

### Task 7: Add ox-reverse to Cargo.toml dependencies

**Files:**
- Modify: `crates/js/Cargo.toml` (add `ox-reverse` dep)
- Modify: `crates/mcp/Cargo.toml` (add `ox-reverse` dep)

**Step 1: Add deps**

```toml
ox-reverse = { path = "../reverse" }
```

**Step 2: Full build + test**

```bash
cargo test --workspace
```

**Step 3: Commit**

```bash
git add crates/js/Cargo.toml crates/mcp/Cargo.toml
git commit -m "feat(reverse): wire ox-reverse into REST and MCP crates"
```

---

### Task 8: Update CLAUDE.md and docs

**Files:**
- Modify: `CLAUDE.md` (add /images/reverse to API list, reverse_image_search to MCP tools)

**Step 1: Update CLAUDE.md**

Add `/images/reverse` to REST list, `reverse_image_search` to MCP tools list.

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add reverse image search to CLAUDE.md"
```
