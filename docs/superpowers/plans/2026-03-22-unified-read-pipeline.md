# ox-browser v0.8.0 — Unified `read` Content Pipeline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the fragmented `fetch_smart` + `readability` MCP tools with a single `read` tool that automatically handles CF bypass (via middleware), content extraction, and format selection — so agents get clean content without caring about implementation details.

**Architecture:** The HTTP client's middleware chain already handles CF detection + solving. A new shared `content` module in `ox-http` provides extraction logic and a `read_pipeline` async function that both MCP and REST call. MCP wraps the result in `CallToolResult`, REST wraps in `(StatusCode, Json<>)`. No duplication of business logic.

**Tech Stack:** Rust 1.93 (edition 2024), rmcp 1.1, readabilityrs, dom_query, htmd 0.5, axum 0.8

---

## File Structure

| Action | File | Responsibility |
|--------|------|---------------|
| Create | `crates/http/src/content.rs` | Shared types (`ReadParams`, `ReadOutput`, `ContentFormat`), extraction, quality check |
| Create | `crates/http/src/content_tests.rs` | Tests for content extraction |
| Create | `crates/http/src/read_pipeline.rs` | Shared async `read_page()` — fetch + extract + headless fallback |
| Create | `crates/http/src/read_pipeline_tests.rs` | Tests for read pipeline |
| Create | `crates/mcp/src/tools/read.rs` | MCP `read` tool — thin wrapper over `read_pipeline` |
| Create | `crates/mcp/src/tools/read_tests.rs` | Tests for MCP read tool |
| Create | `crates/js/src/read.rs` | REST `POST /read` — thin wrapper over `read_pipeline` |
| Create | `crates/js/src/read_tests.rs` | Tests for REST read endpoint |
| Create | `crates/js/src/solve.rs` | Extract solve handler from lib.rs (>200 lines fix) |
| Modify | `crates/mcp/src/tools/mod.rs` | Register `read` tool, deprecate `fetch_smart`/`readability` |
| Modify | `crates/mcp/src/tools/readability.rs` | Delegate to `content::extract_content` |
| Modify | `crates/mcp/src/tools/fetch.rs` | Remove manual CF detection from `do_fetch_smart` |
| Modify | `crates/js/src/lib.rs` | Add `/read` route, extract solve to `solve.rs` |
| Modify | `crates/http/src/lib.rs` | Export content + read_pipeline modules |
| Modify | `crates/http/Cargo.toml` | Add readabilityrs, dom_query, htmd deps |
| Modify | `Cargo.toml` (root) | Version bump 0.7.0 → 0.8.0 |
| Modify | `CLAUDE.md` | Document `read` tool |

### Out of scope
- `fetch` tool/endpoint — stays as low-level debug tool
- `crawl` — stays for multi-page crawling
- Consumer updates (go-search, go-enriche) — separate PR

---

## Task 1: Content Extraction Module (`crates/http/src/content.rs`)

Shared types and pure extraction functions. No HTTP, no async — just HTML in, content out.

**Files:**
- Create: `crates/http/src/content.rs`
- Create: `crates/http/src/content_tests.rs`
- Modify: `crates/http/src/lib.rs`
- Modify: `crates/http/Cargo.toml`

- [ ] **Step 1: Write failing tests**

Create `crates/http/src/content_tests.rs`:

```rust
use super::*;

#[test]
fn format_from_param() {
    assert_eq!(ContentFormat::from_param("text"), ContentFormat::Text);
    assert_eq!(ContentFormat::from_param("markdown"), ContentFormat::Markdown);
    assert_eq!(ContentFormat::from_param("md"), ContentFormat::Markdown);
    assert_eq!(ContentFormat::from_param("html"), ContentFormat::Html);
    assert_eq!(ContentFormat::from_param("unknown"), ContentFormat::Text);
}

#[test]
fn extracts_article_as_text() {
    let html = r#"<html><head><title>Test Article</title></head>
    <body><article><h1>Hello</h1><p>World paragraph.</p></article></body></html>"#;
    let result = extract_content(html, "https://example.com", ContentFormat::Text);
    assert!(!result.content.is_empty());
    assert_eq!(result.title, "Test Article");
    assert!(!result.content.contains('<'));
}

#[test]
fn extracts_article_as_markdown() {
    let html = r#"<html><head><title>MD Test</title></head>
    <body><article><h1>Hello</h1><p>World <a href="/link">click</a></p></article>
    <nav><a href="/">Home</a></nav></body></html>"#;
    let result = extract_content(html, "https://example.com", ContentFormat::Markdown);
    assert!(result.content.contains("Hello"), "got: {}", result.content);
    assert!(!result.content.contains("Home"), "nav should be stripped");
}

#[test]
fn extracts_article_as_html() {
    let html = r#"<html><head><title>HTML Test</title></head>
    <body><article><p>Content here</p></article></body></html>"#;
    let result = extract_content(html, "https://example.com", ContentFormat::Html);
    assert!(result.content.contains("<p>"));
}

#[test]
fn detects_low_quality_content() {
    let filler = "x".repeat(10_000);
    let html = format!(
        "<html><head><title>Block</title></head><body><script>{filler}</script><p>Please wait</p></body></html>"
    );
    assert!(is_low_quality(&html, "Please wait"));
}

#[test]
fn normal_content_is_not_low_quality() {
    let content = "A".repeat(500);
    let html = format!("<html><body><p>{content}</p></body></html>");
    assert!(!is_low_quality(&html, &content));
}

#[test]
fn truncates_with_utf8_safety() {
    let truncated = truncate_utf8("Привет мир!", 10);
    assert!(truncated.len() <= 14);
    assert!(truncated.ends_with('…'));
}

#[test]
fn empty_html_returns_empty() {
    let result = extract_content("", "https://example.com", ContentFormat::Text);
    assert!(result.content.is_empty());
}

#[test]
fn should_fallback_codes() {
    assert!(should_fallback(401));
    assert!(should_fallback(403));
    assert!(should_fallback(429));
    assert!(should_fallback(503));
    assert!(!should_fallback(200));
    assert!(!should_fallback(404));
    assert!(!should_fallback(500));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http content_tests`
Expected: FAIL — module doesn't exist

- [ ] **Step 3: Add dependencies to `crates/http/Cargo.toml`**

Add under `[dependencies]`:
```toml
readabilityrs = "0.1"
dom_query = "0.25"
htmd = "0.5"
serde = { version = "1", features = ["derive"] }
```

- [ ] **Step 4: Implement content.rs**

Create `crates/http/src/content.rs` (~140 lines):

```rust
//! Content extraction — shared types and pure functions.
//!
//! No HTTP, no async. Takes HTML string, returns clean content.

use readabilityrs::Readability;
use serde::{Deserialize, Serialize};

/// Output format for content extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentFormat {
    #[default]
    Text,
    Markdown,
    Html,
}

impl ContentFormat {
    pub fn from_param(s: &str) -> Self {
        match s {
            "markdown" | "md" => Self::Markdown,
            "html" => Self::Html,
            _ => Self::Text,
        }
    }
}

/// Shared input params for read pipeline.
#[derive(Debug, Clone, Deserialize)]
pub struct ReadParams {
    pub url: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub max_length: usize,
}

fn default_format() -> String { "text".into() }

/// Shared output from read pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct ReadOutput {
    pub title: String,
    pub content: String,
    pub author: String,
    pub excerpt: String,
    pub url: String,
    pub format: String,
    pub length: usize,
    pub method: String,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Extracted content (intermediate, before adding request metadata).
pub struct ExtractedContent {
    pub title: String,
    pub content: String,
    pub author: String,
    pub excerpt: String,
    pub length: usize,
}

/// Extract clean content from HTML.
pub fn extract_content(html: &str, url: &str, format: ContentFormat) -> ExtractedContent {
    if html.is_empty() {
        return ExtractedContent {
            title: String::new(), content: String::new(),
            author: String::new(), excerpt: String::new(), length: 0,
        };
    }
    let article = Readability::new(html, Some(url), None)
        .ok().and_then(|r| r.parse());

    match article {
        Some(a) => {
            let raw = a.content.unwrap_or_default();
            let content = convert_format(&raw, format);
            let length = content.len();
            ExtractedContent {
                title: a.title.unwrap_or_default(), content,
                author: a.byline.unwrap_or_default(),
                excerpt: a.excerpt.unwrap_or_default(), length,
            }
        }
        None => {
            let content = convert_format(html, format);
            let length = content.len();
            ExtractedContent {
                title: String::new(), content,
                author: String::new(), excerpt: String::new(), length,
            }
        }
    }
}

fn convert_format(html: &str, format: ContentFormat) -> String {
    match format {
        ContentFormat::Text => html_to_plain(html),
        ContentFormat::Markdown => html_to_fit_markdown(html),
        ContentFormat::Html => html.to_string(),
    }
}

/// Large HTML + tiny extracted text = likely anti-bot page.
pub fn is_low_quality(html: &str, extracted_text: &str) -> bool {
    html.len() > 5_000 && extracted_text.len() < 100
}

/// HTTP status codes that trigger headless fallback.
pub fn should_fallback(status: u16) -> bool {
    matches!(status, 401 | 403 | 429 | 503)
}

/// Truncate at UTF-8 char boundary, append ellipsis.
pub fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes { return s.to_string(); }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    let mut r = s[..end].to_string();
    r.push('…');
    r
}

pub fn html_to_plain(html: &str) -> String {
    let doc = dom_query::Document::from(html);
    let text = doc.select("body").text().to_string();
    collapse_whitespace(&text)
}

fn html_to_fit_markdown(html: &str) -> String {
    let doc = dom_query::Document::from(html);
    for sel in NOISE_SELECTORS { doc.select(sel).remove(); }
    htmd::convert(&doc.html()).unwrap_or_default()
}

fn collapse_whitespace(s: &str) -> String {
    let mut r = String::with_capacity(s.len());
    let mut prev = true;
    for ch in s.chars() {
        if ch.is_whitespace() { if !prev { r.push(' '); prev = true; } }
        else { r.push(ch); prev = false; }
    }
    r.trim().to_string()
}

const NOISE_SELECTORS: &[&str] = &[
    "nav","footer","header",".nav",".navbar",".footer",".sidebar",
    ".menu",".breadcrumb",".pagination",".cookie-banner",".cookie-consent",
    "#cookie-banner","[role=navigation]","[role=banner]","[role=contentinfo]",
    "script","style","noscript","iframe",
];

#[cfg(test)]
#[path = "content_tests.rs"]
mod tests;
```

- [ ] **Step 5: Export in `crates/http/src/lib.rs`**

Add:
```rust
pub mod content;
```

- [ ] **Step 6: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http content_tests -- --nocapture`
Expected: All 9 tests PASS

- [ ] **Step 7: Commit**

```bash
git add crates/http/src/content.rs crates/http/src/content_tests.rs crates/http/src/lib.rs crates/http/Cargo.toml
git commit -m "feat(http): add shared content extraction module"
```

---

## Task 2: Read Pipeline (`crates/http/src/read_pipeline.rs`)

Shared async pipeline: fetch → extract → quality check → headless fallback. Both MCP and REST call this.

**Files:**
- Create: `crates/http/src/read_pipeline.rs`
- Create: `crates/http/src/read_pipeline_tests.rs`
- Modify: `crates/http/src/lib.rs`

- [ ] **Step 1: Write tests for pipeline output construction**

Create `crates/http/src/read_pipeline_tests.rs`:

```rust
use super::*;
use crate::content::{ReadOutput, ReadParams};

#[test]
fn build_output_populates_all_fields() {
    let ext = crate::content::ExtractedContent {
        title: "T".into(), content: "C".into(),
        author: "A".into(), excerpt: "E".into(), length: 1,
    };
    let params = ReadParams { url: "https://x.com".into(), format: "text".into(), max_length: 0 };
    let out = build_output(ext, &params, "direct", 42);
    assert_eq!(out.title, "T");
    assert_eq!(out.url, "https://x.com");
    assert_eq!(out.method, "direct");
    assert_eq!(out.elapsed_ms, 42);
    assert!(out.error.is_none());
}

#[test]
fn build_error_output_has_error() {
    let params = ReadParams { url: "https://fail.com".into(), format: "text".into(), max_length: 0 };
    let out = build_error_output(&params, "direct", 10, "connection refused");
    assert_eq!(out.error.as_deref(), Some("connection refused"));
    assert!(out.content.is_empty());
}

#[test]
fn truncation_applied_when_max_length_set() {
    let ext = crate::content::ExtractedContent {
        title: "T".into(), content: "A".repeat(500),
        author: String::new(), excerpt: String::new(), length: 500,
    };
    let params = ReadParams { url: "https://x.com".into(), format: "text".into(), max_length: 50 };
    let out = build_output(ext, &params, "direct", 0);
    assert!(out.content.len() <= 55); // 50 + char boundary + ellipsis
}
```

- [ ] **Step 2: Implement read_pipeline.rs**

Create `crates/http/src/read_pipeline.rs` (~120 lines):

```rust
//! Shared read pipeline — async fetch + extract + quality fallback.
//!
//! Called by both MCP and REST layers.

use std::sync::Arc;
use std::time::Instant;

use url::Url;

use crate::content::{self, ContentFormat, ReadOutput, ReadParams};
use crate::cookie_cache::CookieCache;
use crate::cookie_provider::CookieProvider;
use crate::cloudflare::ChallengeType;
use crate::HttpClient;

/// Execute the full read pipeline: fetch → extract → quality check → headless fallback.
pub async fn read_page(
    http: &HttpClient,
    provider: &dyn CookieProvider,
    cache: &CookieCache,
    params: &ReadParams,
) -> ReadOutput {
    let start = Instant::now();
    let format = ContentFormat::from_param(&params.format);

    // Stage 1: Fetch (middleware handles CF/retry/rate-limit)
    let resp = match http.get(&params.url).await {
        Ok(r) => r,
        Err(e) => return build_error_output(params, "direct", elapsed(start), &e.to_string()),
    };

    if resp.status != 200 {
        if content::should_fallback(resp.status) {
            return headless_read(http, provider, cache, params, format, start).await;
        }
        return build_error_output(params, "direct", elapsed(start), &format!("HTTP {}", resp.status));
    }

    // Stage 2: Extract
    let extracted = content::extract_content(&resp.body, &params.url, format);

    // Stage 3: Quality check
    if content::is_low_quality(&resp.body, &extracted.content) {
        tracing::info!(url = %params.url, "low quality content, trying headless");
        return headless_read(http, provider, cache, params, format, start).await;
    }

    build_output(extracted, params, "direct", elapsed(start))
}

async fn headless_read(
    http: &HttpClient,
    provider: &dyn CookieProvider,
    cache: &CookieCache,
    params: &ReadParams,
    format: ContentFormat,
    start: Instant,
) -> ReadOutput {
    let domain = Url::parse(&params.url)
        .ok().and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default();

    let solved = match provider.solve(&params.url, ChallengeType::JsChallenge).await {
        Ok(s) => s,
        Err(e) => return build_error_output(
            params, "solved", elapsed(start), &format!("headless solve failed: {e}"),
        ),
    };
    cache.put(&domain, solved);

    match http.get(&params.url).await {
        Ok(retry) if retry.status == 200 => {
            let extracted = content::extract_content(&retry.body, &params.url, format);
            build_output(extracted, params, "solved", elapsed(start))
        }
        Ok(retry) => build_error_output(
            params, "solved", elapsed(start), &format!("HTTP {} after solve", retry.status),
        ),
        Err(e) => build_error_output(
            params, "solved", elapsed(start), &format!("retry: {e}"),
        ),
    }
}

pub fn build_output(
    ext: content::ExtractedContent, params: &ReadParams, method: &str, ms: u64,
) -> ReadOutput {
    let mut c = ext.content;
    if params.max_length > 0 { c = content::truncate_utf8(&c, params.max_length); }
    let length = c.len();
    ReadOutput {
        title: ext.title, content: c, author: ext.author, excerpt: ext.excerpt,
        url: params.url.clone(), format: params.format.clone(), length,
        method: method.into(), elapsed_ms: ms, error: None,
    }
}

pub fn build_error_output(params: &ReadParams, method: &str, ms: u64, msg: &str) -> ReadOutput {
    ReadOutput {
        title: String::new(), content: String::new(), author: String::new(),
        excerpt: String::new(), url: params.url.clone(), format: params.format.clone(),
        length: 0, method: method.into(), elapsed_ms: ms, error: Some(msg.into()),
    }
}

fn elapsed(start: Instant) -> u64 { start.elapsed().as_millis() as u64 }

#[cfg(test)]
#[path = "read_pipeline_tests.rs"]
mod tests;
```

- [ ] **Step 3: Export in lib.rs**

Add to `crates/http/src/lib.rs`:
```rust
pub mod read_pipeline;
```

- [ ] **Step 4: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http read_pipeline_tests -- --nocapture`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/http/src/read_pipeline.rs crates/http/src/read_pipeline_tests.rs crates/http/src/lib.rs
git commit -m "feat(http): add shared read pipeline (fetch + extract + headless fallback)"
```

---

## Task 3: MCP `read` Tool

Thin wrapper: deserializes MCP input → calls `read_pipeline::read_page()` → wraps in `CallToolResult`.

**Files:**
- Create: `crates/mcp/src/tools/read.rs`
- Create: `crates/mcp/src/tools/read_tests.rs`
- Modify: `crates/mcp/src/tools/mod.rs`

- [ ] **Step 1: Write tests for MCP-specific serialization**

Create `crates/mcp/src/tools/read_tests.rs`:

```rust
use ox_http::content::{ReadOutput, ReadParams};

#[test]
fn read_params_defaults() {
    let json = r#"{"url": "https://example.com"}"#;
    let p: ReadParams = serde_json::from_str(json).unwrap();
    assert_eq!(p.format, "text");
    assert_eq!(p.max_length, 0);
}

#[test]
fn read_output_skips_none_error() {
    let out = ReadOutput {
        title: "T".into(), content: "C".into(), author: String::new(),
        excerpt: String::new(), url: "https://x.com".into(),
        format: "text".into(), length: 1, method: "direct".into(),
        elapsed_ms: 50, error: None,
    };
    let json = serde_json::to_value(&out).unwrap();
    assert!(!json.as_object().unwrap().contains_key("error"));
}

#[test]
fn read_output_includes_error() {
    let out = ReadOutput {
        title: String::new(), content: String::new(), author: String::new(),
        excerpt: String::new(), url: "https://fail.com".into(),
        format: "text".into(), length: 0, method: "direct".into(),
        elapsed_ms: 10, error: Some("fail".into()),
    };
    let json = serde_json::to_value(&out).unwrap();
    assert_eq!(json["error"], "fail");
}
```

- [ ] **Step 2: Implement read.rs**

Create `crates/mcp/src/tools/read.rs` (~55 lines):

```rust
//! MCP tool: read — unified content extraction.
//!
//! Thin wrapper over `ox_http::read_pipeline::read_page`.

use ox_http::content::ReadParams;
use ox_http::read_pipeline;
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use rmcp::schemars::{self, JsonSchema};
use serde::Deserialize;

use super::OxMcpServer;

/// Input for the `read` MCP tool (extends ReadParams with JsonSchema).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadInput {
    /// URL to read content from.
    pub url: String,
    /// Output format: "text" (default), "markdown", or "html".
    #[serde(default = "default_format")]
    pub format: String,
    /// Max content length in chars. 0 = unlimited.
    #[serde(default)]
    pub max_length: usize,
}

fn default_format() -> String { "text".into() }

impl From<ReadInput> for ReadParams {
    fn from(i: ReadInput) -> Self {
        Self { url: i.url, format: i.format, max_length: i.max_length }
    }
}

impl OxMcpServer {
    pub(crate) async fn do_read(
        &self,
        input: ReadInput,
    ) -> Result<CallToolResult, McpError> {
        let params: ReadParams = input.into();
        let output = read_pipeline::read_page(
            &self.http_client, self.provider.as_ref(), &self.cache, &params,
        ).await;

        let is_err = output.error.is_some();
        let json = serde_json::to_string(&output).unwrap_or_default();
        if is_err {
            Ok(CallToolResult::error(vec![Content::text(json)]))
        } else {
            Ok(CallToolResult::success(vec![Content::text(json)]))
        }
    }
}

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;
```

- [ ] **Step 3: Register tool in mod.rs**

In `crates/mcp/src/tools/mod.rs`:

Add: `mod read;`
Add: `pub use read::ReadInput;`

Add tool to `#[tool_router] impl`:
```rust
#[tool(
    name = "read",
    description = "Read and extract content from any URL. Returns clean text, markdown, or HTML. Automatically handles Cloudflare bypass, anti-bot detection, retries, and content extraction. Use this as the default tool for reading web pages, articles, blog posts, documentation."
)]
async fn read(
    &self,
    Parameters(input): Parameters<ReadInput>,
) -> Result<CallToolResult, McpError> {
    self.do_read(input).await
}
```

- [ ] **Step 4: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-mcp read_tests -- --nocapture`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/mcp/src/tools/read.rs crates/mcp/src/tools/read_tests.rs crates/mcp/src/tools/mod.rs
git commit -m "feat(mcp): add unified read tool"
```

---

## Task 4: REST `/read` Endpoint + Split `lib.rs`

Add REST `/read` and fix `crates/js/src/lib.rs` (291 lines → split `solve` handler out).

**Files:**
- Create: `crates/js/src/read.rs`
- Create: `crates/js/src/read_tests.rs`
- Create: `crates/js/src/solve.rs` (extracted from lib.rs)
- Modify: `crates/js/src/lib.rs`

- [ ] **Step 1: Extract solve handler from lib.rs**

Move `SolveRequest`, `SolveResponse`, `default_challenge_type()`, and `solve()` function (lines 59-171 of `crates/js/src/lib.rs`) into new `crates/js/src/solve.rs`.

In `lib.rs`:
- Add `mod solve;`
- Change route: `.route("/solve", post(solve::solve))`
- Remove the moved code
- Keep `AppState`, `EndpointDefaults`, `router()`, `health()`, tests

- [ ] **Step 2: Create REST read endpoint**

Create `crates/js/src/read.rs` (~45 lines):

```rust
//! POST /read — unified content extraction.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_http::content::ReadParams;
use ox_http::read_pipeline;

use super::AppState;

pub async fn read(
    State(state): State<AppState>,
    Json(params): Json<ReadParams>,
) -> (StatusCode, Json<ox_http::content::ReadOutput>) {
    let output = read_pipeline::read_page(
        &state.http_client, state.provider.as_ref(), &state.cache, &params,
    ).await;

    let status = if output.error.is_some() { StatusCode::BAD_GATEWAY } else { StatusCode::OK };
    (status, Json(output))
}

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;
```

Create `crates/js/src/read_tests.rs`:

```rust
use ox_http::content::ReadParams;

#[test]
fn read_params_deserializes_with_defaults() {
    let json = r#"{"url": "https://example.com"}"#;
    let p: ReadParams = serde_json::from_str(json).unwrap();
    assert_eq!(p.url, "https://example.com");
    assert_eq!(p.format, "text");
    assert_eq!(p.max_length, 0);
}

#[test]
fn read_params_with_markdown() {
    let json = r#"{"url": "https://x.com", "format": "markdown", "max_length": 1000}"#;
    let p: ReadParams = serde_json::from_str(json).unwrap();
    assert_eq!(p.format, "markdown");
    assert_eq!(p.max_length, 1000);
}
```

- [ ] **Step 3: Add route in lib.rs**

Add: `mod read;`
Add route: `.route("/read", post(read::read))`

- [ ] **Step 4: Verify lib.rs is under 200 lines after extraction**

Run: `wc -l crates/js/src/lib.rs` — should be ~130 lines

- [ ] **Step 5: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-js -- --nocapture`
Expected: All tests PASS (existing solve tests + new read tests)

- [ ] **Step 6: Commit**

```bash
git add crates/js/src/read.rs crates/js/src/read_tests.rs crates/js/src/solve.rs crates/js/src/lib.rs
git commit -m "feat(js): add POST /read, extract solve to own module"
```

---

## Task 5: Deprecate + Deduplicate Old Tools

Mark `fetch_smart` and `readability` as deprecated. Simplify their internals to delegate to shared code.

**Files:**
- Modify: `crates/mcp/src/tools/mod.rs` (descriptions)
- Modify: `crates/mcp/src/tools/readability.rs` (delegate to `content::extract_content`)
- Modify: `crates/mcp/src/tools/fetch.rs` (remove manual CF detection)
- Modify: `crates/js/src/readability.rs` (same delegation as MCP version)

- [ ] **Step 1: Update tool descriptions in mod.rs**

Change `fetch_smart` description:
```rust
description = "DEPRECATED: Use 'read' instead. Returns raw HTML with CF bypass. The 'read' tool provides the same plus automatic content extraction."
```

Change `readability` description:
```rust
description = "DEPRECATED: Use 'read' instead. The 'read' tool provides the same extraction plus markdown output and anti-bot detection."
```

- [ ] **Step 2: Simplify `readability.rs` — delegate to `content::extract_content`**

Replace the private `extract_article` and `html_to_plain` functions with calls to `ox_http::content`:

```rust
// Replace extract_article() call (line 87) with:
let format = if input.plain_text { ox_http::content::ContentFormat::Text }
             else { ox_http::content::ContentFormat::Html };
let extracted = ox_http::content::extract_content(&html, &input.url, format);
let mut content = extracted.content;
if input.max_length > 0 {
    content = ox_http::content::truncate_utf8(&content, input.max_length);
}
let length = content.len();

// Build ReadabilityResult from extracted fields
let result = ReadabilityResult {
    title: extracted.title,
    content,
    author: extracted.author,
    excerpt: extracted.excerpt,
    length,
    elapsed_ms: 0,
    method: method.into(),
};
```

Delete: `extract_article()`, `html_to_plain()` functions (lines 126-207).

**Update tests:** The existing tests in `readability.rs` import `extract_article` and `html_to_plain` directly. After deletion, these tests become compile errors. Remove the `#[cfg(test)] mod tests` block from `readability.rs` entirely — the functionality is now tested by `crates/http/src/content_tests.rs` (9 tests covering the same extraction + truncation + format logic).

- [ ] **Step 2b: Simplify REST `crates/js/src/readability.rs` — same delegation**

Apply the same changes as MCP version:
- Replace `extract_article()` call with `ox_http::content::extract_content()`
- Compute `let length = content.len();` before the struct literal
- Delete `extract_article()`, `html_to_plain()`, `should_fallback()` functions (use `ox_http::content::should_fallback` instead)
- Remove duplicate test code — extraction is tested in `content_tests.rs`

- [ ] **Step 3: Simplify `do_fetch_smart` in `fetch.rs`**

The middleware chain handles CF automatically. Remove manual `detect_cloudflare()` + `provider.solve()` logic. Simplify to:

```rust
pub(crate) async fn do_fetch_smart(
    &self,
    input: FetchSmartInput,
) -> Result<CallToolResult, McpError> {
    let start = Instant::now();
    let save = input.save_to_file;
    let url = input.url.clone();

    // Middleware chain handles CF detect + solve + retry automatically
    match self.http_client.get(&input.url).await {
        Ok(resp) => Ok(smart_ok(resp.status, resp.body, "auto", false, start, save, &url)),
        Err(e) => Ok(smart_error(start, &e.to_string())),
    }
}
```

- [ ] **Step 4: Run full workspace tests**

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/mcp/src/tools/mod.rs crates/mcp/src/tools/readability.rs crates/mcp/src/tools/fetch.rs crates/js/src/readability.rs
git commit -m "refactor: deprecate fetch_smart/readability, delegate to shared content module"
```

---

## Task 6: Version Bump + Docs

**Files:**
- Modify: `Cargo.toml` (root)
- Modify: `CLAUDE.md`

- [ ] **Step 1: Bump workspace version**

In root `Cargo.toml`, change: `version = "0.8.0"`

- [ ] **Step 2: Update CLAUDE.md**

Update API section:
```
**REST**: `/health`, `/solve`, `/fetch`, `/fetch-smart`, `/read`, `/readability`, `/analyze`, `/security`, `/crawl`, `/images/search`, `/images/reverse`, `/media/download`, `/site-audit`

**MCP**: `/mcp` — 11 tools: fetch, fetch_smart (deprecated→use read), read, analyze, solve_cf, security_scan, readability (deprecated→use read), crawl, image_search, reverse_image_search, media_download, site_audit
```

- [ ] **Step 3: Build + test entire workspace**

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace && cargo build --workspace`
Expected: Clean build, all tests pass

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml CLAUDE.md
git commit -m "chore: bump to v0.8.0, document read tool"
```

---

## Task 7: Deploy + Smoke Test

- [ ] **Step 1: Build Docker image**

```bash
cd ~/deploy/krolik-server && docker compose build --no-cache ox-browser
```

- [ ] **Step 2: Deploy**

```bash
docker compose up -d --no-deps --force-recreate ox-browser
```

- [ ] **Step 3: Test `/read` (text)**

```bash
curl -s -X POST http://127.0.0.1:8901/read \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}' | jq '{title, format, method, length}'
```

Expected: `{title: "Example Domain", format: "text", method: "direct", length: >0}`

- [ ] **Step 4: Test `/read` (markdown)**

```bash
curl -s -X POST http://127.0.0.1:8901/read \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","format":"markdown"}' | jq .content
```

Expected: Markdown with heading

- [ ] **Step 5: Verify deprecated tools still work**

```bash
curl -s -X POST http://127.0.0.1:8901/readability \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}' | jq .title
```

Expected: `"Example Domain"`

- [ ] **Step 6: Re-register MCP**

```bash
claude mcp remove ox-browser 2>/dev/null; claude mcp add -s user -t http ox-browser http://127.0.0.1:8901/mcp
```

Verify `read` tool appears in tool list.
