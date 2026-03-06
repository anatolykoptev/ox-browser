# Phase 5: MCP Server Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add native MCP protocol support to ox-browser via `/mcp` endpoint alongside existing REST API.

**Architecture:** Use `rmcp` v1.1.0 (official Rust MCP SDK) with `#[tool]` proc-macros for tool
registration. Mount `StreamableHttpService` as Tower service into existing Axum router via `.nest()`.
4 tools mirroring REST endpoints: fetch, fetch_smart, analyze, solve_cf.

**Tech Stack:** rmcp 1.1.0, schemars, axum 0.8, tokio, serde

---

### Task 1: Add rmcp dependencies to ox-mcp crate

**Files:**
- Modify: `crates/mcp/Cargo.toml`
- Modify: `Cargo.toml` (workspace root — add workspace deps + ox-mcp to binary)

**Step 1: Update `crates/mcp/Cargo.toml`**

```toml
[package]
name = "ox-mcp"
version.workspace = true
edition.workspace = true

[dependencies]
rmcp = { version = "1.1", features = ["server", "transport-streamable-http-server"] }
schemars = "0.8"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
ox-http = { path = "../http" }
ox-core = { path = "../core" }
ox-security = { path = "../security" }
tokio.workspace = true
tracing.workspace = true
```

**Step 2: Add ox-mcp to root binary deps in `Cargo.toml`**

Add to `[dependencies]` section (after `ox-js`):
```toml
ox-mcp = { path = "crates/mcp" }
```

**Step 3: Verify it compiles**

Run: `cd /home/krolik/src/ox-browser && cargo check -p ox-mcp`
Expected: compiles (empty lib.rs is fine)

**Step 4: Commit**

```bash
git add crates/mcp/Cargo.toml Cargo.toml
git commit -m "feat(mcp): add rmcp dependencies to ox-mcp crate"
```

---

### Task 2: Create MCP server struct with tool_router

**Files:**
- Create: `crates/mcp/src/tools.rs`
- Modify: `crates/mcp/src/lib.rs`

**Step 1: Create `crates/mcp/src/tools.rs` with server struct**

```rust
//! MCP tool definitions for ox-browser.

use std::sync::Arc;

use rmcp::{
    handler::server::tool::ToolRouter,
    model::*,
    tool, tool_router,
    ErrorData as McpError,
};
use schemars::JsonSchema;
use serde::Deserialize;

use ox_http::{detect_cloudflare, ChallengeType, CookieCache, CookieProvider, HttpClient};

/// Shared state for MCP tool handlers.
#[derive(Clone)]
pub struct OxMcpServer {
    pub provider: Arc<dyn CookieProvider>,
    pub cache: Arc<CookieCache>,
    pub http_client: Arc<HttpClient>,
    tool_router: ToolRouter<Self>,
}

impl OxMcpServer {
    pub fn new(
        provider: Arc<dyn CookieProvider>,
        cache: Arc<CookieCache>,
        http_client: Arc<HttpClient>,
    ) -> Self {
        Self {
            provider,
            cache,
            http_client,
            tool_router: Self::tool_router(),
        }
    }
}

// --- Input schemas ---

#[derive(Deserialize, JsonSchema)]
pub struct FetchInput {
    /// URL to fetch
    pub url: String,
    /// Request timeout in seconds (default: 15)
    #[serde(default = "default_fetch_timeout")]
    pub timeout: u64,
}

fn default_fetch_timeout() -> u64 {
    15
}

#[derive(Deserialize, JsonSchema)]
pub struct FetchSmartInput {
    /// URL to fetch with automatic CF bypass
    pub url: String,
    /// Request timeout in seconds (default: 30)
    #[serde(default = "default_smart_timeout")]
    pub timeout: u64,
}

fn default_smart_timeout() -> u64 {
    30
}

#[derive(Deserialize, JsonSchema)]
pub struct AnalyzeInput {
    /// URL to analyze for technology stack
    pub url: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct SolveCfInput {
    /// URL behind Cloudflare protection
    pub url: String,
    /// Challenge type: js_challenge, managed_challenge, turnstile, managed_challenge_200
    #[serde(default = "default_challenge")]
    pub challenge_type: String,
}

fn default_challenge() -> String {
    "js_challenge".into()
}

// --- Tool implementations ---

#[tool_router]
impl OxMcpServer {
    #[tool(
        name = "fetch",
        description = "Stealth HTTP fetch with Chrome TLS fingerprint and proxy rotation. Returns status, headers, body, and Cloudflare detection result."
    )]
    async fn fetch(
        &self,
        #[tool(params)] input: FetchInput,
    ) -> Result<CallToolResult, McpError> {
        let start = std::time::Instant::now();

        match self.http_client.get(&input.url).await {
            Ok(resp) => {
                let cf = detect_cloudflare(&resp);
                let cf_detected = cf.is_some();
                let cf_type = cf.map(|c| c.challenge_type.to_string());

                let headers: std::collections::HashMap<String, String> = resp
                    .headers
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str().ok().map(|val| (k.to_string(), val.to_owned()))
                    })
                    .collect();

                let result = serde_json::json!({
                    "status": resp.status,
                    "headers": headers,
                    "body": resp.body,
                    "cf_detected": cf_detected,
                    "cf_type": cf_type,
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                });
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]))
            }
            Err(e) => {
                let result = serde_json::json!({
                    "status": 0,
                    "error": e.to_string(),
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                });
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]))
            }
        }
    }

    #[tool(
        name = "fetch_smart",
        description = "Three-tier fetch chain with automatic Cloudflare bypass: proxy -> stealth HTTP -> headless solver. Returns content with method used (direct or solved)."
    )]
    async fn fetch_smart(
        &self,
        #[tool(params)] input: FetchSmartInput,
    ) -> Result<CallToolResult, McpError> {
        let start = std::time::Instant::now();
        let domain = url::Url::parse(&input.url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();

        // Stage 1: Fast wreq fetch.
        let resp = match self.http_client.get(&input.url).await {
            Ok(r) => r,
            Err(e) => {
                let result = serde_json::json!({
                    "status": 0,
                    "error": e.to_string(),
                    "method": "direct",
                    "cf_detected": false,
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                });
                return Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]));
            }
        };

        let cf = detect_cloudflare(&resp);
        if cf.is_none() {
            let result = serde_json::json!({
                "status": resp.status,
                "body": resp.body,
                "method": "direct",
                "cf_detected": false,
                "elapsed_ms": start.elapsed().as_millis() as u64,
            });
            return Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_default(),
            )]));
        }

        let challenge = cf.unwrap();
        if challenge.challenge_type == ChallengeType::Block {
            let result = serde_json::json!({
                "status": resp.status,
                "body": resp.body,
                "method": "direct",
                "cf_detected": true,
                "error": "CF block — not solvable",
                "elapsed_ms": start.elapsed().as_millis() as u64,
            });
            return Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_default(),
            )]));
        }

        // Stage 2: Solve + retry.
        match self.provider.solve(&input.url, challenge.challenge_type).await {
            Ok(solved) => {
                self.cache.put(&domain, solved);
                match self.http_client.get(&input.url).await {
                    Ok(retry_resp) => {
                        let result = serde_json::json!({
                            "status": retry_resp.status,
                            "body": retry_resp.body,
                            "method": "solved",
                            "cf_detected": true,
                            "elapsed_ms": start.elapsed().as_millis() as u64,
                        });
                        Ok(CallToolResult::success(vec![Content::text(
                            serde_json::to_string_pretty(&result).unwrap_or_default(),
                        )]))
                    }
                    Err(e) => {
                        let result = serde_json::json!({
                            "status": 0,
                            "error": format!("retry after solve failed: {e}"),
                            "method": "solved",
                            "cf_detected": true,
                            "elapsed_ms": start.elapsed().as_millis() as u64,
                        });
                        Ok(CallToolResult::success(vec![Content::text(
                            serde_json::to_string_pretty(&result).unwrap_or_default(),
                        )]))
                    }
                }
            }
            Err(e) => {
                let result = serde_json::json!({
                    "status": resp.status,
                    "body": resp.body,
                    "error": format!("solve failed: {e}"),
                    "method": "direct",
                    "cf_detected": true,
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                });
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]))
            }
        }
    }

    #[tool(
        name = "analyze",
        description = "Detect website technology stack (CMS, JS frameworks, CSS frameworks, analytics, CDN, server software) from HTML and response headers."
    )]
    async fn analyze(
        &self,
        #[tool(params)] input: AnalyzeInput,
    ) -> Result<CallToolResult, McpError> {
        let start = std::time::Instant::now();

        let resp = match self.http_client.get(&input.url).await {
            Ok(r) => r,
            Err(e) => {
                let result = serde_json::json!({
                    "url": input.url,
                    "error": e.to_string(),
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                });
                return Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]));
            }
        };

        let cf_detected = detect_cloudflare(&resp).is_some();
        let page = ox_core::Page::new(resp.url.clone(), resp.status, &resp.body);

        let headers: std::collections::HashMap<String, String> = resp
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|val| (k.to_string().to_lowercase(), val.to_owned()))
            })
            .collect();

        let meta_tags: std::collections::HashMap<String, String> = page
            .meta_tags()
            .into_iter()
            .filter(|m| !m.name.is_empty())
            .map(|m| (m.name.to_lowercase(), m.content))
            .collect();

        let script_srcs: Vec<String> = page
            .select("script[src]")
            .iter()
            .filter_map(|s| s.attr("src").map(|v| v.to_string()))
            .collect();

        let stylesheets: Vec<String> = page
            .select("link[rel='stylesheet'][href]")
            .iter()
            .filter_map(|s| s.attr("href").map(|v| v.to_string()))
            .collect();

        let fingerprinter = ox_security::fingerprint::Fingerprinter::new();
        let detections =
            fingerprinter.detect(&headers, &resp.body, &meta_tags, &script_srcs);

        let techs: Vec<serde_json::Value> = detections
            .into_iter()
            .map(|d| {
                serde_json::json!({
                    "name": d.name,
                    "category": d.category,
                    "confidence": d.confidence,
                })
            })
            .collect();

        let result = serde_json::json!({
            "url": input.url,
            "status": resp.status,
            "technologies": techs,
            "meta": {
                "generator": meta_tags.get("generator").cloned().unwrap_or_default(),
                "server": headers.get("server").cloned().unwrap_or_default(),
                "powered_by": headers.get("x-powered-by").cloned().unwrap_or_default(),
                "title": page.title(),
            },
            "assets": {
                "scripts": script_srcs,
                "stylesheets": stylesheets,
            },
            "cf_detected": cf_detected,
            "elapsed_ms": start.elapsed().as_millis() as u64,
        });
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap_or_default(),
        )]))
    }

    #[tool(
        name = "solve_cf",
        description = "Solve Cloudflare challenge and return clearance cookies. Supports js_challenge, managed_challenge, turnstile, managed_challenge_200."
    )]
    async fn solve_cf(
        &self,
        #[tool(params)] input: SolveCfInput,
    ) -> Result<CallToolResult, McpError> {
        let challenge_type = match input.challenge_type.as_str() {
            "js_challenge" => ChallengeType::JsChallenge,
            "managed_challenge" | "turnstile" => ChallengeType::Turnstile,
            "managed_challenge_200" => ChallengeType::ManagedChallenge,
            "block" => {
                return Ok(CallToolResult::success(vec![Content::text(
                    r#"{"status":"error","error":"block challenges are not solvable"}"#,
                )]));
            }
            _ => ChallengeType::JsChallenge,
        };

        let domain = url::Url::parse(&input.url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "unknown".into());

        if let Some(cached) = self.cache.get(&domain) {
            let result = serde_json::json!({
                "status": "ok",
                "cookies": cached.cookies,
                "user_agent": cached.user_agent,
                "cached": true,
            });
            return Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_default(),
            )]));
        }

        match self.provider.solve(&input.url, challenge_type).await {
            Ok(solved) => {
                self.cache.put(&domain, solved.clone());
                let result = serde_json::json!({
                    "status": "ok",
                    "cookies": solved.cookies,
                    "user_agent": solved.user_agent,
                });
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]))
            }
            Err(e) => {
                let result = serde_json::json!({
                    "status": "error",
                    "error": e,
                });
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]))
            }
        }
    }
}
```

**Step 2: Update `crates/mcp/src/lib.rs`**

```rust
//! MCP server for ox-browser — exposes fetch, analyze, and CF solve tools.

pub mod tools;

pub use tools::OxMcpServer;
```

**Step 3: Verify it compiles**

Run: `cd /home/krolik/src/ox-browser && cargo check -p ox-mcp`
Expected: compiles successfully

**Step 4: Commit**

```bash
git add crates/mcp/src/
git commit -m "feat(mcp): implement 4 MCP tools with rmcp proc-macros

Tools: fetch, fetch_smart, analyze, solve_cf
Uses #[tool_router] + #[tool] for automatic JSON Schema generation."
```

---

### Task 3: Implement ServerHandler and Streamable HTTP mount

**Files:**
- Modify: `crates/mcp/src/lib.rs`

**Step 1: Add ServerHandler impl and router builder to `lib.rs`**

```rust
//! MCP server for ox-browser — exposes fetch, analyze, and CF solve tools.

pub mod tools;

use std::sync::Arc;

use axum::Router;
use rmcp::{
    handler::server::ServerHandler,
    model::*,
    tool_handler,
    transport::streamable_http_server::tower::{
        StreamableHttpServerConfig, StreamableHttpService,
    },
};
use tools::OxMcpServer;

use ox_http::{CookieCache, CookieProvider, HttpClient};

#[tool_handler]
impl ServerHandler for OxMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "ox-browser".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability::default()),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

/// Build an Axum router that serves MCP over Streamable HTTP at `/mcp`.
pub fn build_mcp_router(
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
    http_client: Arc<HttpClient>,
) -> Router {
    let config = StreamableHttpServerConfig::default();

    let p = provider.clone();
    let c = cache.clone();
    let h = http_client.clone();
    let service = StreamableHttpService::new(
        move || Ok(OxMcpServer::new(p.clone(), c.clone(), h.clone())),
        Arc::new(rmcp::transport::streamable_http_server::session::local::LocalSessionManager::default()),
        config,
    );

    Router::new().nest_service("/mcp", service)
}
```

**Step 2: Verify it compiles**

Run: `cd /home/krolik/src/ox-browser && cargo check -p ox-mcp`
Expected: compiles. If rmcp API differs slightly, adjust imports.

**Step 3: Commit**

```bash
git add crates/mcp/src/lib.rs
git commit -m "feat(mcp): add ServerHandler impl and Streamable HTTP router builder"
```

---

### Task 4: Mount MCP router in serve.rs

**Files:**
- Modify: `src/serve.rs`

**Step 1: Merge MCP router with REST router in `serve.rs`**

Replace line 64 (`let app = ox_js::router(state);`) and what follows with:

```rust
    let rest_router = ox_js::router(state.clone());
    let mcp_router = ox_mcp::build_mcp_router(
        state.provider.clone(),
        state.cache.clone(),
        state.http_client.clone(),
    );
    let app = rest_router.merge(mcp_router);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    tracing::info!("ox-browser server listening on :{port} (REST + MCP)");
    axum::serve(listener, app).await?;
```

Note: `state.clone()` requires `AppState` to be `Clone`, which it already is.

**Step 2: Verify it compiles**

Run: `cd /home/krolik/src/ox-browser && cargo check`
Expected: full binary compiles

**Step 3: Commit**

```bash
git add src/serve.rs
git commit -m "feat(mcp): mount MCP Streamable HTTP alongside REST API

Both REST (/fetch, /analyze, etc.) and MCP (/mcp) served on same port."
```

---

### Task 5: Build, deploy, and smoke test

**Files:**
- No new files — deployment and testing

**Step 1: Run all tests locally**

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace`
Expected: all existing tests pass

**Step 2: Build Docker image**

Run:
```bash
cd /home/krolik/deploy/krolik-server
docker compose build --no-cache ox-browser
```
Expected: builds successfully (rmcp adds ~30s to compile time)

**Step 3: Deploy**

Run:
```bash
docker compose up -d --no-deps --force-recreate ox-browser
```

**Step 4: Verify health**

Run: `curl http://127.0.0.1:8901/health`
Expected: `ok`

**Step 5: Smoke test MCP endpoint**

Run:
```bash
curl -X POST http://127.0.0.1:8901/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}'
```
Expected: JSON-RPC response with server info (name: "ox-browser", tools capability)

**Step 6: Test tools/list**

Run:
```bash
curl -X POST http://127.0.0.1:8901/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: test-session" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```
Expected: list of 4 tools (fetch, fetch_smart, analyze, solve_cf) with JSON schemas

**Step 7: Register MCP in Claude Code**

Run: `claude mcp add -s user -t http ox-browser http://127.0.0.1:8901/mcp`

**Step 8: Commit version bump + tag**

```bash
cd /home/krolik/src/ox-browser
# Bump version in Cargo.toml workspace.package from 0.2.0 to 0.3.0
git add -A
git commit -m "feat: ox-browser v0.3.0 — native MCP server

4 MCP tools via rmcp Streamable HTTP:
- fetch: stealth HTTP with Chrome TLS fingerprint
- fetch_smart: three-tier CF bypass chain
- analyze: tech stack detection
- solve_cf: Cloudflare challenge solver

Mounted alongside REST API on port 8901."
git tag v0.3.0
git push origin main --tags
```

---

### Notes for implementer

**If rmcp API differs from examples:**
- Check `cargo doc -p rmcp --open` for exact types
- `StreamableHttpService::new()` may need different session manager import
- `#[tool(params)]` attribute may use `Parameters<T>` wrapper — check rmcp docs
- If `tool_handler` fails, ensure `rmcp` features include `"macros"`

**Key rmcp imports to know:**
```rust
use rmcp::{tool, tool_router, tool_handler};           // proc macros
use rmcp::{ErrorData as McpError, model::*};            // types
use rmcp::handler::server::tool::ToolRouter;            // router type
use rmcp::handler::server::ServerHandler;               // trait
use rmcp::model::{ServerInfo, ServerCapabilities, ...}; // server info
use rmcp::transport::streamable_http_server::tower::*;  // HTTP transport
```

**Cargo.toml rmcp features:**
```toml
rmcp = { version = "1.1", features = ["server", "macros", "transport-streamable-http-server"] }
```
The `macros` feature may be needed separately for `#[tool]`, `#[tool_router]`, `#[tool_handler]`.
If compile errors about missing macros, add `"macros"` to features list.

**schemars version:** rmcp 1.1 may require `schemars = "1"` (not 0.8). Check rmcp's own
Cargo.toml for the exact schemars version it re-exports or depends on.
