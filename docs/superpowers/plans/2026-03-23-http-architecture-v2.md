# ox-browser HTTP Architecture v2 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix wreq proxy handling for Reddit, eliminate dual CF-solve paths, wire up ProxyHealth + DomainLimiter, and add site-specific handler architecture.

**Architecture:** The middleware chain (`client.rs`) already handles CF detection → residential retry → solver retry correctly. But `read_pipeline.rs::headless_read()` duplicates the solver logic outside the chain. We unify by removing `headless_read` and making all requests flow through the middleware chain. Reddit and other site-specific handlers become a "pre-chain" dispatch in the read pipeline. ProxyHealth wraps the WebsharePool, and DomainLimiter is configured from TOML.

**Tech Stack:** Rust 1.93, wreq (BoringSSL), axum, async-trait, tokio

---

## Analysis of Current Problems

### Problem 1: wreq proxy 403 on Reddit
`get_with_proxy()` sets `req.proxy` → `WreqHandler` calls `builder.proxy()`. But the request still goes through the full middleware chain including `client_hints_middleware` which may inject headers that don't match what Reddit expects from the residential proxy IP. More importantly, wreq's `cookie_store(true)` may be sending stale cookies from a previous non-proxied request to the same domain. The fix: add debug logging first, then ensure clean cookie state for per-request proxy overrides.

### Problem 2: Dual CF solve paths
- **Path A** (middleware): `cloudflare_detect` → error → `residential_proxy` retry → `solver_middleware` → solve + retry
- **Path B** (read_pipeline): `headless_read()` → `provider.solve()` directly → use body or retry with cookies

Path B bypasses the middleware chain, loses retry/ratelimit/logging, and duplicates body-passthrough logic. Both paths exist because `read_pipeline` was written before the middleware chain was mature.

### Problem 3: WebsharePool + ProxyHealth not wired
`serve.rs` doesn't init `WebsharePool` even though `WEBSHARE_API_KEY` is available. `HealthyPool` wrapper exists but is never used. `DomainLimiter` exists but `rate_limiter` in `HttpConfig` is always `None`.

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `crates/http/src/handler_reqwest.rs` | Modify | Add debug logging for proxy/UA |
| `crates/http/src/middleware_quality.rs` | Create | Quality-check middleware (anti-bot stub + fallback errors) |
| `crates/http/src/read_pipeline.rs` | Modify | Remove `headless_read`, simplify to chain-only flow |
| `crates/http/src/site_reddit.rs` | Modify | Use standalone wreq client instead of `get_with_proxy` |
| `crates/http/src/client.rs` | Modify | Add quality middleware to chain, remove `get_with_proxy` |
| `crates/http/src/lib.rs` | Modify | Register quality middleware module |
| `src/config/mod.rs` | Modify | Wire WebsharePool + HealthyPool + DomainLimiter |
| `src/config/ratelimit.rs` | Create | TOML config section for domain rate limits |
| `src/serve.rs` | Modify | Wire new config fields |

---

## Task 1: Debug logging in WreqHandler

**Files:**
- Modify: `crates/http/src/handler_reqwest.rs:48-94`

- [ ] **Step 1: Add tracing to WreqHandler::handle**

```rust
// In handler_reqwest.rs, inside handle(), after proxy selection block (line ~70):
tracing::debug!(
    url = %req.url,
    method = %req.method,
    proxy = ?req.proxy,
    ua = ?req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("user-agent")).map(|(_, v)| v.as_str()),
    header_count = req.headers.len(),
    "wreq: sending request"
);

// After resp (line ~83), add:
tracing::debug!(
    url = %req.url,
    status = resp.status().as_u16(),
    final_url = %resp.uri(),
    "wreq: response received"
);
```

- [ ] **Step 2: Build and test locally**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http --lib handler_reqwest`
Expected: PASS (existing test still passes)

- [ ] **Step 3: Commit**

```bash
cd /home/krolik/src/ox-browser
git add crates/http/src/handler_reqwest.rs
git commit -m "feat(http): add debug logging to WreqHandler for proxy diagnostics"
```

---

## Task 2: Fix Reddit site handler — use dedicated reqwest client

The core problem: `get_with_proxy()` goes through the full middleware chain (which may inject wrong headers, stale cookies, etc.). Reddit's JSON API is simple — it just needs a residential proxy with clean headers.

**Files:**
- Modify: `crates/http/src/site_reddit.rs`
- Test: existing tests in same file

- [ ] **Step 1: Write test for standalone Reddit fetch**

Add to `site_reddit.rs` tests:

```rust
#[test]
fn builds_correct_json_url_for_subreddit() {
    let url = "https://www.reddit.com/r/rust/";
    let parsed = Url::parse(url).unwrap();
    let path = parsed.path().trim_end_matches('/');
    let json_url = format!("https://old.reddit.com{path}.json?limit=25&raw_json=1");
    assert_eq!(json_url, "https://old.reddit.com/r/rust.json?limit=25&raw_json=1");
}

#[test]
fn builds_correct_json_url_for_post() {
    let url = "https://www.reddit.com/r/rust/comments/abc123/my_post/";
    let parsed = Url::parse(url).unwrap();
    let path = parsed.path().trim_end_matches('/');
    let json_url = format!("https://old.reddit.com{path}.json?limit=25&raw_json=1");
    assert_eq!(json_url, "https://old.reddit.com/r/rust/comments/abc123/my_post.json?limit=25&raw_json=1");
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http --lib site_reddit`
Expected: PASS

- [ ] **Step 3: Replace `http.get_with_proxy()` with standalone wreq client**

Replace the fetch logic in `try_reddit_json` — use a one-shot wreq client with explicit proxy, Chrome UA, and no cookie jar:

```rust
use wreq_util::Emulation;

// Replace lines 31-37 in try_reddit_json with:
let proxy_url = std::env::var("RESIDENTIAL_PROXY_URL").ok();
let resp = match reddit_fetch(&json_url, proxy_url.as_deref()).await {
    Ok(r) => r,
    Err(e) => {
        tracing::warn!(error = %e, "reddit fetch failed");
        return None;
    }
};
```

Add the standalone fetch function (outside `try_reddit_json`):

```rust
/// Fetch Reddit JSON using a dedicated client (not the middleware chain).
///
/// Reddit blocks datacenter IPs and detects non-browser TLS fingerprints.
/// This uses a fresh wreq client with Chrome emulation and residential proxy.
async fn reddit_fetch(url: &str, proxy_url: Option<&str>) -> Result<(u16, String), String> {
    let mut builder = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .emulation(Emulation::Chrome136)
        .redirect(wreq::redirect::Policy::limited(5))
        .cookie_store(false);

    if let Some(proxy) = proxy_url {
        let p = wreq::Proxy::all(proxy).map_err(|e| e.to_string())?;
        builder = builder.proxy(p);
    }

    let client = builder.build().map_err(|e| e.to_string())?;
    let resp = client
        .get(url)
        .header("accept", "application/json")
        .header("accept-language", "en-US,en;q=0.9")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    Ok((status, body))
}
```

Update `try_reddit_json` to use the new return type:

```rust
let (status, body) = resp;
if status != 200 {
    tracing::warn!(status, "reddit JSON API returned non-200");
    return None;
}
let data: serde_json::Value = serde_json::from_str(&body).ok()?;
```

Remove `use crate::HttpClient;` from the import if `http` param is no longer needed — but keep `http` param for now as it's called from `read_pipeline` with it. We'll remove the dependency in Task 4.

- [ ] **Step 4: Update function signature — remove HttpClient dependency**

Change signature from:
```rust
pub async fn try_reddit_json(
    http: &HttpClient,
    params: &ReadParams,
    format: ContentFormat,
    start: Instant,
) -> Option<ReadOutput> {
```
To:
```rust
pub async fn try_reddit_json(
    params: &ReadParams,
    format: ContentFormat,
    start: Instant,
) -> Option<ReadOutput> {
```

Update the caller in `read_pipeline.rs:44`:
```rust
// Before:
if let Some(output) = crate::site_reddit::try_reddit_json(http, params, format, start).await {
// After:
if let Some(output) = crate::site_reddit::try_reddit_json(params, format, start).await {
```

- [ ] **Step 5: Run all tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd /home/krolik/src/ox-browser
git add crates/http/src/site_reddit.rs crates/http/src/read_pipeline.rs
git commit -m "fix(reddit): use dedicated wreq client with Chrome emulation, bypass middleware chain"
```

---

## Task 3: Add quality-check middleware + remove headless_read

The middleware chain handles CF detect → residential retry → solver, but doesn't handle two cases that `headless_read` covers:
1. **Non-CF errors (401/403/429/503)** via `should_fallback()` — these may be anti-bot pages solvable by headless
2. **Low-quality 200 responses** via `is_low_quality()` — large HTML with tiny extracted text (anti-bot stub pages)

Strategy: Add a `quality_check_middleware` that converts these cases into `HttpError::Cloudflare(JsChallenge)`, letting the existing solver middleware handle them. Then remove `headless_read`.

**Files:**
- Create: `crates/http/src/middleware_quality.rs`
- Modify: `crates/http/src/lib.rs` (add module + re-export)
- Modify: `crates/http/src/client.rs` (add middleware to chain)
- Modify: `crates/http/src/read_pipeline.rs`
- Modify: `crates/http/src/read_pipeline_tests.rs` (if it references `headless_read`)

- [ ] **Step 1: Check what `read_pipeline_tests.rs` tests**

Read the test file to understand which tests reference `headless_read`.

- [ ] **Step 2: Create quality_check_middleware**

Create `crates/http/src/middleware_quality.rs`:

```rust
//! Quality-check middleware: converts anti-bot pages and fallback-worthy
//! HTTP errors into CF challenge errors, so the solver middleware can handle them.
//!
//! This replaces the `headless_read` fallback in `read_pipeline.rs` by
//! moving the detection logic into the middleware chain.

use std::sync::Arc;

use async_trait::async_trait;

use crate::cloudflare::ChallengeType;
use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::{HttpResponse, Result};

/// Returns a middleware that detects anti-bot stub pages and converts them
/// to CF challenge errors for the solver middleware to handle.
///
/// Position in chain: innermost (just before client_hints), so it sees
/// the actual response before any other middleware processes it.
/// The solver middleware sits above this and will catch the CF error.
pub fn quality_check_middleware() -> MiddlewareFn {
    Arc::new(move |next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(QualityCheckHandler { next })
    })
}

struct QualityCheckHandler {
    next: Arc<dyn Handler>,
}

/// HTTP status codes that indicate an anti-bot block (not CF-specific).
fn should_fallback(status: u16) -> bool {
    matches!(status, 401 | 403 | 429 | 503)
}

#[async_trait]
impl Handler for QualityCheckHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let resp = self.next.handle(req).await?;

        // Non-200 fallback-worthy status → trigger solver
        if should_fallback(resp.status) {
            tracing::info!(
                url = %resp.url,
                status = resp.status,
                "quality: non-200 status, triggering solver"
            );
            return Err(HttpError::Cloudflare(
                ChallengeType::JsChallenge,
                resp.status,
                String::new(),
            ));
        }

        // 200 but low-quality content → likely anti-bot stub page.
        // Quick heuristic: large body (>5KB) with very little visible text.
        // We don't do full content extraction here (expensive) — just a fast check.
        if resp.status == 200 && resp.body.len() > 5_000 {
            // Strip HTML tags naively and count remaining non-whitespace chars
            let visible: usize = resp.body
                .split('<')
                .filter_map(|s| s.split_once('>').map(|(_, after)| after))
                .map(|text| text.chars().filter(|c| !c.is_whitespace()).count())
                .sum();
            if visible < 100 {
                tracing::info!(
                    url = %resp.url,
                    body_len = resp.body.len(),
                    visible_chars = visible,
                    "quality: low-quality 200, triggering solver"
                );
                return Err(HttpError::Cloudflare(
                    ChallengeType::JsChallenge,
                    200,
                    String::new(),
                ));
            }
        }

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::chain;
    use wreq::header::HeaderMap;

    struct FixedHandler {
        status: u16,
        body: String,
    }

    #[async_trait]
    impl Handler for FixedHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            Ok(HttpResponse {
                status: self.status,
                url: req.url,
                headers: HeaderMap::new(),
                body: self.body.clone(),
            })
        }
    }

    fn test_req() -> Request {
        Request {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: None,
            proxy: None,
        }
    }

    #[tokio::test]
    async fn passes_through_200_with_good_content() {
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 200,
            body: "Hello world with good content".into(),
        });
        let handler = chain(vec![quality_check_middleware()], base);
        let resp = handler.handle(test_req()).await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn converts_403_to_cf_error() {
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 403,
            body: "Forbidden".into(),
        });
        let handler = chain(vec![quality_check_middleware()], base);
        let err = handler.handle(test_req()).await.unwrap_err();
        assert!(matches!(err, HttpError::Cloudflare(ChallengeType::JsChallenge, 403, _)));
    }

    #[tokio::test]
    async fn converts_503_to_cf_error() {
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 503,
            body: "Service Unavailable".into(),
        });
        let handler = chain(vec![quality_check_middleware()], base);
        let err = handler.handle(test_req()).await.unwrap_err();
        assert!(matches!(err, HttpError::Cloudflare(ChallengeType::JsChallenge, 503, _)));
    }

    #[tokio::test]
    async fn passes_through_404() {
        let base: Arc<dyn Handler> = Arc::new(FixedHandler {
            status: 404,
            body: "Not Found".into(),
        });
        let handler = chain(vec![quality_check_middleware()], base);
        let resp = handler.handle(test_req()).await.unwrap();
        assert_eq!(resp.status, 404);
    }
}
```

- [ ] **Step 3: Register module in lib.rs**

Add to `crates/http/src/lib.rs`:
```rust
pub mod middleware_quality;
pub use middleware_quality::quality_check_middleware;
```

- [ ] **Step 4: Add quality_check to middleware chain in client.rs**

In `client.rs::new()`, add the quality check middleware between `cloudflare_detect` and `client_hints`:

```rust
// Quality check: convert anti-bot 200s and fallback-worthy errors to CF errors.
// Must be inside cloudflare_detect (so CF errors aren't double-converted)
// and before solver (so solver catches the converted errors).
middlewares.push(crate::middleware_quality::quality_check_middleware());
```

Insert after the cloudflare detect block (line ~74) and before the client_hints line (line ~77).

- [ ] **Step 5: Run tests for the new middleware**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http --lib middleware_quality`
Expected: PASS

- [ ] **Step 6: Simplify `read_page_inner` — remove headless fallback**

Now that the middleware chain handles quality fallback, simplify `read_page_inner`:

```rust
async fn read_page_inner(
    http: &HttpClient,
    params: &ReadParams,
) -> ReadOutput {
    let start = Instant::now();
    let format = ContentFormat::from_param(&params.format);

    // Site-specific handlers (bypass middleware chain entirely)
    if let Some(output) = crate::site_reddit::try_reddit_json(params, format, start).await {
        return output;
    }

    // All requests go through middleware chain:
    // CF detect → quality check → residential retry → solver (with body passthrough)
    let resp = match http.get(&params.url).await {
        Ok(r) => r,
        Err(e) => return build_error_output(params, "direct", elapsed(start), &e.to_string()),
    };

    if resp.status != 200 {
        return build_error_output(
            params,
            "direct",
            elapsed(start),
            &format!("HTTP {}", resp.status),
        );
    }

    let extracted = content::extract_content(&resp.body, &params.url, format);
    build_output(extracted, params, "direct", elapsed(start))
}
```

- [ ] **Step 7: Simplify `read_page` signature — remove provider/cache params**

```rust
pub async fn read_page(
    http: &HttpClient,
    params: &ReadParams,
) -> ReadOutput {
    match tokio::time::timeout(
        PIPELINE_TIMEOUT,
        read_page_inner(http, params),
    ).await {
        Ok(output) => output,
        Err(_) => build_error_output(params, "direct", PIPELINE_TIMEOUT.as_millis() as u64, "read pipeline timeout"),
    }
}
```

Remove unused imports: `CookieCache`, `CookieProvider`, `ChallengeType`.

- [ ] **Step 8: Delete `headless_read` function entirely**

Remove the entire `headless_read` function (lines 75-126 in current file).

- [ ] **Step 9: Update all callers of `read_page`**

The callers pass `provider` and `cache` which are no longer needed. Find and update:

Run: Search for `read_page(` in `crates/js/src/read.rs` and `crates/mcp/src/tools/read.rs`.

Update each call from:
```rust
read_page(&state.http_client, &state.provider, &state.cache, &params).await
```
To:
```rust
read_page(&state.http_client, &params).await
```

Note: `provider` and `cache` remain in `AppState`/`OxMcpServer` — they're still used for `http_config.cookie_provider`/`cookie_cache` in `serve.rs`. No need to remove them.

- [ ] **Step 10: Run all tests**

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace`
Expected: PASS (some read_pipeline_tests may need updating)

- [ ] **Step 11: Commit**

```bash
cd /home/krolik/src/ox-browser
git add crates/http/src/middleware_quality.rs crates/http/src/lib.rs crates/http/src/client.rs
git add -u crates/http/ crates/js/ crates/mcp/
git commit -m "refactor(pipeline): add quality_check middleware, remove headless_read

Quality check middleware converts anti-bot stub pages (large HTML, tiny text)
and fallback-worthy HTTP errors (401/403/429/503) into CF challenge errors,
letting the solver middleware handle them. This eliminates the duplicate
headless_read path in read_pipeline.rs."
```

---

## Task 4: Wire WebsharePool + HealthyPool in serve.rs

**Files:**
- Modify: `src/serve.rs`
- Modify: `src/config/mod.rs`

- [ ] **Step 1: Add WebsharePool initialization to `serve.rs::run()`**

After `http_config` is built (line ~24), before `HttpClient::new`:

```rust
// Initialize proxy pool from Webshare API if key is available.
if let Ok(api_key) = std::env::var("WEBSHARE_API_KEY") {
    if !api_key.is_empty() {
        match ox_http::WebsharePool::new(&api_key).await {
            Ok(pool) => {
                let health_cfg = config.proxy.health.to_health_config();
                let healthy = ox_http::HealthyPool::new(Arc::new(pool), health_cfg);
                http_config.proxy_pool = Some(Arc::new(healthy));
                tracing::info!("initialized Webshare proxy pool with health tracking");
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to init Webshare pool, continuing without proxies");
            }
        }
    }
}
```

- [ ] **Step 2: Remove `#[allow(dead_code)]` from `to_health_config`**

In `src/config/proxy.rs:53`, remove the `#[allow(dead_code)]` attribute since it's now used.

- [ ] **Step 3: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
cd /home/krolik/src/ox-browser
git add src/serve.rs src/config/proxy.rs
git commit -m "feat(proxy): wire WebsharePool with HealthyPool tracking in server startup"
```

---

## Task 5: Wire DomainLimiter from TOML config

**Files:**
- Create: `src/config/ratelimit.rs`
- Modify: `src/config/mod.rs`
- Modify: `src/serve.rs`

- [ ] **Step 1: Create ratelimit config section**

Create `src/config/ratelimit.rs`:

```rust
//! Per-domain rate limit configuration.

use std::time::Duration;

use ox_http::DomainConfig;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct RatelimitSection {
    pub rules: Vec<RatelimitRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RatelimitRule {
    /// Domain pattern: exact "api.x.com", wildcard "*.x.com", or "" (catch-all).
    pub domain: String,
    pub requests_per_window: usize,
    pub window_secs: u64,
    #[serde(default)]
    pub min_delay_ms: u64,
    #[serde(default)]
    pub random_delay_ms: u64,
}

impl Default for RatelimitSection {
    fn default() -> Self {
        Self {
            rules: vec![
                RatelimitRule {
                    domain: "*.reddit.com".into(),
                    requests_per_window: 10,
                    window_secs: 60,
                    min_delay_ms: 2000,
                    random_delay_ms: 1000,
                },
                RatelimitRule {
                    domain: String::new(), // catch-all
                    requests_per_window: 30,
                    window_secs: 60,
                    min_delay_ms: 200,
                    random_delay_ms: 100,
                },
            ],
        }
    }
}

impl RatelimitSection {
    pub fn to_domain_configs(&self) -> Vec<DomainConfig> {
        self.rules.iter().map(|r| DomainConfig {
            domain: r.domain.clone(),
            requests_per_window: r.requests_per_window,
            window_duration: Duration::from_secs(r.window_secs),
            min_delay: Duration::from_millis(r.min_delay_ms),
            random_delay: Duration::from_millis(r.random_delay_ms),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_catch_all() {
        let s = RatelimitSection::default();
        assert!(s.rules.iter().any(|r| r.domain.is_empty()));
    }

    #[test]
    fn converts_to_domain_configs() {
        let s = RatelimitSection::default();
        let configs = s.to_domain_configs();
        assert_eq!(configs.len(), s.rules.len());
        assert_eq!(configs[0].domain, "*.reddit.com");
    }
}
```

- [ ] **Step 2: Register module in `src/config/mod.rs`**

Add `mod ratelimit;` and `pub use ratelimit::RatelimitSection;` after the existing modules.

Add field to `ServerConfig`:
```rust
pub ratelimit: RatelimitSection,
```

- [ ] **Step 3: Wire DomainLimiter in `serve.rs`**

After proxy pool init, before `HttpClient::new`:

```rust
// Per-domain rate limits.
let domain_configs = config.ratelimit.to_domain_configs();
if !domain_configs.is_empty() {
    http_config.rate_limiter = Some(Arc::new(ox_http::DomainLimiter::new(domain_configs)));
    tracing::info!("initialized domain rate limiter with {} rules", config.ratelimit.rules.len());
}
```

- [ ] **Step 4: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /home/krolik/src/ox-browser
git add src/config/ratelimit.rs src/config/mod.rs src/serve.rs
git commit -m "feat(ratelimit): wire DomainLimiter from TOML config with sensible defaults"
```

---

## Task 6: Remove `get_with_proxy` from HttpClient

After Task 2 (Reddit uses standalone client) and Task 3 (headless_read removed), `get_with_proxy` has no callers.

**Files:**
- Modify: `crates/http/src/client.rs`

- [ ] **Step 1: Verify no callers remain**

Run: `grep -r "get_with_proxy" /home/krolik/src/ox-browser/crates/ --include="*.rs"`
Expected: Only the definition in `client.rs`

- [ ] **Step 2: Remove the method**

Delete `get_with_proxy` method from `client.rs` (lines 89-94).

- [ ] **Step 3: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
cd /home/krolik/src/ox-browser
git add crates/http/src/client.rs
git commit -m "refactor(client): remove unused get_with_proxy method"
```

---

## Task 7: Deploy and verify

- [ ] **Step 1: Build Docker image**

```bash
cd ~/deploy/krolik-server
docker compose build ox-browser
```

- [ ] **Step 2: Deploy**

```bash
docker compose up -d --no-deps --force-recreate ox-browser
```

- [ ] **Step 3: Verify health**

```bash
curl -sf http://127.0.0.1:8901/health
```

- [ ] **Step 4: Test Reddit via MCP read tool**

```
ox-browser read tool: url="https://www.reddit.com/r/rust/" format="text"
```
Expected: Returns subreddit content, method="reddit-json"

- [ ] **Step 5: Test CF-protected site**

```
ox-browser read tool: url="https://nowsecure.nl" format="text"
```
Expected: Returns content, middleware chain handles CF

- [ ] **Step 6: Test normal site**

```
ox-browser read tool: url="https://habr.com" format="text"
```
Expected: Returns content, method="direct"

---

## Dependency Graph

```
Task 1 (debug logs) ─────────────────────────────────────────→ Task 7 (deploy)
Task 2 (reddit fix) ──→ Task 3 (quality middleware) ──→ Task 6 (cleanup) ──→ Task 7
Task 4 (WebsharePool) ────────────────────────────────────────→ Task 7
Task 5 (DomainLimiter) ───────────────────────────────────────→ Task 7
```

Tasks 1, 2, 4, 5 can run in parallel.
Task 3 depends on Task 2.
Task 6 depends on Tasks 2 and 3.
Task 7 depends on all others.

**Note on dead code:** go-code flagged `default_format`, `chrome_ua`, `fast_config` as dead — but all three are actually used (serde default, test helpers). Do NOT delete them.
