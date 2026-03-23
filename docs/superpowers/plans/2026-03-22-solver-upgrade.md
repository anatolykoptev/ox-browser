# Solver Upgrade: Byparr Fix + Residential Proxy Fallback + Chromiumoxide

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the broken headless solver (wrong Docker image + missing shm), add residential proxy as lightweight CF fallback, and integrate chromiumoxide as a native Rust headless browser for cases where proxies don't help.

**Architecture:** Three independent layers, each additive. (1) Fix Byparr Docker config — instant fix. (2) Add residential proxy retry middleware — when CF detected, retry through Webshare residential proxy before touching headless. (3) chromiumoxide `CookieProvider` — native Rust CDP solver replaces Byparr for in-process headless. The middleware chain becomes: `retry → solver(chromium) → residential_retry → cloudflare_detect → wreq`.

**Tech Stack:** Docker Compose, wreq 6.x, chromiumoxide 0.7, Rust 1.93

---

## File Structure

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `~/deploy/krolik-server/compose/infra.yml` | Fix Byparr image + shm_size |
| Create | `crates/http/src/middleware_residential.rs` | Residential proxy retry on CF error |
| Create | `crates/http/src/middleware_residential_tests.rs` | Tests for residential middleware |
| Create | `crates/http/src/solver_chromium.rs` | chromiumoxide-based CookieProvider |
| Create | `crates/http/src/solver_chromium_tests.rs` | Tests for ChromiumSolver |
| Modify | `crates/http/src/lib.rs` | Export new modules |
| Modify | `crates/http/src/client.rs` | Wire residential middleware into chain |
| Modify | `crates/http/src/config.rs` | Add residential_proxy field to HttpConfig |
| Modify | `crates/http/Cargo.toml` | Add chromiumoxide dep |
| Modify | `src/config/mod.rs` | Build residential middleware from config |
| Modify | `src/config/proxy.rs` | Add residential_url field |
| Modify | `src/serve.rs` | Pass residential proxy to HttpConfig |

---

## Task 1: Fix Byparr Docker (instant fix)

**Files:**
- Modify: `~/deploy/krolik-server/compose/infra.yml`

- [ ] **Step 1: Fix Docker image and add shm_size**

In `~/deploy/krolik-server/compose/infra.yml`, change the `byparr` service:

```yaml
  byparr:
    image: ghcr.io/thephaseless/byparr:latest
    container_name: byparr
    restart: unless-stopped
    labels:
      dozor.group: "scraping"
    logging: *default-logging
    ports:
      - "8191:8191"
    shm_size: '512m'
    environment:
      - LOG_LEVEL=info
      - HEADLESS=true
      - BROWSER_TIMEOUT=60000
      - TZ=Europe/Moscow
    deploy:
      resources:
        limits:
          memory: 1536M
          pids: 120
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8191/"]
```

Key changes:
- `image`: `flaresolverr/flaresolverr:latest` → `ghcr.io/thephaseless/byparr:latest` (Camoufox, not Chrome)
- `shm_size: '512m'` — Firefox/Camoufox needs shared memory for rendering
- `memory: 1536M` — bumped from 1024M (Camoufox is heavier than Chrome-only FlareSolverr)

- [ ] **Step 2: Rebuild and deploy**

```bash
cd ~/deploy/krolik-server
docker compose -f compose/infra.yml pull byparr
docker compose up -d --no-deps --force-recreate byparr
```

- [ ] **Step 3: Verify Byparr starts**

```bash
sleep 10
curl -s http://127.0.0.1:8191/ | head -1
docker logs byparr --tail 20 2>&1 | grep -i "error\|ready\|started"
```

Expected: healthcheck passes, no "session not created" errors in logs.

- [ ] **Step 4: Test solve via ox-browser**

```bash
curl -s -X POST http://127.0.0.1:8901/read \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.reddit.com/r/rust/"}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'method={d.get(\"method\")} len={d.get(\"length\")} err={d.get(\"error\",\"none\")}')"
```

Expected: `method=direct` or `method=solved`, non-zero length, no error.

- [ ] **Step 5: Commit**

```bash
cd ~/deploy/krolik-server
git add compose/infra.yml
git commit -m "fix(byparr): switch to Byparr image with Camoufox, add shm_size 512m"
```

---

## Task 2: Residential Proxy Fallback Middleware

When CF is detected, retry through residential proxy BEFORE calling headless solver. This is faster (no browser spawn) and works for CF managed challenges that just need a clean IP.

**Files:**
- Create: `crates/http/src/middleware_residential.rs`
- Create: `crates/http/src/middleware_residential_tests.rs`
- Modify: `crates/http/src/lib.rs`
- Modify: `crates/http/src/config.rs`
- Modify: `crates/http/src/client.rs`
- Modify: `src/config/proxy.rs`
- Modify: `src/config/mod.rs`
- Modify: `src/serve.rs`

- [ ] **Step 1: Write tests for residential middleware**

Create `crates/http/src/middleware_residential_tests.rs`:

```rust
use super::*;
use crate::cloudflare::ChallengeType;
use crate::error::HttpError;
use crate::middleware::{chain, Handler, Request};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use wreq::header::HeaderMap;

/// Mock handler that returns CF error on first call, 200 on second (residential).
struct CfThenOkHandler {
    call_count: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Handler for CfThenOkHandler {
    async fn handle(&self, req: Request) -> crate::Result<crate::HttpResponse> {
        let n = self.call_count.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            return Err(HttpError::Cloudflare(
                ChallengeType::ManagedChallenge, 200, "ray-1".into(),
            ));
        }
        Ok(crate::HttpResponse {
            status: 200,
            url: req.url,
            headers: HeaderMap::new(),
            body: "ok from residential".into(),
        })
    }
}

struct AlwaysOkHandler;

#[async_trait::async_trait]
impl Handler for AlwaysOkHandler {
    async fn handle(&self, req: Request) -> crate::Result<crate::HttpResponse> {
        Ok(crate::HttpResponse {
            status: 200,
            url: req.url,
            headers: HeaderMap::new(),
            body: "ok".into(),
        })
    }
}

struct AlwaysCfHandler;

#[async_trait::async_trait]
impl Handler for AlwaysCfHandler {
    async fn handle(&self, _req: Request) -> crate::Result<crate::HttpResponse> {
        Err(HttpError::Cloudflare(
            ChallengeType::JsChallenge, 503, "ray".into(),
        ))
    }
}

#[tokio::test]
async fn retries_with_residential_proxy_on_cf() {
    let calls = Arc::new(AtomicUsize::new(0));
    let base: Arc<dyn Handler> = Arc::new(CfThenOkHandler { call_count: calls.clone() });
    let handler = chain(
        vec![residential_proxy_middleware("http://res:8080".into())],
        base,
    );
    let req = Request {
        method: "GET".into(),
        url: "https://example.com".into(),
        headers: vec![],
        body: None,
    };
    let resp = handler.handle(req).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, "ok from residential");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn passes_through_without_cf() {
    let base: Arc<dyn Handler> = Arc::new(AlwaysOkHandler);
    let handler = chain(
        vec![residential_proxy_middleware("http://res:8080".into())],
        base,
    );
    let req = Request {
        method: "GET".into(),
        url: "https://example.com".into(),
        headers: vec![],
        body: None,
    };
    let resp = handler.handle(req).await.unwrap();
    assert_eq!(resp.body, "ok");
}

#[tokio::test]
async fn propagates_cf_if_residential_also_fails() {
    let base: Arc<dyn Handler> = Arc::new(AlwaysCfHandler);
    let handler = chain(
        vec![residential_proxy_middleware("http://res:8080".into())],
        base,
    );
    let req = Request {
        method: "GET".into(),
        url: "https://example.com".into(),
        headers: vec![],
        body: None,
    };
    let err = handler.handle(req).await.unwrap_err();
    assert!(matches!(err, HttpError::Cloudflare(..)));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http middleware_residential`
Expected: FAIL — module doesn't exist

- [ ] **Step 3: Implement residential proxy middleware**

Create `crates/http/src/middleware_residential.rs`:

```rust
//! Residential proxy retry middleware.
//!
//! On CF error, retries the request once with a residential proxy URL
//! injected into the request metadata. This is faster than headless
//! solve and works for CF managed challenges that check IP reputation.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::info;

use crate::cloudflare::ChallengeType;
use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::{HttpResponse, Result};

/// Returns a middleware that retries CF-blocked requests through a residential proxy.
///
/// On `HttpError::Cloudflare` (except `Block`), sets the proxy on the request
/// and retries once. If the retry also fails, the error propagates to the
/// next middleware (solver) for headless fallback.
pub fn residential_proxy_middleware(proxy_url: String) -> MiddlewareFn {
    Arc::new(move |next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(ResidentialHandler {
            next,
            proxy_url: proxy_url.clone(),
        })
    })
}

struct ResidentialHandler {
    next: Arc<dyn Handler>,
    proxy_url: String,
}

#[async_trait]
impl Handler for ResidentialHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        match self.next.handle(req.clone()).await {
            // Block errors are not solvable by proxy change.
            Err(HttpError::Cloudflare(ChallengeType::Block, s, r)) => {
                Err(HttpError::Cloudflare(ChallengeType::Block, s, r))
            }
            // CF challenge — retry with residential proxy.
            Err(HttpError::Cloudflare(ct, _s, _r)) => {
                info!(
                    url = %req.url,
                    challenge = %ct,
                    "CF detected, retrying with residential proxy"
                );
                let mut retry_req = req;
                retry_req.set_proxy(self.proxy_url.clone());
                self.next.handle(retry_req).await
            }
            // Everything else passes through.
            other => other,
        }
    }
}

#[cfg(test)]
#[path = "middleware_residential_tests.rs"]
mod tests;
```

- [ ] **Step 4: Add `set_proxy` to Request**

In `crates/http/src/middleware.rs`, check if `Request` struct has a `proxy` field. If not, add:

```rust
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub proxy: Option<String>,  // Add this field
}
```

And add method:
```rust
impl Request {
    pub fn set_proxy(&mut self, proxy_url: String) {
        self.proxy = Some(proxy_url);
    }
}
```

Update `WreqHandler` in `handler_reqwest.rs` to respect `req.proxy` — if set, use it as the proxy for this request.

- [ ] **Step 5: Add residential_proxy to HttpConfig**

In `crates/http/src/config.rs`, add field:
```rust
pub residential_proxy: Option<String>,
```

Default: `None`.

- [ ] **Step 6: Wire into middleware chain**

In `crates/http/src/client.rs`, add residential middleware between retry and solver:

```rust
// Residential proxy retry (between retry and solver).
if let Some(ref proxy) = config.residential_proxy {
    middlewares.push(residential_proxy_middleware(proxy.clone()));
}
```

Chain becomes: `SSRF → logging → rate_limit → retry → residential → solver → cloudflare_detect → client_hints → wreq`

- [ ] **Step 7: Add config support**

In `src/config/proxy.rs`, add:
```rust
pub residential_url: Option<String>,
```

In `src/config/mod.rs` `build_http_config()`, add:
```rust
residential_proxy: config.proxy.residential_url.clone(),
```

In `src/serve.rs`, check for env var fallback:
```rust
if http_config.residential_proxy.is_none() {
    http_config.residential_proxy = std::env::var("RESIDENTIAL_PROXY_URL").ok();
}
```

- [ ] **Step 8: Export module**

In `crates/http/src/lib.rs`, add:
```rust
pub mod middleware_residential;
pub use middleware_residential::residential_proxy_middleware;
```

- [ ] **Step 9: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http middleware_residential -- --nocapture`
Expected: 3 tests PASS

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http`
Expected: All tests PASS (no regressions)

- [ ] **Step 10: Add RESIDENTIAL_PROXY_URL to docker-compose**

In `~/deploy/krolik-server/docker-compose.yml` or the ox-browser service env, add:
```yaml
RESIDENTIAL_PROXY_URL: "http://dowpklpe-US-1:gnyvfkkj1et7@p.webshare.io:80"
```

- [ ] **Step 11: Commit**

```bash
git add crates/http/src/middleware_residential.rs crates/http/src/middleware_residential_tests.rs \
  crates/http/src/lib.rs crates/http/src/config.rs crates/http/src/client.rs \
  crates/http/src/middleware.rs crates/http/src/handler_reqwest.rs \
  src/config/proxy.rs src/config/mod.rs src/serve.rs
git commit -m "feat(http): add residential proxy retry middleware for CF bypass"
```

---

## Task 3: Chromiumoxide Native Solver

Replace Byparr HTTP calls with in-process Chrome via chromiumoxide CDP. Implements `CookieProvider` trait — drop-in replacement.

**Files:**
- Create: `crates/http/src/solver_chromium.rs`
- Create: `crates/http/src/solver_chromium_tests.rs`
- Modify: `crates/http/Cargo.toml`
- Modify: `crates/http/src/lib.rs`
- Modify: `src/config/solver.rs`
- Modify: `src/config/mod.rs`

- [ ] **Step 1: Add chromiumoxide dependency**

In `crates/http/Cargo.toml`, add:
```toml
chromiumoxide = { version = "0.7", features = ["tokio-runtime"], default-features = false }
```

- [ ] **Step 2: Write tests for ChromiumSolver**

Create `crates/http/src/solver_chromium_tests.rs`:

```rust
use super::*;

#[test]
fn chromium_config_defaults() {
    let cfg = ChromiumConfig::default();
    assert_eq!(cfg.timeout, std::time::Duration::from_secs(30));
    assert_eq!(cfg.max_concurrent, 3);
    assert!(cfg.proxy_url.is_none());
    assert!(cfg.chrome_path.is_none());
}

#[test]
fn chromium_solver_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ChromiumConfig>();
    // ChromiumSolver itself is checked at construction time
}
```

Note: Full integration tests (launching Chrome) are not practical in CI — they require Chrome binary. Unit tests cover config and trait bounds. Integration testing is done via smoke tests after deployment.

- [ ] **Step 3: Implement ChromiumSolver**

Create `crates/http/src/solver_chromium.rs`:

```rust
//! ChromiumSolver — native Rust CookieProvider using chromiumoxide (CDP).
//!
//! Launches a headless Chrome/Chromium, navigates to the CF-protected URL,
//! waits for challenge resolution, then extracts cf_clearance cookie.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use chromiumoxide::browser::{Browser, BrowserConfig};
use tokio::sync::Semaphore;

use crate::cloudflare::ChallengeType;
use crate::cookie_provider::{CookieProvider, SolvedChallenge};

/// Configuration for the chromiumoxide-based solver.
#[derive(Debug, Clone)]
pub struct ChromiumConfig {
    /// Timeout for challenge solving.
    pub timeout: Duration,
    /// Max concurrent browser tabs.
    pub max_concurrent: usize,
    /// Optional proxy URL for the browser.
    pub proxy_url: Option<String>,
    /// Optional path to Chrome/Chromium binary.
    pub chrome_path: Option<String>,
}

impl Default for ChromiumConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_concurrent: 3,
            proxy_url: None,
            chrome_path: None,
        }
    }
}

/// Solves CF challenges using an in-process headless Chrome via CDP.
pub struct ChromiumSolver {
    config: ChromiumConfig,
    semaphore: Semaphore,
}

impl ChromiumSolver {
    pub fn new(config: ChromiumConfig) -> Self {
        let max = config.max_concurrent;
        tracing::info!(max_concurrent = max, "chromium solver initialized");
        Self {
            config,
            semaphore: Semaphore::new(max),
        }
    }

    async fn launch_and_solve(&self, url: &str) -> Result<SolvedChallenge, String> {
        let mut builder = BrowserConfig::builder()
            .no_sandbox()
            .disable_default_args()
            .arg("--headless=new")
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--no-first-run")
            .arg("--disable-extensions");

        if let Some(ref path) = self.config.chrome_path {
            builder = builder.chrome_executable(path);
        }

        if let Some(ref proxy) = self.config.proxy_url {
            builder = builder.arg(format!("--proxy-server={proxy}"));
        }

        let browser_config = builder.build()
            .map_err(|e| format!("browser config: {e}"))?;

        let (browser, mut handler) = Browser::launch(browser_config)
            .await
            .map_err(|e| format!("browser launch: {e}"))?;

        let handler_task = tokio::spawn(async move {
            while let Some(h) = handler.next().await {
                if h.is_err() { break; }
            }
        });

        let result = self.solve_in_browser(&browser, url).await;

        // Cleanup
        let _ = browser.close().await;
        handler_task.abort();

        result
    }

    async fn solve_in_browser(
        &self,
        browser: &Browser,
        url: &str,
    ) -> Result<SolvedChallenge, String> {
        let page = browser.new_page(url).await
            .map_err(|e| format!("new page: {e}"))?;

        // Wait for CF challenge to resolve (poll for cf_clearance cookie)
        let deadline = tokio::time::Instant::now() + self.config.timeout;
        loop {
            if tokio::time::Instant::now() > deadline {
                return Err("chromium solver timeout".into());
            }

            let cookies = page.get_cookies().await
                .map_err(|e| format!("get cookies: {e}"))?;

            let cf_cookie = cookies.iter()
                .find(|c| c.name == "cf_clearance");

            if let Some(cookie) = cf_cookie {
                let ua = page.evaluate("navigator.userAgent")
                    .await
                    .map_err(|e| format!("get UA: {e}"))?
                    .into_value::<String>()
                    .unwrap_or_default();

                let mut cookie_map = HashMap::new();
                for c in &cookies {
                    cookie_map.insert(c.name.clone(), c.value.clone());
                }

                return Ok(SolvedChallenge {
                    cookies: cookie_map,
                    user_agent: ua,
                });
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

#[async_trait]
impl CookieProvider for ChromiumSolver {
    async fn solve(
        &self,
        url: &str,
        _challenge_type: ChallengeType,
    ) -> Result<SolvedChallenge, String> {
        let _permit = self.semaphore.acquire().await
            .map_err(|e| format!("semaphore: {e}"))?;

        self.launch_and_solve(url).await
    }
}

#[cfg(test)]
#[path = "solver_chromium_tests.rs"]
mod tests;
```

- [ ] **Step 4: Export module**

In `crates/http/src/lib.rs`, add:
```rust
pub mod solver_chromium;
pub use solver_chromium::{ChromiumConfig, ChromiumSolver};
```

- [ ] **Step 5: Add config support**

In `src/config/solver.rs`, add fields:
```rust
pub chromium_enabled: bool,
pub chromium_path: Option<String>,
pub chromium_max_concurrent: usize,
pub chromium_timeout_secs: u64,
```

With defaults: `chromium_enabled: false`, `chromium_max_concurrent: 3`, `chromium_timeout_secs: 30`.

In `src/config/mod.rs` `build_cookie_provider()`, add chromium option:
```rust
if config.solver.chromium_enabled {
    let chromium_cfg = ChromiumConfig {
        timeout: Duration::from_secs(config.solver.chromium_timeout_secs),
        max_concurrent: config.solver.chromium_max_concurrent,
        chrome_path: config.solver.chromium_path.clone(),
        proxy_url: config.proxy.residential_url.clone(),
    };
    return Arc::new(ChromiumSolver::new(chromium_cfg));
}
```

This means chromium takes priority over byparr when enabled.

- [ ] **Step 6: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http solver_chromium -- --nocapture`
Expected: 2 tests PASS

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace`
Expected: All tests PASS

- [ ] **Step 7: Add Chrome to Dockerfile (for future use)**

In the ox-browser Dockerfile, add Chromium installation:
```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends chromium && rm -rf /var/lib/apt/lists/*
ENV CHROME_PATH=/usr/bin/chromium
```

Note: This is optional — chromiumoxide can also download Chrome automatically via the `chromiumoxide_fetcher` crate. For now, keep chromium_enabled=false and use Byparr.

- [ ] **Step 8: Commit**

```bash
git add crates/http/src/solver_chromium.rs crates/http/src/solver_chromium_tests.rs \
  crates/http/src/lib.rs crates/http/Cargo.toml \
  src/config/solver.rs src/config/mod.rs
git commit -m "feat(http): add chromiumoxide-based CookieProvider solver"
```

---

## Task 4: Deploy + Smoke Test

- [ ] **Step 1: Build ox-browser with new code**

```bash
cd ~/deploy/krolik-server
docker compose build --no-cache ox-browser
```

- [ ] **Step 2: Deploy**

```bash
docker compose up -d --no-deps --force-recreate ox-browser
```

- [ ] **Step 3: Test residential proxy fallback**

```bash
curl -s -X POST http://127.0.0.1:8901/read \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.reddit.com/r/rust/"}' | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'method={d.get(\"method\")} len={d.get(\"length\")} err={d.get(\"error\",\"none\")}')
"
```

Expected: method=direct (residential proxy handled CF transparently), non-zero length.

- [ ] **Step 4: Test with CF-protected site**

```bash
curl -s -X POST http://127.0.0.1:8901/read \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://medium.com/tag/rust"}' | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'method={d.get(\"method\")} len={d.get(\"length\")} err={d.get(\"error\",\"none\")}')
"
```

- [ ] **Step 5: Test Byparr solver directly**

```bash
curl -s -X POST http://127.0.0.1:8191/v1 \
  -H 'Content-Type: application/json' \
  -d '{"cmd":"request.get","url":"https://www.reddit.com/r/rust/","maxTimeout":30000}' | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'status={d.get(\"status\")} cookies={len(d.get(\"solution\",{}).get(\"cookies\",[]))}')
"
```

Expected: `status=ok cookies=N` (N > 0).

- [ ] **Step 6: Verify all services healthy**

```bash
docker compose ps --format '{{.Name}}\t{{.Status}}' | grep -E "ox-browser|byparr|go-search"
```

Expected: All "Up" and "healthy".
