# Phase 2: Cloudflare Bypass — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable ox-browser to solve Cloudflare challenges by delegating to an external solver (Byparr/FlareSolverr), caching cookies, and providing a `CookieProvider` trait for go-stealth integration.

**Architecture:** Research (March 2026) shows that JS engine + DOM stubs (Boa/QuickJS) cannot solve modern CF challenges — they require Canvas, WebGL, Audio Context. The viable approach is: external stealth browser solver (Byparr) → extract `cf_clearance` cookies → cache per-domain with TTL → reuse in wreq HTTP client. The `CookieProvider` trait abstracts the solver, allowing swap between Byparr, FlareSolverr, or future alternatives. An HTTP endpoint (`POST /solve`) exposes this to go-stealth.

**Tech Stack:** Rust, wreq, async-trait, tokio, serde/serde_json, cookie_store (already in deps)

**Baseline:** 187 tests pass, ~5085 LOC, 6 crates (ox-http, ox-core, ox-js, ox-security, ox-crawler, ox-mcp)

**Key design decisions:**
- `ox-js` crate repurposed: no longer "JS engine" — becomes the CF solver client + cookie provider
- `CookieProvider` trait lives in `ox-http` (where CF detection already is)
- Cookie cache lives in `ox-http` (close to the middleware that needs it)
- Solver middleware sits between retry and cloudflare_detect in the chain
- External solver (Byparr) runs as Docker sidecar, called via HTTP

---

### Task 1: CookieProvider trait + types

**Files:**
- Create: `crates/http/src/cookie_provider.rs`
- Modify: `crates/http/src/lib.rs` (add module + re-exports)

**Step 1: Write the failing test**

Create `crates/http/src/cookie_provider.rs`:

```rust
use std::collections::HashMap;

use async_trait::async_trait;

use crate::cloudflare::ChallengeType;

/// A solved Cloudflare challenge: domain → cookies.
#[derive(Debug, Clone)]
pub struct SolvedChallenge {
    /// Cookies to inject (name → value), e.g. `cf_clearance → <token>`.
    pub cookies: HashMap<String, String>,
    /// User-Agent that was used to solve (must match subsequent requests).
    pub user_agent: String,
}

/// Trait for solving Cloudflare challenges and returning cookies.
///
/// Implementations may call external services (Byparr, FlareSolverr),
/// use a headless browser, or any other method.
#[async_trait]
pub trait CookieProvider: Send + Sync {
    /// Attempt to solve a CF challenge for the given URL.
    ///
    /// - `url`: the URL that returned the challenge
    /// - `challenge_type`: which CF challenge was detected
    ///
    /// Returns cookies on success, or an error string on failure.
    async fn solve(
        &self,
        url: &str,
        challenge_type: ChallengeType,
    ) -> Result<SolvedChallenge, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider;

    #[async_trait]
    impl CookieProvider for MockProvider {
        async fn solve(
            &self,
            _url: &str,
            _ct: ChallengeType,
        ) -> Result<SolvedChallenge, String> {
            let mut cookies = HashMap::new();
            cookies.insert("cf_clearance".into(), "test_token".into());
            Ok(SolvedChallenge {
                cookies,
                user_agent: "Mozilla/5.0 Test".into(),
            })
        }
    }

    #[tokio::test]
    async fn mock_provider_returns_cookies() {
        let provider = MockProvider;
        let result = provider
            .solve("https://example.com", ChallengeType::JsChallenge)
            .await
            .unwrap();
        assert!(result.cookies.contains_key("cf_clearance"));
        assert_eq!(result.cookies["cf_clearance"], "test_token");
    }

    #[tokio::test]
    async fn provider_is_object_safe() {
        let provider: Box<dyn CookieProvider> = Box::new(MockProvider);
        let result = provider
            .solve("https://example.com", ChallengeType::Turnstile)
            .await;
        assert!(result.is_ok());
    }
}
```

**Step 2: Run test to verify it fails**

```bash
cd ~/src/ox-browser && cargo test -p ox-http cookie_provider -v
```

Expected: compilation error (module not declared in lib.rs)

**Step 3: Wire module in lib.rs**

Add to `crates/http/src/lib.rs`:

```rust
pub mod cookie_provider;
```

And re-export:

```rust
pub use cookie_provider::{CookieProvider, SolvedChallenge};
```

**Step 4: Run test to verify it passes**

```bash
cd ~/src/ox-browser && cargo test -p ox-http cookie_provider -v
```

Expected: 2 tests pass

**Step 5: Commit**

```bash
git add crates/http/src/cookie_provider.rs crates/http/src/lib.rs
git commit -m "feat(http): add CookieProvider trait and SolvedChallenge type"
```

---

### Task 2: Cookie cache with per-domain TTL

**Files:**
- Create: `crates/http/src/cookie_cache.rs`
- Modify: `crates/http/src/lib.rs` (add module + re-exports)

**Step 1: Write the failing test**

Create `crates/http/src/cookie_cache.rs`:

```rust
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::cookie_provider::SolvedChallenge;

/// Cached challenge solution with expiry time.
struct CacheEntry {
    solution: SolvedChallenge,
    expires_at: Instant,
}

/// Thread-safe, per-domain cache for solved CF challenges.
///
/// Default TTL is 25 minutes (cf_clearance typically lasts 30 min).
pub struct CookieCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl CookieCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Get cached solution for a domain, if not expired.
    pub fn get(&self, domain: &str) -> Option<SolvedChallenge> {
        let entries = self.entries.read().expect("cache lock poisoned");
        let entry = entries.get(domain)?;
        if Instant::now() < entry.expires_at {
            Some(entry.solution.clone())
        } else {
            None
        }
    }

    /// Store a solved challenge for a domain.
    pub fn put(&self, domain: &str, solution: SolvedChallenge) {
        let mut entries = self.entries.write().expect("cache lock poisoned");
        entries.insert(
            domain.to_owned(),
            CacheEntry {
                solution,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    /// Remove expired entries.
    pub fn evict_expired(&self) {
        let mut entries = self.entries.write().expect("cache lock poisoned");
        let now = Instant::now();
        entries.retain(|_, e| now < e.expires_at);
    }

    /// Number of cached domains (including expired).
    pub fn len(&self) -> usize {
        self.entries.read().expect("cache lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for CookieCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(25 * 60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_solution(token: &str) -> SolvedChallenge {
        let mut cookies = HashMap::new();
        cookies.insert("cf_clearance".into(), token.into());
        SolvedChallenge {
            cookies,
            user_agent: "test-ua".into(),
        }
    }

    #[test]
    fn put_and_get() {
        let cache = CookieCache::default();
        cache.put("example.com", make_solution("abc123"));
        let sol = cache.get("example.com").unwrap();
        assert_eq!(sol.cookies["cf_clearance"], "abc123");
    }

    #[test]
    fn miss_on_unknown_domain() {
        let cache = CookieCache::default();
        assert!(cache.get("unknown.com").is_none());
    }

    #[test]
    fn expired_entry_returns_none() {
        let cache = CookieCache::new(Duration::from_millis(0));
        cache.put("example.com", make_solution("expired"));
        // TTL=0ms means already expired
        std::thread::sleep(Duration::from_millis(1));
        assert!(cache.get("example.com").is_none());
    }

    #[test]
    fn evict_removes_expired() {
        let cache = CookieCache::new(Duration::from_millis(0));
        cache.put("a.com", make_solution("a"));
        cache.put("b.com", make_solution("b"));
        std::thread::sleep(Duration::from_millis(1));
        cache.evict_expired();
        assert!(cache.is_empty());
    }

    #[test]
    fn overwrite_domain() {
        let cache = CookieCache::default();
        cache.put("example.com", make_solution("old"));
        cache.put("example.com", make_solution("new"));
        let sol = cache.get("example.com").unwrap();
        assert_eq!(sol.cookies["cf_clearance"], "new");
    }

    #[test]
    fn len_and_is_empty() {
        let cache = CookieCache::default();
        assert!(cache.is_empty());
        cache.put("a.com", make_solution("a"));
        assert_eq!(cache.len(), 1);
    }
}
```

**Step 2: Run test to verify it fails**

```bash
cd ~/src/ox-browser && cargo test -p ox-http cookie_cache -v
```

Expected: compilation error (module not declared)

**Step 3: Wire module in lib.rs**

Add to `crates/http/src/lib.rs`:

```rust
pub mod cookie_cache;
```

And re-export:

```rust
pub use cookie_cache::CookieCache;
```

**Step 4: Run test to verify it passes**

```bash
cd ~/src/ox-browser && cargo test -p ox-http cookie_cache -v
```

Expected: 6 tests pass

**Step 5: Commit**

```bash
git add crates/http/src/cookie_cache.rs crates/http/src/lib.rs
git commit -m "feat(http): add CookieCache with per-domain TTL"
```

---

### Task 3: Byparr solver (CookieProvider implementation)

**Files:**
- Create: `crates/http/src/solver_byparr.rs`
- Modify: `crates/http/src/lib.rs` (add module + re-exports)
- Modify: `crates/http/Cargo.toml` (no new deps needed — serde/serde_json already present)

**Step 1: Write the failing test**

Create `crates/http/src/solver_byparr.rs`:

```rust
//! Byparr/FlareSolverr-compatible solver — calls external HTTP API.
//!
//! API: `POST http://<host>:8191/v1` with JSON body.
//! Compatible with Byparr, FlareSolverr, and any drop-in replacement.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::cloudflare::ChallengeType;
use crate::cookie_provider::{CookieProvider, SolvedChallenge};

/// Byparr/FlareSolverr solver configuration.
#[derive(Debug, Clone)]
pub struct ByparrConfig {
    /// Base URL of the solver (e.g. `http://127.0.0.1:8191`).
    pub base_url: String,
    /// Timeout for solve requests (default 60s — CF challenges take ~10-30s).
    pub timeout: Duration,
}

impl Default for ByparrConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8191".into(),
            timeout: Duration::from_secs(60),
        }
    }
}

/// FlareSolverr-compatible request body.
#[derive(Serialize)]
struct SolverRequest {
    cmd: String,
    url: String,
    #[serde(rename = "maxTimeout")]
    max_timeout: u64,
}

/// FlareSolverr-compatible response.
#[derive(Deserialize)]
struct SolverResponse {
    status: String,
    solution: Option<SolverSolution>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct SolverSolution {
    url: String,
    cookies: Vec<SolverCookie>,
    #[serde(rename = "userAgent")]
    user_agent: String,
}

#[derive(Deserialize)]
struct SolverCookie {
    name: String,
    value: String,
}

/// Solver that calls a Byparr/FlareSolverr-compatible HTTP API.
pub struct ByparrSolver {
    config: ByparrConfig,
    client: wreq::Client,
}

impl ByparrSolver {
    pub fn new(config: ByparrConfig) -> Self {
        let client = wreq::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("failed to build solver HTTP client");
        Self { config, client }
    }
}

#[async_trait]
impl CookieProvider for ByparrSolver {
    async fn solve(
        &self,
        url: &str,
        _challenge_type: ChallengeType,
    ) -> Result<SolvedChallenge, String> {
        let endpoint = format!("{}/v1", self.config.base_url);
        let body = SolverRequest {
            cmd: "request.get".into(),
            url: url.to_owned(),
            max_timeout: self.config.timeout.as_millis() as u64,
        };

        let resp = self
            .client
            .post(&endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("solver request failed: {e}"))?;

        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("solver response read failed: {e}"))?;

        if status != 200 {
            return Err(format!("solver HTTP {status}: {text}"));
        }

        let parsed: SolverResponse =
            serde_json::from_str(&text).map_err(|e| format!("solver JSON parse: {e}"))?;

        if parsed.status != "ok" {
            return Err(format!(
                "solver error: {}",
                parsed.message.unwrap_or_default()
            ));
        }

        let solution = parsed
            .solution
            .ok_or_else(|| "solver returned ok but no solution".to_owned())?;

        let cookies = solution
            .cookies
            .into_iter()
            .map(|c| (c.name, c.value))
            .collect();

        Ok(SolvedChallenge {
            cookies,
            user_agent: solution.user_agent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = ByparrConfig::default();
        assert_eq!(cfg.base_url, "http://127.0.0.1:8191");
        assert_eq!(cfg.timeout, Duration::from_secs(60));
    }

    #[test]
    fn solver_request_serializes() {
        let req = SolverRequest {
            cmd: "request.get".into(),
            url: "https://example.com".into(),
            max_timeout: 60000,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"cmd\":\"request.get\""));
        assert!(json.contains("\"maxTimeout\":60000"));
    }

    #[test]
    fn solver_response_deserializes_ok() {
        let json = r#"{
            "status": "ok",
            "solution": {
                "url": "https://example.com",
                "cookies": [
                    {"name": "cf_clearance", "value": "abc123"}
                ],
                "userAgent": "Mozilla/5.0 Test"
            }
        }"#;
        let resp: SolverResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "ok");
        let sol = resp.solution.unwrap();
        assert_eq!(sol.cookies.len(), 1);
        assert_eq!(sol.cookies[0].name, "cf_clearance");
        assert_eq!(sol.user_agent, "Mozilla/5.0 Test");
    }

    #[test]
    fn solver_response_deserializes_error() {
        let json = r#"{
            "status": "error",
            "message": "Challenge not detected",
            "solution": null
        }"#;
        let resp: SolverResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "error");
        assert!(resp.solution.is_none());
        assert_eq!(resp.message.unwrap(), "Challenge not detected");
    }

    #[test]
    fn byparr_solver_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ByparrSolver>();
    }
}
```

**Step 2: Run test to verify it fails**

```bash
cd ~/src/ox-browser && cargo test -p ox-http solver_byparr -v
```

Expected: compilation error (module not declared)

**Step 3: Wire module in lib.rs**

Add to `crates/http/src/lib.rs`:

```rust
pub mod solver_byparr;
```

And re-export:

```rust
pub use solver_byparr::{ByparrConfig, ByparrSolver};
```

**Step 4: Run test to verify it passes**

```bash
cd ~/src/ox-browser && cargo test -p ox-http solver_byparr -v
```

Expected: 5 tests pass

**Step 5: Commit**

```bash
git add crates/http/src/solver_byparr.rs crates/http/src/lib.rs
git commit -m "feat(http): add ByparrSolver — FlareSolverr-compatible CookieProvider"
```

---

### Task 4: CF solver middleware

**Files:**
- Create: `crates/http/src/middleware_solver.rs`
- Modify: `crates/http/src/lib.rs` (add module + re-exports)
- Modify: `crates/http/src/config.rs` (add `cookie_provider` field)
- Modify: `crates/http/src/client.rs` (insert solver middleware in chain)

**Step 1: Write the failing test**

Create `crates/http/src/middleware_solver.rs`:

```rust
//! CF solver middleware — intercepts Cloudflare errors, solves via CookieProvider,
//! injects cookies, and retries the request.
//!
//! Chain position: `retry -> solver -> cloudflare_detect -> client_hints -> wreq`
//! The solver sits OUTSIDE cloudflare_detect so it catches `HttpError::Cloudflare`,
//! and INSIDE retry so the whole solve+retry is wrapped in retry logic.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::info;

use crate::cookie_cache::CookieCache;
use crate::cookie_provider::CookieProvider;
use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::{HttpResponse, Result};

/// Create a middleware that solves CF challenges via an external CookieProvider.
///
/// On `HttpError::Cloudflare`:
/// 1. Check cache for existing cookies
/// 2. If miss, call `provider.solve()` and cache result
/// 3. Inject cookies into request and retry once
///
/// On `Block` challenge type, does NOT attempt to solve (blocks are not solvable).
pub fn solver_middleware(
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
) -> MiddlewareFn {
    Arc::new(move |next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(SolverHandler {
            next,
            provider: Arc::clone(&provider),
            cache: Arc::clone(&cache),
        })
    })
}

struct SolverHandler {
    next: Arc<dyn Handler>,
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
}

/// Extract domain from URL for cache key.
fn domain_from_url(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_owned()))
        .unwrap_or_default()
}

#[async_trait]
impl Handler for SolverHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let domain = domain_from_url(&req.url);

        // Check cache first — inject cookies if available.
        if let Some(solution) = self.cache.get(&domain) {
            let mut req = req.clone();
            let cookie_header: String = solution
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            req.set_header("cookie", cookie_header);
            return self.next.handle(req).await;
        }

        // Try the request normally.
        match self.next.handle(req.clone()).await {
            Ok(resp) => Ok(resp),
            Err(HttpError::Cloudflare(ct, status, ray)) => {
                // Blocks are not solvable.
                if ct == crate::cloudflare::ChallengeType::Block {
                    return Err(HttpError::Cloudflare(ct, status, ray));
                }

                info!(url = %req.url, challenge = %ct, "solving CF challenge");

                // Call external solver.
                let solution = self
                    .provider
                    .solve(&req.url, ct)
                    .await
                    .map_err(|e| HttpError::ProxyPool(format!("CF solve failed: {e}")))?;

                // Cache the solution.
                self.cache.put(&domain, solution.clone());

                // Retry with cookies injected.
                let mut req = req;
                let cookie_header: String = solution
                    .cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                req.set_header("cookie", cookie_header);
                self.next.handle(req).await
            }
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare::ChallengeType;
    use crate::cookie_provider::SolvedChallenge;
    use crate::middleware::chain;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use wreq::header::HeaderMap;

    struct MockProvider {
        call_count: AtomicUsize,
    }

    #[async_trait]
    impl CookieProvider for MockProvider {
        async fn solve(&self, _url: &str, _ct: ChallengeType) -> Result<SolvedChallenge, String> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let mut cookies = HashMap::new();
            cookies.insert("cf_clearance".into(), "solved_token".into());
            Ok(SolvedChallenge {
                cookies,
                user_agent: "test-ua".into(),
            })
        }
    }

    /// Handler that returns CF challenge on first call, 200 on subsequent.
    struct CfThenOkHandler {
        call_count: AtomicUsize,
    }

    #[async_trait]
    impl Handler for CfThenOkHandler {
        async fn handle(&self, req: Request) -> Result<HttpResponse> {
            let n = self.call_count.fetch_add(1, Ordering::SeqCst);
            if n == 0 && !req.has_header("cookie") {
                return Err(HttpError::Cloudflare(
                    ChallengeType::JsChallenge,
                    503,
                    "ray123".into(),
                ));
            }
            Ok(HttpResponse {
                status: 200,
                url: req.url,
                headers: HeaderMap::new(),
                body: req.header("cookie").unwrap_or("no-cookie").to_owned(),
            })
        }
    }

    struct AlwaysBlockHandler;

    #[async_trait]
    impl Handler for AlwaysBlockHandler {
        async fn handle(&self, _req: Request) -> Result<HttpResponse> {
            Err(HttpError::Cloudflare(
                ChallengeType::Block,
                403,
                "ray".into(),
            ))
        }
    }

    fn test_request() -> Request {
        Request {
            method: "GET".into(),
            url: "https://example.com/page".into(),
            headers: vec![],
            body: None,
        }
    }

    #[tokio::test]
    async fn solves_js_challenge_and_retries() {
        let provider = Arc::new(MockProvider {
            call_count: AtomicUsize::new(0),
        });
        let cache = Arc::new(CookieCache::new(Duration::from_secs(300)));
        let base: Arc<dyn Handler> = Arc::new(CfThenOkHandler {
            call_count: AtomicUsize::new(0),
        });
        let handler = chain(vec![solver_middleware(provider.clone(), cache)], base);
        let resp = handler.handle(test_request()).await.unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("cf_clearance=solved_token"));
        assert_eq!(provider.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn uses_cached_cookies() {
        let provider = Arc::new(MockProvider {
            call_count: AtomicUsize::new(0),
        });
        let cache = Arc::new(CookieCache::new(Duration::from_secs(300)));
        // Pre-fill cache
        let mut cookies = HashMap::new();
        cookies.insert("cf_clearance".into(), "cached_token".into());
        cache.put(
            "example.com",
            SolvedChallenge {
                cookies,
                user_agent: "test".into(),
            },
        );
        let base: Arc<dyn Handler> = Arc::new(CfThenOkHandler {
            call_count: AtomicUsize::new(0),
        });
        let handler = chain(
            vec![solver_middleware(provider.clone(), cache)],
            base,
        );
        let resp = handler.handle(test_request()).await.unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("cf_clearance=cached_token"));
        // Provider should NOT have been called (cache hit).
        assert_eq!(provider.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn block_not_solvable() {
        let provider = Arc::new(MockProvider {
            call_count: AtomicUsize::new(0),
        });
        let cache = Arc::new(CookieCache::new(Duration::from_secs(300)));
        let base: Arc<dyn Handler> = Arc::new(AlwaysBlockHandler);
        let handler = chain(vec![solver_middleware(provider.clone(), cache)], base);
        let err = handler.handle(test_request()).await.unwrap_err();
        assert!(matches!(err, HttpError::Cloudflare(ChallengeType::Block, _, _)));
        // Provider should NOT be called for blocks.
        assert_eq!(provider.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn passes_through_normal_requests() {
        let provider = Arc::new(MockProvider {
            call_count: AtomicUsize::new(0),
        });
        let cache = Arc::new(CookieCache::new(Duration::from_secs(300)));
        let base: Arc<dyn Handler> = Arc::new(CfThenOkHandler {
            call_count: AtomicUsize::new(1), // skip the CF path
        });
        let handler = chain(vec![solver_middleware(provider.clone(), cache)], base);
        let resp = handler.handle(test_request()).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(provider.call_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn domain_extraction() {
        assert_eq!(domain_from_url("https://example.com/path"), "example.com");
        assert_eq!(domain_from_url("https://sub.example.com"), "sub.example.com");
        assert_eq!(domain_from_url("invalid"), "");
    }
}
```

**Step 2: Run test to verify it fails**

```bash
cd ~/src/ox-browser && cargo test -p ox-http middleware_solver -v
```

Expected: compilation error (module not declared)

**Step 3: Wire module in lib.rs**

Add to `crates/http/src/lib.rs`:

```rust
pub mod middleware_solver;
```

And re-export:

```rust
pub use middleware_solver::solver_middleware;
```

**Step 4: Run test to verify it passes**

```bash
cd ~/src/ox-browser && cargo test -p ox-http middleware_solver -v
```

Expected: 5 tests pass

**Step 5: Wire into HttpConfig and HttpClient**

Add to `crates/http/src/config.rs`:

```rust
use crate::cookie_cache::CookieCache;
use crate::cookie_provider::CookieProvider;
// ... in HttpConfig struct:
    /// External CF challenge solver (Byparr, FlareSolverr, etc.).
    /// When set with `cloudflare_detect`, solver middleware auto-solves challenges.
    pub cookie_provider: Option<Arc<dyn CookieProvider>>,
    /// Cookie cache for solved CF challenges. Shared across sessions.
    pub cookie_cache: Option<Arc<CookieCache>>,
```

Add solver middleware to chain in `crates/http/src/client.rs`, between retry and cloudflare_detect:

```rust
// After retry middleware, before cloudflare_detect:
if let (Some(ref provider), Some(ref cache)) = (&config.cookie_provider, &config.cookie_cache) {
    middlewares.push(solver_middleware(Arc::clone(provider), Arc::clone(cache)));
}
```

**Step 6: Run full test suite**

```bash
cd ~/src/ox-browser && cargo test --workspace
```

Expected: all 187 + new tests pass (existing tests use default config with `cookie_provider: None`)

**Step 7: Commit**

```bash
git add crates/http/src/middleware_solver.rs crates/http/src/lib.rs \
    crates/http/src/config.rs crates/http/src/client.rs
git commit -m "feat(http): add solver middleware — auto-solve CF challenges via CookieProvider"
```

---

### Task 5: HTTP API endpoint (POST /solve)

**Files:**
- Repurpose: `crates/js/Cargo.toml` (rename crate to `ox-solver`, add deps)
- Create: `crates/js/src/lib.rs` (HTTP server with `/solve` and `/health`)
- Modify: `Cargo.toml` (workspace — rename member)

**Note:** We repurpose the empty `ox-js` crate since the original Boa plan is abandoned.
Actually, keep it as `ox-js` for now (avoid workspace churn) but make it the solver server.

**Step 1: Update `crates/js/Cargo.toml`**

```toml
[package]
name = "ox-js"
version.workspace = true
edition.workspace = true

[dependencies]
ox-http = { path = "../http" }
axum = "0.8"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio.workspace = true
tracing.workspace = true
```

**Step 2: Write the server code**

Create `crates/js/src/lib.rs`:

```rust
//! ox-browser CF solver HTTP server.
//!
//! Exposes `POST /solve` for go-stealth to request CF challenge solutions.
//! Delegates to a configured `CookieProvider` (Byparr by default).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use ox_http::cloudflare::ChallengeType;
use ox_http::cookie_cache::CookieCache;
use ox_http::cookie_provider::CookieProvider;

/// Shared state for the solver server.
#[derive(Clone)]
pub struct SolverState {
    pub provider: Arc<dyn CookieProvider>,
    pub cache: Arc<CookieCache>,
}

/// Request body for `POST /solve`.
#[derive(Deserialize)]
pub struct SolveRequest {
    pub url: String,
    #[serde(default = "default_challenge")]
    pub challenge_type: String,
}

fn default_challenge() -> String {
    "js_challenge".into()
}

/// Response body for `POST /solve`.
#[derive(Serialize)]
pub struct SolveResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookies: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Build the Axum router for the solver server.
pub fn router(state: SolverState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/solve", post(solve))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn solve(
    State(state): State<SolverState>,
    Json(req): Json<SolveRequest>,
) -> (StatusCode, Json<SolveResponse>) {
    let ct = match req.challenge_type.as_str() {
        "turnstile" | "managed_challenge" => ChallengeType::Turnstile,
        "block" => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SolveResponse {
                    status: "error".into(),
                    cookies: None,
                    user_agent: None,
                    error: Some("block challenges are not solvable".into()),
                }),
            );
        }
        _ => ChallengeType::JsChallenge,
    };

    // Check cache first.
    let domain = url::Url::parse(&req.url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_owned()))
        .unwrap_or_default();

    if let Some(cached) = state.cache.get(&domain) {
        return (
            StatusCode::OK,
            Json(SolveResponse {
                status: "ok".into(),
                cookies: Some(cached.cookies),
                user_agent: Some(cached.user_agent),
                error: None,
            }),
        );
    }

    match state.provider.solve(&req.url, ct).await {
        Ok(solution) => {
            state.cache.put(&domain, solution.clone());
            (
                StatusCode::OK,
                Json(SolveResponse {
                    status: "ok".into(),
                    cookies: Some(solution.cookies),
                    user_agent: Some(solution.user_agent),
                    error: None,
                }),
            )
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(SolveResponse {
                status: "error".into(),
                cookies: None,
                user_agent: None,
                error: Some(e),
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ox_http::cookie_provider::SolvedChallenge;
    use std::collections::HashMap;
    use std::time::Duration;
    use tower::ServiceExt;

    struct MockProvider;

    #[async_trait]
    impl CookieProvider for MockProvider {
        async fn solve(
            &self,
            _url: &str,
            _ct: ChallengeType,
        ) -> Result<SolvedChallenge, String> {
            let mut cookies = HashMap::new();
            cookies.insert("cf_clearance".into(), "test123".into());
            Ok(SolvedChallenge {
                cookies,
                user_agent: "TestAgent/1.0".into(),
            })
        }
    }

    fn test_state() -> SolverState {
        SolverState {
            provider: Arc::new(MockProvider),
            cache: Arc::new(CookieCache::new(Duration::from_secs(300))),
        }
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let app = router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn solve_returns_cookies() {
        let app = router(test_state());
        let body = serde_json::to_string(&SolveRequest {
            url: "https://example.com".into(),
            challenge_type: "js_challenge".into(),
        })
        .unwrap();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/solve")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 10_000)
            .await
            .unwrap();
        let result: SolveResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.status, "ok");
        assert!(result.cookies.unwrap().contains_key("cf_clearance"));
    }

    #[tokio::test]
    async fn solve_block_rejected() {
        let app = router(test_state());
        let body = r#"{"url":"https://example.com","challenge_type":"block"}"#;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/solve")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn solve_caches_result() {
        let state = test_state();
        let app = router(state.clone());
        let body = r#"{"url":"https://example.com","challenge_type":"js_challenge"}"#;
        // First call
        let _ = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/solve")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Cache should have entry
        assert!(state.cache.get("example.com").is_some());
    }
}
```

**Step 3: Run tests**

```bash
cd ~/src/ox-browser && cargo test -p ox-js -v
```

Expected: 4 tests pass

**Step 4: Commit**

```bash
git add crates/js/Cargo.toml crates/js/src/lib.rs
git commit -m "feat(solver): HTTP server with POST /solve for go-stealth integration"
```

---

### Task 6: Update ROADMAP and docs

**Files:**
- Modify: `docs/ROADMAP.md`

**Step 1: Update Phase 2 in ROADMAP.md**

Mark Phase 2a as "Architecture revised" — explain why Boa approach was abandoned.
Update Phase 2 tasks to reflect the new architecture:

```markdown
## Phase 2: Cloudflare Bypass (v0.2.0) ✅

**Goal:** Solve Cloudflare challenges via external solver, provide cookies to go-stealth.

**Architecture revision (March 2026):** Research showed that embedded JS engines (Boa/QuickJS)
cannot solve modern CF challenges — they require Canvas, WebGL, Audio Context (full browser surface).
New approach: external stealth browser solver (Byparr/Camoufox) + cookie caching + HTTP API.

### Phase 2a: CookieProvider + Solver Integration

- [x] `CookieProvider` trait: `async fn solve(url, challenge_type) -> SolvedChallenge`
- [x] `CookieCache`: per-domain TTL cache (25min default, matching cf_clearance lifetime)
- [x] `ByparrSolver`: FlareSolverr-compatible HTTP client (Byparr, FlareSolverr, any drop-in)
- [x] `solver_middleware`: intercepts HttpError::Cloudflare, solves, injects cookies, retries
- [x] Block challenges correctly passed through (not solvable)

### Phase 2b: HTTP API for go-stealth

- [x] `POST /solve` endpoint (accepts URL + challenge_type, returns cookies)
- [x] `/health` endpoint
- [x] Cache-aware (returns cached cookies on repeat requests)
- [x] go-stealth integration: call ox-browser on HttpError::Cloudflare
```

**Step 2: Run full test suite one final time**

```bash
cd ~/src/ox-browser && cargo test --workspace
```

Expected: all tests pass (187 original + ~22 new)

**Step 3: Commit**

```bash
git add docs/ROADMAP.md
git commit -m "docs: update ROADMAP — Phase 2 architecture revised, tasks complete"
```

---

## Dependency Summary

| Task | Depends On | Creates |
|------|-----------|---------|
| 1. CookieProvider trait | — | `cookie_provider.rs` |
| 2. CookieCache | Task 1 (uses `SolvedChallenge`) | `cookie_cache.rs` |
| 3. ByparrSolver | Task 1 (implements `CookieProvider`) | `solver_byparr.rs` |
| 4. Solver middleware | Task 1 + 2 | `middleware_solver.rs`, config/client changes |
| 5. HTTP API server | Task 1 + 2 | `crates/js/src/lib.rs` |
| 6. ROADMAP update | All above | docs update |

Tasks 1→2→3 are sequential. Tasks 4 and 5 can run in parallel after Task 2.
