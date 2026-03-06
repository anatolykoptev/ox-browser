# ox-browser Approach B: CF Detection + /fetch + Smart Fallback

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend ox-browser with HTTP 200 CF detection, fast `/fetch` endpoint (wreq+BoringSSL), smart `/fetch-smart` endpoint (TLS-first → headless fallback), Docker deployment, and go-engine integration.

**Architecture:** Three-layer fallback chain: go-stealth proxy → ox-browser `/fetch-smart` → Byparr. ox-browser's `/fetch-smart` internally does wreq fetch → CF detection → headless solve → retry with cookies. Cookie cache (already exists) reuses cf_clearance across requests.

**Tech Stack:** Rust (ox-http, ox-js crates), wreq+BoringSSL, axum, Docker, Go (go-engine/fetch)

---

### Task 1: Extend CF Detection for HTTP 200

**Files:**
- Modify: `crates/http/src/cloudflare.rs:34-84` (detect_cloudflare function + ChallengeType enum)
- Test: same file, `mod tests` section at line 86

**Context:**
- Current `detect_cloudflare()` returns `None` for any status != 403/503
- Need to detect CF challenges served at HTTP 200: Turnstile, Managed Challenge, JS Challenge
- Key markers from research: `cf-mitigated: challenge` header, `_cf_chl_opt` in body, `"Just a moment..."` title, `challenge-platform` scripts, `cf-browser-verification`
- `HttpResponse` has `status: u16`, `headers: HeaderMap`, `body: String`

**Step 1: Add ManagedChallenge variant to ChallengeType**

```rust
// In ChallengeType enum, add:
/// Managed challenge at HTTP 200 (interstitial page with JS or Turnstile)
ManagedChallenge,
```

Update Display impl:
```rust
Self::ManagedChallenge => write!(f, "managed_challenge_200"),
```

**Step 2: Write failing tests for HTTP 200 detection**

Add these tests to the existing `mod tests`:

```rust
#[test]
fn detects_cf_mitigated_header_at_200() {
    let mut headers = HeaderMap::new();
    headers.insert("server", "cloudflare".parse().unwrap());
    headers.insert("cf-mitigated", "challenge".parse().unwrap());
    let resp = HttpResponse {
        status: 200,
        url: "https://example.com".into(),
        headers,
        body: "<html>Just a moment...</html>".into(),
    };
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
    assert_eq!(cf.status, 200);
}

#[test]
fn detects_cf_chl_opt_at_200() {
    let mut headers = HeaderMap::new();
    headers.insert("server", "cloudflare".parse().unwrap());
    let resp = HttpResponse {
        status: 200,
        url: "https://example.com".into(),
        headers,
        body: "<html><script>window._cf_chl_opt={}</script></html>".into(),
    };
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
}

#[test]
fn detects_challenge_platform_at_200() {
    let mut headers = HeaderMap::new();
    headers.insert("server", "cloudflare".parse().unwrap());
    let resp = HttpResponse {
        status: 200,
        url: "https://example.com".into(),
        headers,
        body: "<html><script src=\"/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1\"></script></html>".into(),
    };
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::ManagedChallenge);
}

#[test]
fn ignores_normal_200_from_cloudflare() {
    let resp = cf_response(200, "<html><body>Normal page content</body></html>", "cloudflare");
    assert!(detect_cloudflare(&resp).is_none());
}

#[test]
fn detects_turnstile_at_200() {
    let mut headers = HeaderMap::new();
    headers.insert("server", "cloudflare".parse().unwrap());
    let resp = HttpResponse {
        status: 200,
        url: "https://example.com".into(),
        headers,
        body: "<html><div class=\"cf-turnstile\"></div></html>".into(),
    };
    let cf = detect_cloudflare(&resp).unwrap();
    assert_eq!(cf.challenge_type, ChallengeType::Turnstile);
}
```

**Step 3: Run tests to verify they fail**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http cloudflare::tests`
Expected: FAIL — new tests reference `ManagedChallenge` variant and 200 detection

**Step 4: Implement HTTP 200 detection**

Rewrite `detect_cloudflare()` in `crates/http/src/cloudflare.rs`:

```rust
pub fn detect_cloudflare(resp: &HttpResponse) -> Option<CloudflareChallenge> {
    let server = resp
        .headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !server.to_ascii_lowercase().contains("cloudflare") {
        return None;
    }

    let body = resp.body.to_ascii_lowercase();
    let ray_id = resp
        .headers
        .get("cf-ray")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    // --- HTTP 403/503 detection (existing logic) ---

    if resp.status == 403 || resp.status == 503 {
        // JS challenge: 503 + challenge-platform scripts
        if resp.status == 503 && body.contains("challenge-platform") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::JsChallenge,
                status: resp.status,
                ray_id,
            });
        }

        // Turnstile managed challenge
        if body.contains("turnstile-wrapper") || body.contains("cf-turnstile") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::Turnstile,
                status: resp.status,
                ray_id,
            });
        }

        // Block page
        if body.contains("you have been blocked") || body.contains("cf-error-details") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::Block,
                status: resp.status,
                ray_id,
            });
        }

        return None;
    }

    // --- HTTP 200 detection (new: interstitial challenges) ---

    if resp.status == 200 {
        // cf-mitigated header is the strongest signal
        let cf_mitigated = resp
            .headers
            .get("cf-mitigated")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if cf_mitigated.contains("challenge") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::ManagedChallenge,
                status: resp.status,
                ray_id,
            });
        }

        // Turnstile widget at 200
        if body.contains("cf-turnstile") || body.contains("turnstile-wrapper") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::Turnstile,
                status: resp.status,
                ray_id,
            });
        }

        // JS challenge markers at 200
        if body.contains("_cf_chl_opt") || body.contains("challenge-platform") {
            return Some(CloudflareChallenge {
                challenge_type: ChallengeType::ManagedChallenge,
                status: resp.status,
                ray_id,
            });
        }
    }

    None
}
```

**Step 5: Update the `ignores_200` test**

The existing `ignores_200` test at line 145 uses a body of `"<html>ok</html>"` which should still pass (no CF markers). Rename it for clarity:

```rust
#[test]
fn ignores_clean_200() {
    let resp = cf_response(200, "<html>ok</html>", "cloudflare");
    assert!(detect_cloudflare(&resp).is_none());
}
```

**Step 6: Run tests to verify all pass**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http cloudflare::tests`
Expected: all tests PASS

**Step 7: Update ManagedChallenge in middleware and solver**

In `crates/js/src/lib.rs`, add `"managed_challenge_200"` to the match in `solve()`:

```rust
"managed_challenge" | "managed_challenge_200" | "turnstile" => ChallengeType::Turnstile,
```

Actually, map it to ManagedChallenge:

```rust
"managed_challenge_200" => ChallengeType::ManagedChallenge,
"managed_challenge" | "turnstile" => ChallengeType::Turnstile,
```

And update the block match to handle ManagedChallenge as solvable (it falls through to the default JsChallenge handling).

In `crates/http/src/error.rs`, ensure `ManagedChallenge` is retryable (it already is — the `Cloudflare(_, _, _)` match arm covers all variants).

**Step 8: Commit**

```bash
cd /home/krolik/src/ox-browser
git add -A
git commit -m "feat: detect Cloudflare challenges at HTTP 200 (cf-mitigated, _cf_chl_opt, challenge-platform)"
```

---

### Task 2: Add POST /fetch Endpoint

**Files:**
- Create: `crates/js/src/fetch.rs`
- Modify: `crates/js/src/lib.rs:46-51` (add route)
- Modify: `crates/js/Cargo.toml` (add `wreq-util` dep if needed for Emulation)
- Test: `crates/js/src/fetch.rs` (inline tests)

**Context:**
- The Axum server in `crates/js/src/lib.rs` already has `SolverState` with `provider` and `cache`
- We need a new state that includes an `HttpClient` (from ox-http) for direct wreq fetches
- `HttpClient` already has `get()` method that returns `HttpResponse` with `status`, `headers`, `body`
- `detect_cloudflare()` works on `HttpResponse` directly

**Step 1: Create FetchState and extend SolverState**

We need to refactor the state to include an `HttpClient`. Create a new shared `AppState`:

In `crates/js/src/lib.rs`, replace `SolverState` with:

```rust
/// Shared state for the ox-browser HTTP server.
#[derive(Clone)]
pub struct AppState {
    pub provider: Arc<dyn CookieProvider>,
    pub cache: Arc<CookieCache>,
    pub http_client: Arc<ox_http::HttpClient>,
}
```

**Step 2: Write the fetch module**

Create `crates/js/src/fetch.rs`:

```rust
//! POST /fetch — fast wreq+BoringSSL fetch without headless browser.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_http::detect_cloudflare;
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Deserialize)]
pub struct FetchRequest {
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_timeout() -> u64 {
    15
}

#[derive(Serialize)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub cf_detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_type: Option<String>,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn fetch(
    State(state): State<AppState>,
    Json(req): Json<FetchRequest>,
) -> (StatusCode, Json<FetchResponse>) {
    let start = Instant::now();

    match state.http_client.get(&req.url).await {
        Ok(resp) => {
            let cf = detect_cloudflare(&resp);
            let cf_detected = cf.is_some();
            let cf_type = cf.map(|c| c.challenge_type.to_string());

            let headers: HashMap<String, String> = resp
                .headers
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_owned())))
                .collect();

            (
                StatusCode::OK,
                Json(FetchResponse {
                    status: resp.status,
                    headers,
                    body: resp.body,
                    cf_detected,
                    cf_type,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: None,
                }),
            )
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(FetchResponse {
                status: 0,
                headers: HashMap::new(),
                body: String::new(),
                cf_detected: false,
                cf_type: None,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some(e.to_string()),
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_request_defaults() {
        let json = r#"{"url": "https://example.com"}"#;
        let req: FetchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.url, "https://example.com");
        assert_eq!(req.timeout, 15);
        assert!(req.headers.is_empty());
    }

    #[test]
    fn fetch_response_serializes() {
        let resp = FetchResponse {
            status: 200,
            headers: HashMap::new(),
            body: "<html>ok</html>".into(),
            cf_detected: false,
            cf_type: None,
            elapsed_ms: 150,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], 200);
        assert_eq!(json["cf_detected"], false);
        assert!(!json.as_object().unwrap().contains_key("cf_type"));
        assert!(!json.as_object().unwrap().contains_key("error"));
    }

    #[test]
    fn fetch_response_with_cf() {
        let resp = FetchResponse {
            status: 200,
            headers: HashMap::new(),
            body: String::new(),
            cf_detected: true,
            cf_type: Some("managed_challenge_200".into()),
            elapsed_ms: 300,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["cf_detected"], true);
        assert_eq!(json["cf_type"], "managed_challenge_200");
    }
}
```

**Step 3: Write fetch_smart module**

Create `crates/js/src/fetch_smart.rs`:

```rust
//! POST /fetch-smart — two-stage fetch: wreq first, headless fallback on CF.

use std::collections::HashMap;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_http::{detect_cloudflare, ChallengeType};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::AppState;

#[derive(Deserialize)]
pub struct FetchSmartRequest {
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_timeout() -> u64 {
    30
}

#[derive(Serialize)]
pub struct FetchSmartResponse {
    pub status: u16,
    pub body: String,
    pub method: String, // "direct" or "solved"
    pub cf_detected: bool,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn fetch_smart(
    State(state): State<AppState>,
    Json(req): Json<FetchSmartRequest>,
) -> (StatusCode, Json<FetchSmartResponse>) {
    let start = Instant::now();
    let domain = Url::parse(&req.url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default();

    // Check cookie cache first — if we have cf_clearance, skip to direct with cookies.
    // (Cookie injection happens at HttpClient middleware level via solver_middleware.)

    // Stage 1: Fast wreq fetch
    match state.http_client.get(&req.url).await {
        Ok(resp) => {
            let cf = detect_cloudflare(&resp);
            if cf.is_none() {
                // No CF — return directly
                return (
                    StatusCode::OK,
                    Json(FetchSmartResponse {
                        status: resp.status,
                        body: resp.body,
                        method: "direct".into(),
                        cf_detected: false,
                        elapsed_ms: start.elapsed().as_millis() as u64,
                        error: None,
                    }),
                );
            }

            let challenge = cf.unwrap();
            tracing::info!(
                domain = %domain,
                challenge = %challenge.challenge_type,
                "CF detected, attempting headless solve"
            );

            // Stage 2: Block challenges are not solvable
            if challenge.challenge_type == ChallengeType::Block {
                return (
                    StatusCode::OK,
                    Json(FetchSmartResponse {
                        status: resp.status,
                        body: resp.body,
                        method: "direct".into(),
                        cf_detected: true,
                        elapsed_ms: start.elapsed().as_millis() as u64,
                        error: Some("CF block — not solvable".into()),
                    }),
                );
            }

            // Stage 2: Headless solve → get cookies → retry
            match state.provider.solve(&req.url, challenge.challenge_type).await {
                Ok(solved) => {
                    state.cache.put(&domain, solved.clone());
                    tracing::info!(domain = %domain, "CF solved, retrying with cookies");

                    // Retry the fetch — solver middleware will inject cached cookies
                    match state.http_client.get(&req.url).await {
                        Ok(retry_resp) => (
                            StatusCode::OK,
                            Json(FetchSmartResponse {
                                status: retry_resp.status,
                                body: retry_resp.body,
                                method: "solved".into(),
                                cf_detected: true,
                                elapsed_ms: start.elapsed().as_millis() as u64,
                                error: None,
                            }),
                        ),
                        Err(e) => (
                            StatusCode::BAD_GATEWAY,
                            Json(FetchSmartResponse {
                                status: 0,
                                body: String::new(),
                                method: "solved".into(),
                                cf_detected: true,
                                elapsed_ms: start.elapsed().as_millis() as u64,
                                error: Some(format!("retry after solve failed: {e}")),
                            }),
                        ),
                    }
                }
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    Json(FetchSmartResponse {
                        status: resp.status,
                        body: resp.body,
                        method: "direct".into(),
                        cf_detected: true,
                        elapsed_ms: start.elapsed().as_millis() as u64,
                        error: Some(format!("solve failed: {e}")),
                    }),
                ),
            }
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(FetchSmartResponse {
                status: 0,
                body: String::new(),
                method: "direct".into(),
                cf_detected: false,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some(e.to_string()),
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_smart_request_defaults() {
        let json = r#"{"url": "https://example.com"}"#;
        let req: FetchSmartRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.timeout, 30);
    }

    #[test]
    fn fetch_smart_response_serializes() {
        let resp = FetchSmartResponse {
            status: 200,
            body: "ok".into(),
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 100,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["method"], "direct");
        assert!(!json.as_object().unwrap().contains_key("error"));
    }
}
```

**Step 4: Wire routes in lib.rs**

Update `crates/js/src/lib.rs`:

```rust
mod fetch;
mod fetch_smart;

// Replace SolverState with AppState
#[derive(Clone)]
pub struct AppState {
    pub provider: Arc<dyn CookieProvider>,
    pub cache: Arc<CookieCache>,
    pub http_client: Arc<ox_http::HttpClient>,
}

// Keep SolverState as a type alias for backward compat in /solve
// Actually, just update the router:

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/solve", post(solve))
        .route("/fetch", post(fetch::fetch))
        .route("/fetch-smart", post(fetch_smart::fetch_smart))
        .with_state(state)
}
```

Update the `solve` handler to use `AppState` instead of `SolverState`.

Update tests to construct `AppState` with a mock `HttpClient`. Since `HttpClient` requires a real wreq client, wrap the state differently — use `Arc<dyn Handler>` or create a test-friendly builder. Simplest approach: keep existing tests working by constructing a real `HttpClient` with default config.

**Step 5: Run all tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-js`
Expected: all tests PASS

**Step 6: Commit**

```bash
cd /home/krolik/src/ox-browser
git add -A
git commit -m "feat: add POST /fetch and /fetch-smart endpoints (wreq + headless fallback)"
```

---

### Task 3: Add server subcommand to CLI

**Files:**
- Modify: `src/main.rs` (add `Serve` subcommand)
- Modify: `Cargo.toml` (add `ox-js` dependency)

**Context:**
- Current CLI has `Fetch` and `Version` subcommands
- Need a `Serve` command that starts the Axum HTTP server with all endpoints
- Must construct `AppState` with `HttpClient`, `CookieProvider` (Byparr), and `CookieCache`

**Step 1: Add ox-js dependency**

In root `Cargo.toml`:
```toml
[dependencies]
ox-js = { path = "crates/js" }
```

**Step 2: Add Serve subcommand**

```rust
/// Start HTTP API server
Serve {
    /// Port to listen on
    #[arg(long, default_value = "8901")]
    port: u16,
    /// Byparr/FlareSolverr URL for challenge solving
    #[arg(long, env = "BYPARR_URL")]
    byparr_url: Option<String>,
    /// Proxy URL (e.g. socks5://user:pass@host:port)
    #[arg(long, env = "PROXY_URL")]
    proxy_url: Option<String>,
    /// Enable debug logging
    #[arg(long)]
    debug: bool,
}
```

**Step 3: Implement Serve handler**

```rust
Commands::Serve { port, byparr_url, proxy_url, debug } => {
    use std::time::Duration;
    use ox_http::{HttpConfig, HttpClient, CookieCache, ByparrSolver, ByparrConfig};

    let mut config = HttpConfig {
        cloudflare_detect: true,
        debug,
        emulation: Some(wreq_util::Emulation::Chrome136),
        ..Default::default()
    };

    if let Some(ref proxy) = proxy_url {
        config.proxy_url = Some(proxy.clone());
    }

    let cache = Arc::new(CookieCache::new(Duration::from_secs(25 * 60)));

    let provider: Arc<dyn ox_http::CookieProvider> = if let Some(ref url) = byparr_url {
        Arc::new(ByparrSolver::new(ByparrConfig {
            base_url: url.clone(),
            timeout: Duration::from_secs(60),
        }))
    } else {
        // No solver — use a no-op provider that always errors
        Arc::new(NoOpProvider)
    };

    config.cookie_provider = Some(Arc::clone(&provider));
    config.cookie_cache = Some(Arc::clone(&cache));

    let http_client = Arc::new(HttpClient::new(config)?);
    let state = ox_js::AppState { provider, cache, http_client };
    let app = ox_js::router(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    tracing::info!("ox-browser server listening on :{port}");
    axum::serve(listener, app).await?;
}
```

Add a `NoOpProvider`:
```rust
struct NoOpProvider;

#[async_trait::async_trait]
impl ox_http::CookieProvider for NoOpProvider {
    async fn solve(&self, _url: &str, _ct: ox_http::ChallengeType) -> Result<ox_http::SolvedChallenge, String> {
        Err("no solver configured".into())
    }
}
```

**Step 4: Add axum and async-trait to root Cargo.toml deps**

```toml
axum = "0.8"
async-trait = "0.1"
wreq-util = "3.0.0-rc.10"
```

**Step 5: Build and test**

Run: `cd /home/krolik/src/ox-browser && cargo build`
Expected: compiles without errors

Run: `cd /home/krolik/src/ox-browser && cargo test`
Expected: all tests PASS

**Step 6: Commit**

```bash
cd /home/krolik/src/ox-browser
git add -A
git commit -m "feat: add serve subcommand with /health, /solve, /fetch, /fetch-smart endpoints"
```

---

### Task 4: Docker Service

**Files:**
- Create: `Dockerfile` in `/home/krolik/src/ox-browser/`
- Modify: `/home/krolik/deploy/krolik-server/docker-compose.yml` (add ox-browser service)

**Context:**
- No Dockerfile exists yet for ox-browser
- Use multi-stage build with cargo-chef for caching
- Port 8901 (next free per CLAUDE.md)
- Needs BYPARR_URL env to connect to byparr service

**Step 1: Create Dockerfile**

```dockerfile
# Stage 1: Chef — compute recipe
FROM rust:1.86-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# Stage 2: Planner — generate recipe.json
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder — cached dependency build + final build
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin ox-browser

# Stage 4: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ox-browser /usr/local/bin/ox-browser

ENV RUST_LOG=info
EXPOSE 8901

ENTRYPOINT ["ox-browser"]
CMD ["serve", "--port", "8901"]
```

**Step 2: Add to docker-compose.yml**

Add this service block to `/home/krolik/deploy/krolik-server/docker-compose.yml`:

```yaml
  ox-browser:
    build:
      context: /home/krolik/src/ox-browser
      dockerfile: Dockerfile
    container_name: ox-browser
    restart: unless-stopped
    ports:
      - "127.0.0.1:8901:8901"
    environment:
      - RUST_LOG=info
      - BYPARR_URL=http://byparr:8191
    networks:
      - default
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://127.0.0.1:8901/health"]
      interval: 30s
      timeout: 5s
      retries: 3
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
```

**Step 3: Build and test Docker image**

Run: `cd /home/krolik/deploy/krolik-server && docker compose build ox-browser`
Expected: builds successfully

Run: `docker compose up -d ox-browser && sleep 3 && curl -s http://127.0.0.1:8901/health`
Expected: `ok`

**Step 4: Commit**

```bash
cd /home/krolik/src/ox-browser
git add Dockerfile
git commit -m "feat: add Dockerfile for ox-browser server"

cd /home/krolik/deploy/krolik-server
git add docker-compose.yml
git commit -m "feat: add ox-browser service on port 8901"
```

---

### Task 5: go-engine Integration

**Files:**
- Create: `/home/krolik/src/go-engine/fetch/oxbrowser.go`
- Modify: `/home/krolik/src/go-engine/fetch/fetcher.go:46-54` (add oxBrowserURL field)
- Modify: `/home/krolik/src/go-engine/fetch/fetcher.go:136-174` (add fallback step in FetchBody)
- Modify: `/home/krolik/src/go-search/internal/engine/config.go:22-56` (add OxBrowserURL field)
- Modify: `/home/krolik/src/go-search/internal/engine/config.go:82-106` (wire option)
- Modify: `/home/krolik/src/go-search/config.go` (read OX_BROWSER_URL env)
- Modify: `/home/krolik/deploy/krolik-server/docker-compose.yml` (add OX_BROWSER_URL to go-search)

**Context:**
- Follow the exact same pattern as `byparr.go` / `WithByparrFallback`
- ox-browser POST /fetch-smart returns `{status, body, method, cf_detected, elapsed_ms, error}`
- Fallback chain: proxy → ox-browser → Byparr

**Step 1: Create oxbrowser.go**

Create `/home/krolik/src/go-engine/fetch/oxbrowser.go`:

```go
package fetch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const oxBrowserTimeout = 30 * time.Second

type oxFetchRequest struct {
	URL     string `json:"url"`
	Timeout int    `json:"timeout"`
}

type oxFetchResponse struct {
	Status    int    `json:"status"`
	Body      string `json:"body"`
	Method    string `json:"method"`
	CFDetect  bool   `json:"cf_detected"`
	ElapsedMs int    `json:"elapsed_ms"`
	Error     string `json:"error,omitempty"`
}

// WithOxBrowser enables fallback to an ox-browser /fetch-smart endpoint.
func WithOxBrowser(baseURL string) Option {
	return func(f *Fetcher) {
		if baseURL != "" {
			f.oxBrowserURL = baseURL
		}
	}
}

func (f *Fetcher) fetchViaOxBrowser(ctx context.Context, pageURL string) ([]byte, error) {
	body, err := json.Marshal(oxFetchRequest{
		URL:     pageURL,
		Timeout: int(oxBrowserTimeout.Seconds()),
	})
	if err != nil {
		return nil, fmt.Errorf("ox-browser marshal: %w", err)
	}

	endpoint := f.oxBrowserURL + "/fetch-smart"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ox-browser request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: oxBrowserTimeout + 5*time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ox-browser call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ox-browser read: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ox-browser HTTP %d: %s", resp.StatusCode, truncate(string(respBody)))
	}

	var result oxFetchResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("ox-browser parse: %w", err)
	}

	if result.Error != "" {
		return nil, fmt.Errorf("ox-browser error: %s", result.Error)
	}
	if result.Body == "" {
		return nil, errors.New("ox-browser: empty response")
	}

	slog.Debug("ox-browser fallback ok",
		slog.String("url", pageURL),
		slog.String("method", result.Method),
		slog.Bool("cf", result.CFDetect),
		slog.Int("elapsed_ms", result.ElapsedMs))

	return []byte(result.Body), nil
}
```

**Step 2: Add oxBrowserURL field to Fetcher**

In `fetcher.go`, add field to Fetcher struct:

```go
type Fetcher struct {
	httpClient     *http.Client
	browserClient  *stealth.BrowserClient
	retryConfig    RetryConfig
	retryTracker   *stealth.RetryTracker
	proxyPool      proxypool.ProxyPool
	cookieProvider stealth.CookieProvider
	byparrURL      string
	oxBrowserURL   string  // ox-browser /fetch-smart fallback (empty = disabled)
}
```

**Step 3: Update FetchBody fallback chain**

In `fetcher.go`, update the fallback section (after the switch statement):

```go
	// Fallback to ox-browser when proxy fails.
	if err != nil && f.oxBrowserURL != "" {
		obCtx, obCancel := context.WithTimeout(context.Background(), oxBrowserTimeout+5*time.Second)
		defer obCancel()
		if fallback, obErr := f.fetchViaOxBrowser(obCtx, url); obErr == nil {
			body, err = fallback, nil
		}
	}

	// Fallback to Byparr when ox-browser also fails (or not configured).
	if err != nil && f.byparrURL != "" {
		fbCtx, fbCancel := context.WithTimeout(context.Background(), byparrTimeout)
		defer fbCancel()
		if fallback, fbErr := f.fetchViaByparr(fbCtx, url); fbErr == nil {
			body, err = fallback, nil
		}
	}
```

**Step 4: Wire through engine config**

In `/home/krolik/src/go-search/internal/engine/config.go`, add field:

```go
OxBrowserURL     string
```

In `Init()`, add:

```go
if c.OxBrowserURL != "" {
    fetcherOpts = append(fetcherOpts, fetch.WithOxBrowser(c.OxBrowserURL))
}
```

In `/home/krolik/src/go-search/config.go`, add to Config init:

```go
OxBrowserURL: env.Str("OX_BROWSER_URL", ""),
```

**Step 5: Add env to docker-compose**

In go-search service environment:

```yaml
- OX_BROWSER_URL=http://ox-browser:8901
```

**Step 6: Build and verify**

Run: `cd /home/krolik/src/go-engine && go build ./...`
Expected: compiles

Run: `cd /home/krolik/src/go-search && go build ./...`
Expected: compiles

**Step 7: Commit**

```bash
cd /home/krolik/src/go-engine
git add -A
git commit -m "feat: add ox-browser /fetch-smart fallback in fetch chain"

cd /home/krolik/src/go-search
git add -A
git commit -m "feat: wire OX_BROWSER_URL env for ox-browser fallback"

cd /home/krolik/deploy/krolik-server
git add docker-compose.yml
git commit -m "feat: add OX_BROWSER_URL to go-search environment"
```

---

## Dependency Graph

```
Task 1 (CF detection)  ──→  Task 2 (endpoints)  ──→  Task 3 (CLI serve)
                                                            │
Task 4 (Docker)  ←──────────────────────────────────────────┘
     │
     └──→  Task 5 (go-engine integration)
```

- **Task 1** and **Task 4** (Docker) can start in parallel (Docker only needs Cargo.toml + main.rs structure)
- **Task 2** depends on Task 1 (uses `detect_cloudflare` with new markers)
- **Task 3** depends on Task 2 (uses `AppState` and routes from Task 2)
- **Task 4** depends on Task 3 (needs `serve` subcommand to exist)
- **Task 5** depends on Task 4 (needs ox-browser URL)

Actually, Task 4 needs the `serve` command, so the real order is: **1 → 2 → 3 → 4 → 5**, with Task 4 Dockerfile creatable early but docker-compose wiring last.
