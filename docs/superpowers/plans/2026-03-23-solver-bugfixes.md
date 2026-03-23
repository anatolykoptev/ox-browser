# Solver Bugfixes — Middleware Chain + Retry Loop + Stealth

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the residential proxy retry loop, correct middleware chain order so solver actually triggers, and add proper per-request proxy handling in WreqHandler.

**Architecture:** Three bugs in the current middleware chain: (1) residential middleware retries infinitely inside retry loop, (2) solver never triggers because residential swallows CF errors, (3) WreqHandler ignores `req.proxy` field. Fix: residential becomes one-shot (skip if proxy already set), swap residential BEFORE solver in chain, and ensure WreqHandler respects per-request proxy.

**Tech Stack:** Rust 1.93, wreq 6.x, axum 0.8

---

## Bug Analysis

Current chain: `SSRF → logging → rate_limit → retry → solver → residential → cloudflare_detect → wreq`

### Bug 1: Residential retry loop

When `cloudflare_detect` raises CF error:
1. `residential` catches it, sets `req.proxy`, retries through `next` (which is `cloudflare_detect → wreq`)
2. Retry also gets CF (managed challenge needs JS, not just residential IP)
3. `residential` catches again — but it already retried! **Should propagate to solver.**
4. Error bubbles to `solver`, solver calls `provider.solve()` (chromium)
5. BUT solver retries through `next` (residential → cloudflare_detect → wreq) — residential catches AGAIN
6. `retry` middleware wraps all of this — causes exponential retries

**Fix:** Residential middleware must be **one-shot per request**. If `req.proxy` is already set (we already retried with proxy), skip and propagate.

### Bug 2: Solver never triggers

Chain order: `solver → residential → cloudflare_detect`

When CF detected:
1. `cloudflare_detect` raises `HttpError::Cloudflare`
2. `residential` catches it, retries with proxy
3. If retry fails, residential propagates CF error UP
4. `solver` catches CF error, calls `provider.solve()` (chromium) ✅
5. Solver gets cookies, injects them, retries through `next` (residential → cloudflare_detect → wreq)
6. BUT wreq now has cookies — should pass CF without challenge

**Actually:** This should work if residential is one-shot. The solver → residential → cloudflare flow is correct IF residential doesn't retry when proxy already set.

### Bug 3: WreqHandler may ignore req.proxy

Need to verify that `WreqHandler::handle()` actually uses `req.proxy` to set the proxy for that specific request.

---

## File Structure

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `crates/http/src/middleware_residential.rs` | One-shot: skip if req.proxy already set |
| Modify | `crates/http/src/handler_reqwest.rs` | Verify per-request proxy handling |
| Modify | `crates/http/src/middleware_retry.rs` | Cap max retries for CF errors specifically |
| Modify | `crates/http/src/read_pipeline.rs` | Add timeout to read_page() to prevent 60s+ hangs |

---

## Task 1: Fix Residential Middleware — One-Shot Guard

The middleware retries infinitely because it catches CF error every time. Fix: if `req.proxy` is already set, this request was already retried with a proxy — skip and propagate.

**Files:**
- Modify: `crates/http/src/middleware_residential.rs`

- [ ] **Step 1: Add one-shot guard to handle()**

```rust
#[async_trait]
impl Handler for ResidentialHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        // One-shot guard: if proxy already set, we already retried — propagate.
        if req.proxy.is_some() {
            return self.next.handle(req).await;
        }

        match self.next.handle(req.clone()).await {
            Err(HttpError::Cloudflare(ChallengeType::Block, s, r)) => {
                Err(HttpError::Cloudflare(ChallengeType::Block, s, r))
            }
            Err(HttpError::Cloudflare(ct, _s, _r)) => {
                tracing::info!(
                    url = %req.url,
                    challenge = %ct,
                    "CF detected, retrying with residential proxy"
                );
                let mut retry_req = req;
                retry_req.proxy = Some(self.proxy_url.clone());
                self.next.handle(retry_req).await
            }
            other => other,
        }
    }
}
```

Key change: `if req.proxy.is_some() { return self.next.handle(req).await; }` at the top.

- [ ] **Step 2: Add test for one-shot behavior**

```rust
#[tokio::test]
async fn does_not_retry_when_proxy_already_set() {
    let call_count = Arc::new(AtomicUsize::new(0));
    struct AlwaysCfHandler { call_count: Arc<AtomicUsize> }
    #[async_trait]
    impl Handler for AlwaysCfHandler {
        async fn handle(&self, _req: Request) -> Result<HttpResponse> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Err(HttpError::Cloudflare(ChallengeType::ManagedChallenge, 200, "ray".into()))
        }
    }
    let base: Arc<dyn Handler> = Arc::new(AlwaysCfHandler { call_count: call_count.clone() });
    let handler = chain(vec![residential_proxy_middleware("http://proxy:8080".into())], base);

    // Request already has proxy set — should NOT retry
    let mut req = make_req("https://example.com");
    req.proxy = Some("http://existing:1234".into());
    let err = handler.handle(req).await.unwrap_err();
    assert!(matches!(err, HttpError::Cloudflare(..)));
    assert_eq!(call_count.load(Ordering::SeqCst), 1, "should call handler only once — no retry");
}
```

- [ ] **Step 3: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http middleware_residential`
Expected: 5 tests PASS (4 existing + 1 new)

- [ ] **Step 4: Commit**

```bash
git add crates/http/src/middleware_residential.rs
git commit -m "fix(http): residential middleware one-shot guard — prevent retry loop"
```

---

## Task 2: Verify WreqHandler Per-Request Proxy

Ensure `handler_reqwest.rs` actually uses `req.proxy` when set.

**Files:**
- Modify: `crates/http/src/handler_reqwest.rs` (if needed)

- [ ] **Step 1: Read handler_reqwest.rs and check proxy handling**

Look for `req.proxy` usage in `WreqHandler::handle()`. If it's not there, add it.

Expected logic:
```rust
async fn handle(&self, req: Request) -> Result<HttpResponse> {
    // Per-request proxy override takes precedence over pool
    let client = if let Some(ref proxy_url) = req.proxy {
        // Build one-off client with this proxy
        self.build_proxy_client(proxy_url)?
    } else if let Some(ref pool) = self.proxy_pool {
        // Use rotating pool
        ...
    } else {
        // Use default client
        &self.client
    };
    ...
}
```

- [ ] **Step 2: Run full test suite**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http`
Expected: All tests PASS

- [ ] **Step 3: Commit (if changes needed)**

```bash
git add crates/http/src/handler_reqwest.rs
git commit -m "fix(http): ensure WreqHandler respects per-request proxy override"
```

---

## Task 3: Add Timeout to read_pipeline

Currently `read_page()` can hang for 60+ seconds (retry loop × solver timeout). Add overall timeout.

**Files:**
- Modify: `crates/http/src/read_pipeline.rs`

- [ ] **Step 1: Wrap read_page in tokio::time::timeout**

Add a configurable overall timeout (default 30s) to `read_page()`:

```rust
pub async fn read_page(
    http: &HttpClient,
    provider: &dyn CookieProvider,
    cache: &CookieCache,
    params: &ReadParams,
) -> ReadOutput {
    let timeout_duration = Duration::from_secs(30);
    match tokio::time::timeout(timeout_duration, read_page_inner(http, provider, cache, params)).await {
        Ok(output) => output,
        Err(_) => build_error_output(params, "direct", 30_000, "read timeout after 30s"),
    }
}

async fn read_page_inner(
    http: &HttpClient,
    provider: &dyn CookieProvider,
    cache: &CookieCache,
    params: &ReadParams,
) -> ReadOutput {
    // ... existing logic
}
```

- [ ] **Step 2: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-http read_pipeline`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add crates/http/src/read_pipeline.rs
git commit -m "fix(http): add 30s overall timeout to read_page pipeline"
```

---

## Task 4: Deploy + Smoke Test

- [ ] **Step 1: Build (cached)**

```bash
cd ~/deploy/krolik-server && docker compose build ox-browser
```

- [ ] **Step 2: Deploy**

```bash
docker compose up -d --no-deps --force-recreate ox-browser
```

- [ ] **Step 3: Test normal site**

```bash
curl -s -D- -X POST http://127.0.0.1:8901/read \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}' | head -5
```

Expected: 200 OK, valid JSON

- [ ] **Step 4: Test CF site — verify no infinite loop**

```bash
time curl -s -X POST http://127.0.0.1:8901/read \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://nowsecure.nl","max_length":200}' | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'method={d.get(\"method\")} len={d.get(\"length\")} elapsed={d.get(\"elapsed_ms\")}ms err={str(d.get(\"error\",\"none\"))[:80]}')
"
```

Expected: Response in <35 seconds (not 60+), method=solved or error with reasonable timeout.

- [ ] **Step 5: Verify no retry loop in logs**

```bash
docker logs ox-browser --tail 20 2>&1 | grep -c "CF detected, retrying"
```

Expected: ≤2 retries per request (1 direct + 1 residential), not 14+.
