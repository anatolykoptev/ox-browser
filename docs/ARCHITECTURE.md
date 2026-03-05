# ox-browser Architecture

## Problem

Existing Rust headless browser options fall into two categories:

1. **Chrome wrappers** (`headless_chrome`, `chromiumoxide`) — require 200MB+ Chromium binary
2. **From-scratch attempts** — incomplete, low quality, dead code

Neither provides a lightweight, self-contained browser suitable for stealth scraping,
Cloudflare bypass, and headless automation without external binary dependencies.

## Solution

Build on battle-tested Servo-ecosystem crates (html5ever, selectors) via `dom_query`,
add JS execution through Boa (pure Rust), and wrap in a clean workspace architecture.
Use wreq (BoringSSL-backed reqwest fork) for Chrome-identical TLS/HTTP2 fingerprints.

## Crate Dependency Graph

```
                    ┌─────────┐
                    │   mcp   │  MCP server (port 8901)
                    └────┬────┘
                         │
                    ┌────┴────┐
              ┌─────┤   cli   ├─────┐
              │     └────┬────┘     │
              │          │          │
         ┌────┴───┐ ┌────┴───┐ ┌───┴─────┐
         │crawler │ │security│ │         │
         └────┬───┘ └────┬───┘ │         │
              │          │     │         │
              └─────┬────┘     │         │
                    │          │         │
               ┌────┴────┐    │         │
               │  core   │────┘         │
               └──┬───┬──┘              │
                  │   │                 │
            ┌─────┘   └──────┐          │
            │                │          │
       ┌────┴───┐       ┌───┴───┐      │
       │  http  │       │  js   │──────┘
       └────────┘       └───────┘

External crates:
  core     → dom_query (html5ever + selectors)
  http     → wreq (BoringSSL), cookie_store
  js       → boa_engine (default)
```

## HTTP Layer — Stealth Architecture

### TLS Fingerprinting (wreq + BoringSSL)

**Problem:** rustls cannot match Chrome TLS fingerprints — it intentionally omits legacy
cipher suites and has no API for ClientHello customization. Cloudflare/Akamai detect this.

**Solution:** Replace reqwest+rustls with `wreq` (hard fork of reqwest using BoringSSL).
Chrome itself uses BoringSSL, so fingerprints are authentic — not reverse-engineered.

```rust
// Before (detectable)
let client = reqwest::Client::builder().build()?;

// After (Chrome-identical fingerprint)
let client = wreq::Client::builder()
    .emulation(Emulation::Chrome131)
    .build()?;
```

**What wreq handles automatically per emulation profile:**
- JA4 TLS fingerprint (cipher suites, extensions, curves, ALPN order)
- HTTP/2 Akamai fingerprint (SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order)
- HTTP/1 header case sensitivity
- GREASE values matching Chrome behavior
- Post-quantum key exchange (X25519MLKEM768)

**JA3 vs JA4:** JA3 is dead — Chrome 108+ randomizes extension order, breaking JA3's
MD5 hash. JA4 sorts extensions before hashing (immune to permutation). Cloudflare,
AWS WAF, VirusTotal all use JA4+ as of 2025.

### Middleware Chain

Composable request pipeline via `Handler` trait and `chain()` function.

```
Request flow (outermost → innermost):

  logging? → rate_limit? → retry? → cloudflare? → client_hints → wreq
```

Each middleware wraps the next handler. `MiddlewareFn` type alias enables
closure-based middleware. `chain(middlewares, base)` composes them (outermost-first).

### Cloudflare Detection

Port of go-stealth's `DetectCloudflare`. Inspects responses for CF challenge markers:

| Challenge | Status | Body markers |
|-----------|--------|-------------|
| JsChallenge | 503 | `challenge-platform` |
| Turnstile | 403/503 | `turnstile-wrapper`, `cf-turnstile` |
| Block | 403/503 | `you have been blocked`, `cf-error-details` |

On detection → `HttpError::Cloudflare` (retryable) → retry middleware auto-retries
with a different proxy. Server header must contain "cloudflare", cf-ray extracted.

### Browser Profiles (16 UAs)

Chrome, Firefox, Safari, Edge across Windows, macOS, Linux, Android, iOS.
`random_profile(filter)` selects by browser/os/mobile criteria.
Client Hints (`sec-ch-ua-*`) auto-injected for Chromium UAs; Firefox/Safari omit them.

### Proxy Pool

`ProxyPool` trait with three implementations:
- `StaticPool` — fixed list with atomic round-robin rotation
- `WebsharePool` — fetches proxies from Webshare API, periodic refresh
- `HealthyPool` — wraps any pool, tracks success/failure per proxy, auto-deactivates

### Rate Limiting

Two-level system:
- `Limiter` — sliding-window counter per key with block-until support
- `DomainLimiter` — matches URLs against domain rules (exact, wildcard, catch-all)

### Retry

Exponential backoff with jitter. `is_retryable_status()` classifies 429/5xx + CF errors.
`parse_retry_after()` handles integer seconds and HTTP-date. `retry_do()` is async executor.

## Core Interfaces

```rust
pub struct Page {
    pub url: String,
    pub status: u16,
    pub title: String,
    dom: dom_query::Document,
    session: Session,
}

pub trait JsEngine: Send + Sync {
    fn execute(&mut self, code: &str) -> Result<JsValue>;
    fn bind_dom(&mut self, dom: &dom_query::Document) -> Result<()>;
    fn clear(&mut self);
}
```

## Crate Structure

```
ox-browser/
├── Cargo.toml                      # workspace definition
├── crates/
│   ├── http/                       # wreq wrapper + middleware + proxy + CF detect
│   ├── core/                       # Page + DOM + Session + Pool
│   ├── js/                         # JsEngine trait + Boa backend
│   ├── security/                   # XSS, CSP, SRI, headers (standalone)
│   ├── crawler/                    # Queue, dedup, robots.txt, rate limit
│   └── mcp/                       # MCP server (HTTP+SSE transport)
├── src/
│   └── main.rs                     # CLI: fetch, scan, crawl subcommands
└── docs/
```

## Cloudflare Bypass Architecture (Phase 2)

```
go-stealth request
    │
    ▼
ox-browser HttpClient (wreq + Chrome131 emulation)
    │
    ├── TLS fingerprint: BoringSSL (authentic Chrome JA4)
    ├── HTTP/2 fingerprint: Akamai H2 (SETTINGS, PRIORITY, pseudo-headers)
    ├── Headers: client hints + browser profile + correct case
    │
    ▼
cloudflare_detect_middleware
    │
    ├── No challenge → return response
    ├── Block/Turnstile → HttpError::Cloudflare → retry with different proxy
    └── JsChallenge → ox-js solver (Phase 2b)
                          │
                          ├── Extract challenge-platform scripts
                          ├── Execute in Boa with DOM shim
                          └── Return cf_clearance cookie
```

## Configuration

| Env Var | Default | Purpose |
|---------|---------|---------|
| `OX_BROWSER_PORT` | `8901` | MCP server port |
| `OX_BROWSER_CONCURRENCY` | `3` | Max concurrent pages |
| `OX_BROWSER_TIMEOUT` | `20s` | Page load timeout |
| `OX_BROWSER_JS` | `boa` | JS engine: `boa`, `none` |
| `WEBSHARE_API_KEY` | — | Proxy authentication |

## Testing Strategy

- Unit tests per crate (30%+ coverage)
- Integration tests in `tests/` with real HTML fixtures
- Hard red tests for edge cases (retry, proxy, CF detection)
- No external services needed for unit tests (mock HTTP responses)
- `cargo test --workspace` runs everything
- **187 tests, ~5100 LOC** (as of Phase 1.5)
