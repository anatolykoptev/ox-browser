# ox-browser Roadmap

Module: `github.com/anatolykoptev/ox-browser`
Naming convention: `ox-*` prefix for Rust services (oxide theme), parallel to `go-*` for Go.

## Phase 1: Core MVP (v0.1.0) ✅

**Goal:** Fetch pages, parse DOM, extract data — no JS, no browser chrome.

- [x] Workspace setup (Cargo.toml, 6 crates)
- [x] `ox-http`: reqwest wrapper with proxy, cookies, redirects
- [x] `ox-core`: Browser, Page, DOM facade over dom_query
- [x] Page: select, select_single, title, html, text, forms, links, meta_tags
- [x] Form extraction and filling (input/select/textarea, set_field, serialize)
- [x] URL resolution (relative → absolute, same-origin check)
- [x] Concurrency pool (tokio semaphore)
- [x] CLI: `ox-browser fetch <url> [--css] [--text]`
- [x] Unit tests (36 tests: page, form, navigation)
- [x] Lint setup (clippy, rustfmt, Makefile)
- [x] GitHub repo + v0.1.0 tag

**Result:** HTML scraper with CSS selectors and form support. 950 LOC, 36 tests.

## Phase 1.5: Stealth HTTP (v0.1.5) ✅

**Goal:** Anti-detection HTTP layer ported from go-stealth patterns.

- [x] Browser profiles: 16 UA strings (Chrome/Firefox/Safari/Edge × Win/Mac/Linux/Mobile)
- [x] Client Hints: auto-inject `sec-ch-ua-*` headers matching UA
- [x] Header ordering: realistic browser header order per profile
- [x] Middleware chain: composable `Handler` trait (logging, retry, rate limit, client hints)
- [x] Retry with backoff: exponential backoff + jitter on 429/5xx, retryable error classification
- [x] Proxy pool: Webshare API integration, round-robin rotation, health tracking
- [x] Per-domain rate limiting: sliding window + min delay, Retry-After parsing
- [x] Session: persistent browsing context (consistent fingerprint, cookie jar)
- [x] Cloudflare detection: `detect_cloudflare()` + `cloudflare_detect_middleware`
- [x] CF challenge types: JsChallenge, Turnstile, Block → retryable `HttpError::Cloudflare`
- [x] CF + retry integration: auto-retry with different proxy on CF block
- [x] Hard red tests: 34 edge case tests (retry, proxy, CF detection + middleware)

**Result:** Stealth HTTP client with Cloudflare detection. ~5100 LOC, 187 tests.
**Ported from:** `go-stealth` (Grade A, 6.6K LOC) — concepts adapted to Rust idioms.

## Phase 2: Cloudflare Bypass (v0.2.0)

**Goal:** Solve Cloudflare JS challenges natively, provide cookies to go-stealth.

### Phase 2a: TLS Fingerprinting

- [ ] Replace rustls with `boring` (BoringSSL) or `rustls` with JA3 customization
- [ ] Chrome TLS fingerprint mimicry (cipher suites, extensions, ALPN order)
- [ ] HTTP/2 fingerprint: SETTINGS frame, WINDOW_UPDATE, priority matching Chrome
- [ ] `TlsProfile` struct tied to `BrowserProfile`
- [ ] Middleware: `tls_fingerprint_middleware` (or configure at client level)

### Phase 2b: JS Challenge Solver

- [ ] `ox-js` crate: Boa engine with minimal DOM shim
- [ ] DOM shim: `document.createElement`, `document.getElementById`, cookie access
- [ ] `window.setTimeout`/`setInterval` via tokio timers
- [ ] Extract + execute CF challenge-platform scripts
- [ ] Return `cf_clearance` cookie on success
- [ ] Timeout + fallback (max 30s per challenge attempt)

### Phase 2c: CookieProvider Integration

- [ ] `CookieProvider` trait: `async fn solve(url, challenge) -> CookieJar`
- [ ] HTTP endpoint: `POST /solve` — accepts URL, returns cookies
- [ ] go-stealth integration: call ox-browser on `HttpError::Cloudflare`
- [ ] Cookie caching: per-domain, TTL-based (cf_clearance ~30min)
- [ ] Metrics: solve success rate, avg solve time

**Result:** CF JS challenges solved in ~5s without Chromium. go-stealth gets cookies.
**Not solving:** Turnstile/CAPTCHA (requires visual solver — out of scope).
**Depends on:** Phase 1.5

## Phase 3: Security Scanner (v0.3.0)

**Goal:** Analyze pages for common web vulnerabilities.

- [ ] `ox-security` crate (usable standalone, without browser)
- [ ] XSS detector: DOM sinks, event handlers, reflected patterns
- [ ] CSP parser and scorer (A-F grade)
- [ ] SRI checker (missing integrity attributes)
- [ ] Security headers analysis (HSTS, X-Frame-Options, etc.)
- [ ] SecurityReport struct with findings + severity
- [ ] CLI: `ox-browser scan <url>`

**Result:** One-command security audit for any URL. ~600 LOC.
**Depends on:** Phase 1 (Phase 2 optional but improves XSS detection)

## Phase 4: Crawler (v0.4.0)

**Goal:** Crawl websites with configurable depth, filters, rate limiting.

- [ ] `ox-crawler` crate
- [ ] BFS/DFS crawl queue with deduplication (visited set)
- [ ] Depth and breadth limits
- [ ] URL include/exclude filters (regex)
- [ ] robots.txt parsing and respect
- [ ] Rate limiting (requests per second per domain)
- [ ] Callback-based page processing
- [ ] CLI: `ox-browser crawl <url> --depth 3`

**Result:** Full site crawling with polite behavior. ~500 LOC.
**Depends on:** Phase 1

## Phase 5: MCP Server (v0.5.0)

**Goal:** Expose ox-browser as MCP service for AI agents.

- [ ] `ox-mcp` crate with HTTP+SSE transport
- [ ] Tools: browse, select, fill_form, crawl, security_scan, solve_cf
- [ ] Docker container with multi-stage build
- [ ] docker-compose.yml entry (port 8901)
- [ ] Integration with krolik-agent (skill + mcp_call)
- [ ] Health endpoint

**Result:** AI agents can browse, scrape, scan, and solve CF via MCP. ~400 LOC.
**Depends on:** Phases 1-4

## Phase 6: Polish (v1.0.0)

**Goal:** Production-ready quality.

- [ ] CI/CD: GitHub Actions (test, lint, build, release)
- [ ] Benchmarks (parsing, JS execution, CF solve time)
- [ ] Crate documentation (rustdoc, 60%+ coverage)
- [ ] GoReleaser-style binary releases

**Result:** Publishable crate + production Docker image.
**Depends on:** Phases 1-5

## Non-Goals

- **CSS layout/rendering** — no visual rendering, no computed styles
- **Full browser compatibility** — not trying to replace Chrome/Firefox
- **WebDriver/CDP protocol** — MCP is the integration protocol
- **Turnstile/CAPTCHA solving** — requires visual solver, out of scope
- **Image/media processing** — text and HTML only

## Comparison

| Feature | ox-browser | go-stealth | go-browser |
|---------|-----------|-----------|------------|
| Language | Rust | Go | Go |
| Purpose | Headless browser + CF bypass | Stealth HTTP client | Chrome automation |
| Chrome needed | No | No | Yes (Rod) |
| JS engine | Boa (Phase 2) | None | V8 (via Rod) |
| DOM parsing | dom_query (mutable) | None | Chrome DOM |
| TLS fingerprinting | Phase 2a | Yes (tls-client) | Via Chrome |
| Browser profiles | 16 built-in ✅ | 16 built-in | N/A |
| CF detection | ✅ (Phase 1.5) | ✅ | N/A |
| CF JS solving | Phase 2b | No (delegates) | Via Chrome |
| Proxy pool | Webshare + health ✅ | Webshare + health | No |
| Rate limiting | Per-domain ✅ | Per-domain | No |
| Middleware | Chain pattern ✅ | Chain pattern | No |
| MCP server | Phase 5 | No | No |

**When to use which:**
- **ox-browser** — lightweight scraping + DOM + CF bypass, no Chrome dependency
- **go-stealth** — stealth HTTP requests without DOM/JS, delegates CF to ox-browser
- **go-browser** — SPA rendering, full JS, screenshot/PDF (needs Chromium)
