# ox-browser Roadmap

Module: `github.com/anatolykoptev/ox-browser`
Naming convention: `ox-*` prefix for Rust services (oxide theme), parallel to `go-*` for Go.

## Phase 1: Core MVP (v0.1.0) ✅

**Goal:** Fetch pages, parse DOM, extract data — no JS, no browser chrome.

- [x] Workspace setup (Cargo.toml, 6 crates)
- [x] `ox-http`: HTTP wrapper with proxy, cookies, redirects
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

## Phase 1.6: TLS Fingerprinting (v0.1.6) ✅

**Goal:** Chrome-identical TLS/HTTP2 fingerprints via BoringSSL.

- [x] Replace `reqwest+rustls` with `wreq+BoringSSL` (wreq = reqwest hard fork)
- [x] Chrome-identical TLS fingerprint (JA4 match via BoringSSL)
- [x] HTTP/2 fingerprint: SETTINGS, WINDOW_UPDATE, priority matching Chrome
- [x] `wreq_util::Emulation` support in `HttpConfig` (Chrome131, etc.)
- [x] Per-request proxy rotation via `RequestBuilder::proxy()` (replaces `Proxy::custom()`)
- [x] Re-export `Emulation` from `ox-http` for downstream use
- [x] All 140 tests pass, clippy clean

**Result:** Undetectable TLS fingerprint. ~5085 LOC, 140 tests.
**Key change:** `reqwest` → `wreq` (near-identical API, BoringSSL backend).

## Phase 2: Cloudflare Bypass + HTTP API (v0.2.0) ✅

**Goal:** Solve Cloudflare challenges via external solver, provide cookies to go-stealth,
expose fetch/analyze API for the ecosystem.

**Architecture revision (March 2026):** Research showed embedded JS engines (Boa/QuickJS)
cannot solve modern CF challenges — they require Canvas, WebGL, Audio Context (full browser
surface). New approach: external stealth browser solver (Byparr/Camoufox) + cookie caching +
HTTP API. See `docs/plans/2026-03-05-phase2-cloudflare-bypass.md` for full research.

### Phase 2a: CookieProvider + Solver Integration

- [x] `CookieProvider` trait: `async fn solve(url, challenge_type) -> SolvedChallenge`
- [x] `SolvedChallenge` struct: cookies HashMap + user_agent
- [x] `CookieCache`: per-domain TTL cache (25min default, matching cf_clearance lifetime)
- [x] `ByparrSolver`: FlareSolverr-compatible HTTP client (Byparr, FlareSolverr, any drop-in)
- [x] `solver_middleware`: intercepts HttpError::Cloudflare, solves, injects cookies, retries
- [x] Block challenges correctly passed through (not solvable)

### Phase 2b: CF Detection at HTTP 200

- [x] Detect Cloudflare challenges hidden behind HTTP 200 responses
- [x] `cf-mitigated` header detection (managed challenge)
- [x] Body markers: `_cf_chl_opt`, `challenge-platform`, `cf-turnstile`
- [x] Updated `detect_cloudflare()` to check both status codes and response body/headers
- [x] 35 hard red tests covering edge cases (CF 200 detection, retry, proxy, middleware)

### Phase 2c: HTTP API

- [x] `POST /solve` endpoint (accepts URL + challenge_type, returns cookies)
- [x] `POST /fetch` endpoint (stealth fetch with proxy + CF bypass)
- [x] `POST /fetch-smart` endpoint (three-tier chain: proxy → ox-browser → Byparr fallback)
- [x] `POST /analyze` endpoint (fetch page + detect tech stack from HTML/headers)
- [x] `/health` endpoint
- [x] Cache-aware (returns cached cookies on repeat requests)
- [x] Block challenge rejection (400 Bad Request)

### Phase 2d: Docker Deployment

- [x] Multi-stage Dockerfile: cargo-chef (dep caching) + BoringSSL build (cmake, libclang-dev)
- [x] `.dockerignore` (excludes target/, .git/ — context from ~10GB to ~30MB)
- [x] docker-compose.yml entry (port 8901, backend network)
- [x] Integration with go-code `site_analyze` MCP tool (tech detection + source map extraction)
- [x] Integration with go-search `web_url_read` via `/fetch-smart`

**Result:** CF bypass + stealth fetch API + tech analysis. ~5800 LOC, 218 tests.
**Architecture:** ox-browser → Byparr/FlareSolverr → stealth browser → cf_clearance → cache.
**Three-tier fetch:** go-stealth proxy → ox-browser /fetch-smart → Byparr (escalating bypass).
**Not solving:** Turnstile/CAPTCHA directly (delegates to external solver).
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

**Goal:** Expose ox-browser as native MCP service for AI agents.

- [x] Docker container with multi-stage build *(done in Phase 2d)*
- [x] docker-compose.yml entry, port 8901 *(done in Phase 2d)*
- [x] Health endpoint *(done in Phase 2c)*
- [x] Integration with go-code (`site_analyze` tool) *(done in Phase 2d)*
- [ ] `ox-mcp` crate with HTTP+SSE transport (native MCP protocol)
- [ ] Tools: browse, select, fill_form, crawl, security_scan, solve_cf
- [ ] Integration with krolik-agent (skill + mcp_call)

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
| JS engine | External solver (Phase 2) | None | V8 (via Rod) |
| DOM parsing | dom_query (mutable) | None | Chrome DOM |
| TLS fingerprinting | ✅ wreq+BoringSSL | Yes (tls-client) | Via Chrome |
| Browser profiles | 16 built-in ✅ | 16 built-in | N/A |
| CF detection | ✅ (Phase 1.5) | ✅ | N/A |
| CF JS solving | ✅ via Byparr/FlareSolverr | No (delegates) | Via Chrome |
| CF 200 detection | ✅ (cf-mitigated, body markers) | No | N/A |
| HTTP API | ✅ /fetch, /fetch-smart, /analyze | No | No |
| Tech detection | ✅ /analyze (CMS, frameworks, CDN) | No | No |
| Proxy pool | Webshare + health ✅ | Webshare + health | No |
| Rate limiting | Per-domain ✅ | Per-domain | No |
| Middleware | Chain pattern ✅ | Chain pattern | No |
| MCP server | Phase 5 | No | No |

**When to use which:**
- **ox-browser** — lightweight scraping + DOM + CF bypass, no Chrome dependency
- **go-stealth** — stealth HTTP requests without DOM/JS, delegates CF to ox-browser
- **go-browser** — SPA rendering, full JS, screenshot/PDF (needs Chromium)
