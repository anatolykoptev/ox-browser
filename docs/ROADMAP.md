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

**Result:** CF bypass + stealth fetch API + tech analysis. ~5800 LOC, 220 tests.
**Architecture:** ox-browser → Byparr/FlareSolverr → stealth browser → cf_clearance → cache.
**Three-tier fetch:** go-stealth proxy → ox-browser /fetch-smart → Byparr (escalating bypass).
**Not solving:** Turnstile/CAPTCHA directly (delegates to external solver).
**Depends on:** Phase 1.5

## Phase 2.5: Web Intelligence (v0.2.5) ✅

**Goal:** Full website analysis — technology stack, SEO, performance, accessibility, content,
media, fonts, PWA, API discovery. One `POST /analyze` → complete intelligence report.

**Crate restructure:** Created `ox-intelligence` crate. Moved `fingerprint.rs` from `ox-security`.
`ox-security` reserved for Phase 4 (vulnerability scanning).

```
ox-intelligence/src/
├── fingerprint.rs    — rswappalyzer wrapper (7,000+ techs, version extraction, false positive filter)
├── seo.rs            — OG, Twitter Cards, JSON-LD, canonical, hreflang, robots, description
├── seo_helpers.rs    — meta_property(), meta_name(), link_href() helpers
├── performance.rs    — compression, cache headers, HTTP/3, preload/prefetch, lazy images, inline CSS
├── accessibility.rs  — html lang, alt coverage, heading hierarchy, ARIA landmarks, form labels, score
├── content.rs        — internal/external links, word count, iframes
├── fonts.rs          — Google Fonts, Adobe Fonts, @font-face from CSS
├── pwa.rs            — manifest.json link, service worker, theme-color, apple-touch-icon
├── media.rs          — image formats, video/audio embeds, srcset/picture, CDN detection
├── api_discovery.rs  — fetch/axios endpoints, GraphQL, WebSocket, __NEXT_DATA__, form actions
└── lib.rs
```

### Phase 2.5a: Fingerprint DB v2 ✅

- [x] Replace custom 30-tech DB with `rswappalyzer` v0.4.0 (7,000+ technologies)
- [x] Version detection via rswappalyzer capture groups
- [x] False positive filter (Onsen UI on wp-consent-api) + garbage version sanitizer
- [x] Categories as `Vec<String>` (CMS, Blogs, etc.)
- [x] `Detection` struct with name, categories, confidence, version
- [x] Tests: 10 tests (React, Next.js, Nginx, Cloudflare, WordPress, versions, false positives)

### Phase 2.5b: SEO Module ✅

- [x] Open Graph tags (og:title, og:description, og:image, og:type, og:url, og:site_name)
- [x] Twitter Cards (twitter:card, twitter:title, twitter:description, twitter:image, twitter:site)
- [x] JSON-LD structured data (extract @type, raw JSON)
- [x] Canonical URL (`<link rel="canonical">`)
- [x] Hreflang tags (language alternatives)
- [x] Robots meta (index/noindex, follow/nofollow)
- [x] Meta description, meta keywords
- [x] Favicon URL
- [x] `SeoReport` struct with weighted completeness score (9 checks, 0-100)
- [x] Tests: 8 tests

### Phase 2.5c: Performance Module ✅

- [x] Compression (Content-Encoding: gzip/br/zstd)
- [x] Cache headers (Cache-Control, ETag, Expires, Age)
- [x] HTTP/3 detection (alt-svc header)
- [x] Preload/prefetch/preconnect hints
- [x] Lazy loading coverage (images with `loading="lazy"` vs total)
- [x] Inline CSS count + byte size
- [x] `PerformanceReport` struct
- [x] Tests: 7 tests

### Phase 2.5d: Accessibility Module ✅

- [x] `<html lang="...">` presence and value
- [x] Image alt text coverage (with alt / empty alt / no alt counts)
- [x] Heading hierarchy (h1 count, full heading list, skip detection)
- [x] ARIA landmarks (role="main|nav|banner|contentinfo" count)
- [x] Form labels coverage (inputs with associated labels vs orphans)
- [x] `AccessibilityReport` struct with weighted score (6 checks, 0-100)
- [x] Tests: 6 tests

### Phase 2.5e: Content + Media Module ✅

- [x] Links: internal vs external count, external domains list
- [x] Word count (body text, excluding scripts/styles)
- [x] Iframes with platform detection (YouTube, Vimeo, Google Maps, Spotify, etc.)
- [x] Images: total count, formats breakdown (JPEG/PNG/WebP/AVIF/SVG/GIF)
- [x] Images: srcset/`<picture>` responsive coverage
- [x] Images: CDN detection (imgix, Cloudinary, Cloudflare Images)
- [x] Video: platform detection (YouTube, Vimeo, Wistia, self-hosted)
- [x] Audio: platform detection (Spotify, Apple, SoundCloud, self-hosted)
- [x] `ContentReport` + `MediaReport` structs
- [x] Tests: 9 tests (4 content + 5 media)

### Phase 2.5f: Fonts + PWA + API Discovery ✅

- [x] Fonts: Google Fonts URLs (CSS2 multi-param), Adobe Fonts, `@font-face` from inline CSS
- [x] PWA: `<link rel="manifest">`, service worker registration, theme-color, apple-touch-icon
- [x] API Discovery: fetch/axios endpoints from inline scripts
- [x] API Discovery: `__NEXT_DATA__`, `__NUXT__` detection
- [x] API Discovery: GraphQL endpoint detection
- [x] API Discovery: WebSocket URL detection (ws://, wss://)
- [x] API Discovery: `<form action="...">` POST endpoints
- [x] `FontsReport`, `PwaReport`, `ApiReport` structs
- [x] Tests: 15 tests (4 fonts + 4 PWA + 7 API discovery)

### Phase 2.5g: Integration ✅

- [x] `analyze.rs` calls all 9 intelligence modules
- [x] `AnalyzeResponse` expanded with seo, performance, accessibility, content, media, fonts, pwa, api
- [x] `analyze_types.rs` extracted (types + error constructor)
- [x] go-code `webanalyze/types.go` — all Go types matching Rust structs
- [x] go-code `webanalyze/client.go` — `AnalyzeResponse` with new fields, `Technology.Categories`
- [x] go-code `tool_site_analyze_format.go` — XML formatters for all 8 sections
- [x] Deploy ox-browser + go-code
- [x] Integration test: wordpress.org (SEO 100, a11y 100, 9 techs), piter.now (11 techs, SEO 95)

**Result:** Complete website intelligence from a single HTTP request. ~1500 LOC, 55 tests.
**Key dep:** `rswappalyzer` v0.4.0 (7,000+ technologies, Wappalyzer DB successor).
**Depends on:** Phase 2

## Phase 3: MCP Server (v0.3.0) ✅

**Goal:** Expose ox-browser as native MCP service for AI agents via Streamable HTTP.

**Architecture:** rmcp v1.1.0 SDK with `#[tool_handler]` proc-macro registration,
Streamable HTTP transport (SSE deprecated), mounted alongside REST API at `/mcp`.

### Phase 3a: Core MCP Infrastructure ✅

- [x] `ox-mcp` crate with rmcp v1.1.0 (Streamable HTTP transport)
- [x] `OxMcpServer` struct with `#[tool_router]` proc-macro registration
- [x] `ServerHandler` impl with `get_info()` (name, version, capabilities)
- [x] `StreamableHttpService` with `LocalSessionManager` for session management
- [x] MCP router merged with REST API via `axum::Router::merge()`

### Phase 3b: MCP Tools (REST Mirror) ✅

- [x] `fetch` — stealth HTTP fetch via wreq+BoringSSL (mirrors `/fetch`)
- [x] `fetch_smart` — three-tier CF bypass chain (mirrors `/fetch-smart`)
- [x] `analyze` — tech stack detection via Fingerprinter (mirrors `/analyze`)
- [x] `solve_cf` — Cloudflare challenge solver with cache (mirrors `/solve`)

### Phase 3c: Deploy + Integration ✅

- [x] Docker rebuild with MCP support (same port 8901, `/mcp` endpoint)
- [x] MCP initialize/tools/list smoke tests pass (4 tools registered)
- [x] `claude mcp add -s user -t http ox-browser http://127.0.0.1:8901/mcp`

**Result:** 4 MCP tools over Streamable HTTP, AI agents can fetch/analyze/bypass CF. ~400 LOC.
**Key tech:** rmcp v1.1.0, Streamable HTTP (not SSE), proc-macro tool registration.
**Competitive edge:** No browser needed — Chrome MCP (29 tools) and Playwright MCP (35+ tools)
require real browser; ox-browser is headless HTTP with stealth TLS fingerprinting.
**Depends on:** Phase 2

### Future MCP Tools (incremental)

- [ ] `seo_audit` — SEO analysis report (after Phase 2.5b)
- [ ] `performance_audit` — performance metrics (after Phase 2.5c)
- [ ] `accessibility_audit` — a11y report (after Phase 2.5d)
- [ ] `site_intelligence` — full Phase 2.5 report (after Phase 2.5g)
- [ ] `security_scan` — security audit (after Phase 4)
- [ ] `crawl` — site crawling (after Phase 5)

## Phase 4: Security Scanner (v0.4.0)

**Goal:** Vulnerability scanning and security posture assessment.

`ox-security` crate — focused on security analysis only (fingerprinting moved to `ox-intelligence`).

```
ox-security/src/
├── headers.rs   — HSTS, CSP, X-Content-Type-Options, Permissions-Policy, CORS, Referrer-Policy
├── cookies.rs   — Secure/HttpOnly/SameSite flags, known tracker cookies
├── xss.rs       — DOM sinks, event handlers, reflected patterns
├── csp.rs       — CSP parser + scorer (A-F grade)
├── sri.rs       — missing integrity attributes on scripts/styles
└── lib.rs
```

- [ ] Security headers analysis with severity grading
- [ ] Cookie security flags audit (Secure, HttpOnly, SameSite)
- [ ] Known tracker cookies detection (ga_, _fbp, _gid, etc.)
- [ ] XSS detector: DOM sinks, event handlers, reflected patterns
- [ ] CSP parser and scorer (A-F grade)
- [ ] SRI checker (missing integrity attributes)
- [ ] `SecurityReport` struct with findings + severity + recommendations
- [ ] `POST /security` endpoint (or `?security=true` param on `/analyze`)
- [ ] CLI: `ox-browser scan <url>`

**Result:** One-command security audit for any URL. ~800 LOC.
**Depends on:** Phase 2.5 (uses intelligence modules for context)

## Phase 5: Crawler (v0.5.0)

**Goal:** Crawl websites with configurable depth, filters, rate limiting.

- [ ] `ox-crawler` crate
- [ ] BFS/DFS crawl queue with deduplication (visited set)
- [ ] Depth and breadth limits
- [ ] URL include/exclude filters (regex)
- [ ] robots.txt parsing and respect
- [ ] Rate limiting (requests per second per domain)
- [ ] Callback-based page processing (integrates with intelligence + security modules)
- [ ] CLI: `ox-browser crawl <url> --depth 3`

**Result:** Full site crawling with polite behavior. ~500 LOC.
**Depends on:** Phase 1 (Phase 2.5 optional for per-page intelligence)

## Phase 6: Polish (v1.0.0)

**Goal:** Production-ready quality.

- [ ] CI/CD: GitHub Actions (test, lint, build, release)
- [ ] Benchmarks (parsing, analysis, CF solve time)
- [ ] Crate documentation (rustdoc, 60%+ coverage)
- [ ] GoReleaser-style binary releases

**Result:** Publishable crate + production Docker image.
**Depends on:** Phases 1-5

## Crate Architecture

```
ox-browser/crates/
├── core/           — Page, DOM (dom_query), forms, navigation, URL resolution
├── http/           — HTTP client (wreq+BoringSSL), proxy, cookies, CF detection, middleware
├── intelligence/   — Web intelligence: fingerprint, SEO, perf, a11y, content, media, fonts, PWA, API
├── security/       — Security scanning (Phase 4: headers, CSP, cookies, XSS, SRI)
├── js/             — REST API: /health, /solve, /fetch, /fetch-smart, /analyze
├── mcp/            — MCP server (rmcp v1.1.0, Streamable HTTP, 4 tools)
├── crawler/        — Site crawler (BFS/DFS, robots.txt, rate limiting)
└── src/            — Binary: CLI + server startup (serve.rs merges REST + MCP)
```

## Non-Goals

- **CSS layout/rendering** — no visual rendering, no computed styles
- **Full browser compatibility** — not trying to replace Chrome/Firefox
- **WebDriver/CDP protocol** — MCP is the integration protocol
- **Turnstile/CAPTCHA solving** — requires visual solver, out of scope

## Comparison

| Feature | ox-browser | go-stealth | go-browser |
|---------|-----------|-----------|------------|
| Language | Rust | Go | Go |
| Purpose | Web intelligence + CF bypass | Stealth HTTP client | Chrome automation |
| Chrome needed | No | No | Yes (Rod) |
| JS engine | External solver (Phase 2) | None | V8 (via Rod) |
| DOM parsing | dom_query (mutable) | None | Chrome DOM |
| TLS fingerprinting | ✅ wreq+BoringSSL | Yes (tls-client) | Via Chrome |
| Browser profiles | 16 built-in ✅ | 16 built-in | N/A |
| CF detection | ✅ (Phase 1.5) | ✅ | N/A |
| CF JS solving | ✅ via Byparr/FlareSolverr | No (delegates) | Via Chrome |
| CF 200 detection | ✅ (cf-mitigated, body markers) | No | N/A |
| HTTP API | ✅ /fetch, /fetch-smart, /analyze | No | No |
| Tech detection | ✅ 7,000+ technologies (rswappalyzer) | No | No |
| SEO analysis | ✅ OG, Twitter, JSON-LD, hreflang, score | No | No |
| Web intelligence | ✅ SEO + perf + a11y + content + media + fonts + PWA + API | No | No |
| Security audit | Phase 4 (headers, CSP, XSS) | No | No |
| Proxy pool | Webshare + health ✅ | Webshare + health | No |
| Rate limiting | Per-domain ✅ | Per-domain | No |
| Middleware | Chain pattern ✅ | Chain pattern | No |
| MCP server | ✅ 4 tools, Streamable HTTP (v0.3.0) | No | No |

**When to use which:**
- **ox-browser** — web intelligence, security audit, CF bypass, no Chrome dependency
- **go-stealth** — stealth HTTP requests without DOM/JS, delegates CF to ox-browser
- **go-browser** — SPA rendering, full JS, screenshot/PDF (needs Chromium)
