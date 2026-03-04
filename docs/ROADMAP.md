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

**Goal:** Anti-detection HTTP layer ported from go-stealth patterns. Make requests indistinguishable from real browsers.

- [x] Browser profiles: 16 UA strings (Chrome/Firefox/Safari/Edge × Win/Mac/Linux/Mobile)
- [x] Client Hints: auto-inject `sec-ch-ua-*` headers matching UA
- [x] Header ordering: realistic browser header order per profile
- [x] Middleware chain: composable `Middleware` trait (logging, retry, rate limit, client hints)
- [x] Retry with backoff: exponential backoff + jitter on 429/5xx, retryable error classification
- [x] Proxy pool: Webshare API integration, round-robin rotation, health tracking (success rate, latency, auto-deactivation)
- [x] Per-domain rate limiting: sliding window + min delay + random delay, Retry-After parsing
- [x] Session: persistent browsing context (consistent fingerprint, cookie jar, request counting)
- [x] CLI: `ox-browser fetch <url> --profile chrome` (profile selection)
- [x] Unit + integration tests for profiles, retry, rate limiter, proxy pool (139 tests)

**Result:** Stealth HTTP client that passes bot detection. ~2900 LOC, 139 tests.
**Ported from:** `go-stealth` (Grade A, 6.6K LOC) — concepts adapted to Rust idioms.
**Depends on:** Phase 1

## Phase 2: JavaScript (v0.2.0)

**Goal:** Execute JS on pages, expose DOM to scripts.

- [ ] `JsEngine` trait with pluggable backends
- [ ] Boa backend (default): `boa_engine` 0.21+
- [ ] DOM bindings: document, window, element → dom_query
- [ ] addEventListener support (click, submit, load)
- [ ] Inline `<script>` execution on page load
- [ ] Feature flag `quickjs`: rquickjs backend
- [ ] CLI: `ox-browser fetch --js <url>`

**Result:** Pages with inline JS render correctly. DOM mutations from JS visible. ~500-800 LOC bindings.
**Depends on:** Phase 1

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
- [ ] Tools: browse, select, run_script, fill_form, crawl, security_scan, extract_links, extract_meta
- [ ] Docker container with multi-stage build
- [ ] docker-compose.yml entry (port 8901)
- [ ] Integration with krolik-agent (skill + mcp_call)
- [ ] Health endpoint

**Result:** AI agents can browse, scrape, and scan via MCP. ~400 LOC.
**Depends on:** Phases 1-4

## Phase 6: Polish (v1.0.0)

**Goal:** Production-ready quality.

- [ ] Clippy config (strict, deny warnings)
- [ ] CI/CD: GitHub Actions (test, lint, build, release)
- [ ] Benchmarks (parsing, JS execution, crawl throughput)
- [ ] README.md with examples
- [ ] Crate documentation (rustdoc, 60%+ coverage)
- [ ] GoReleaser-style binary releases

**Result:** Publishable crate + production Docker image.
**Depends on:** Phases 1-5

## Non-Goals

- **CSS layout/rendering** — no visual rendering, no computed styles
- **Full browser compatibility** — not trying to replace Chrome/Firefox
- **WebDriver/CDP protocol** — MCP is the integration protocol
- **Image/media processing** — text and HTML only
- **WebSocket connections** — HTTP request/response only in MVP

## Comparison

| Feature | ox-browser | go-stealth | go-browser | kalamari |
|---------|-----------|-----------|------------|----------|
| Language | Rust | Go | Go | Rust |
| Purpose | Headless browser | Stealth HTTP client | Chrome automation | Headless browser |
| Chrome needed | No | No | Yes (Rod) | No |
| JS engine | Boa + QuickJS | None | V8 (via Rod) | Boa |
| DOM parsing | dom_query (mutable) | None | Chrome DOM | Custom |
| TLS fingerprinting | rustls (Phase 1.5) | Yes (tls-client) | Via Chrome | No |
| Browser profiles | 16 built-in ✅ | 16 built-in | N/A | No |
| Proxy pool | Webshare + health ✅ | Webshare + health | No | No |
| Rate limiting | Per-domain ✅ | Per-domain | No | No |
| Middleware | Chain pattern ✅ | Chain pattern | No | No |
| Security scanning | Planned (Phase 3) | No | No | Built-in |
| Crawling | Planned (Phase 4) | No | No | Basic |
| MCP server | Planned (Phase 5) | No | No | No |
| Binary size | ~10MB est. | ~15MB | ~15MB + Chromium | ~8MB |
| Quality | Grade A (v0.1.0) | Grade A | Grade A | Grade D |

**When to use which:**
- **ox-browser** — lightweight scraping + DOM + JS, security scanning, no Chrome dependency
- **go-stealth** — stealth HTTP requests without DOM/JS (API scraping, anti-bot bypass)
- **go-browser** — SPA rendering, full JS, screenshot/PDF generation
- **ox-browser + go-stealth patterns** — Phase 1.5 combines both: DOM parsing + stealth HTTP
