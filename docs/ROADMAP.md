# ox-browser Roadmap

Module: `github.com/anatolykoptev/ox-browser`
Naming convention: `ox-*` prefix for Rust services (oxide theme), parallel to `go-*` for Go.

## Phase 1: Core MVP (v0.1.0)

**Goal:** Fetch pages, parse DOM, extract data — no JS, no browser chrome.

- [ ] Workspace setup (Cargo.toml, 6 crates)
- [ ] `ox-http`: reqwest wrapper with proxy, cookies, interceptor
- [ ] `ox-core`: Browser, Page, DOM facade over dom_query
- [ ] Page: navigate, select, title, html, text, forms
- [ ] Form extraction and filling (extract fields, set values, serialize)
- [ ] URL resolution (relative → absolute, redirect following)
- [ ] Concurrency pool (semaphore, context-aware)
- [ ] CLI: `ox-browser fetch <url>` → stdout
- [ ] Unit tests (target: 30%+ coverage)

**Result:** Usable HTML scraper with CSS selectors and form support. ~800 LOC.

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

| Feature | ox-browser | go-browser | kalamari |
|---------|-----------|------------|----------|
| Language | Rust | Go | Rust |
| Chrome needed | No | Yes (Rod) | No |
| JS engine | Boa + QuickJS | V8 (via Rod) | Boa |
| DOM | dom_query (mutable) | N/A (Chrome DOM) | Custom |
| Binary size | ~10MB est. | ~15MB + Chromium | ~8MB |
| Security scanning | Built-in | No | Built-in |
| Crawling | Built-in | No | Basic |
| MCP server | Yes | No (library) | No |
| SPA support | Limited (Boa) | Full (Chrome) | Limited (Boa) |

**When to use which:**
- **ox-browser** — lightweight scraping, security scanning, SEO analysis, no Chrome dependency
- **go-browser** — SPA rendering, full JS compatibility, screenshot/PDF generation
