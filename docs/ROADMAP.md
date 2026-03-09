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

- [x] Browser profiles: 16 UA strings (Chrome/Firefox/Safari/Edge x Win/Mac/Linux/Mobile)
- [x] Client Hints: auto-inject `sec-ch-ua-*` headers matching UA
- [x] Header ordering: realistic browser header order per profile
- [x] Middleware chain: composable `Handler` trait (logging, retry, rate limit, client hints)
- [x] Retry with backoff: exponential backoff + jitter on 429/5xx, retryable error classification
- [x] Proxy pool: Webshare API integration, round-robin rotation, health tracking
- [x] Per-domain rate limiting: sliding window + min delay, Retry-After parsing
- [x] Session: persistent browsing context (consistent fingerprint, cookie jar)
- [x] Cloudflare detection: `detect_cloudflare()` + `cloudflare_detect_middleware`
- [x] CF challenge types: JsChallenge, Turnstile, Block
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
**Key change:** `reqwest` -> `wreq` (near-identical API, BoringSSL backend).

## Phase 2: Cloudflare Bypass + HTTP API (v0.2.0) ✅

**Goal:** Solve Cloudflare challenges via external solver, provide cookies to go-stealth,
expose fetch/analyze API for the ecosystem.

### Phase 2a: CookieProvider + Solver Integration ✅

- [x] `CookieProvider` trait: `async fn solve(url, challenge_type) -> SolvedChallenge`
- [x] `SolvedChallenge` struct: cookies HashMap + user_agent
- [x] `CookieCache`: per-domain TTL cache (25min default, matching cf_clearance lifetime)
- [x] `ByparrSolver`: FlareSolverr-compatible HTTP client
- [x] `solver_middleware`: intercepts HttpError::Cloudflare, solves, injects cookies, retries

### Phase 2b: CF Detection at HTTP 200 ✅

- [x] Detect Cloudflare challenges hidden behind HTTP 200 responses
- [x] `cf-mitigated` header detection (managed challenge)
- [x] Body markers: `_cf_chl_opt`, `challenge-platform`, `cf-turnstile`
- [x] 35 hard red tests covering edge cases

### Phase 2c: HTTP API ✅

- [x] `POST /solve`, `POST /fetch`, `POST /fetch-smart`, `POST /analyze`, `/health`
- [x] Three-tier fetch chain: proxy -> ox-browser -> Byparr fallback

### Phase 2d: Docker Deployment ✅

- [x] Multi-stage Dockerfile: cargo-chef + BoringSSL build
- [x] docker-compose.yml entry (port 8901, backend network)
- [x] Integration with go-code `site_analyze` and go-search `web_url_read`

**Result:** CF bypass + stealth fetch API + tech analysis. ~5800 LOC, 220 tests.
**Depends on:** Phase 1.5

## Phase 2.5: Web Intelligence (v0.2.5) ✅

**Goal:** Full website analysis — technology stack, SEO, performance, accessibility, content,
media, fonts, PWA, API discovery. One `POST /analyze` -> complete intelligence report.

**Crate:** `ox-intelligence` (9 modules, ~1500 LOC, 55 tests).

- [x] Fingerprint: rswappalyzer 7,000+ technologies
- [x] SEO: OG, Twitter Cards, JSON-LD, canonical, hreflang, robots, score 0-100
- [x] Performance: compression, cache, HTTP/3, preload, lazy images
- [x] Accessibility: lang, alt coverage, headings, ARIA, form labels, score 0-100
- [x] Content: links, word count, iframes
- [x] Media: image formats, video/audio, srcset, CDN detection
- [x] Fonts: Google Fonts, Adobe Fonts, @font-face
- [x] PWA: manifest, service worker, theme-color
- [x] API Discovery: fetch/axios endpoints, GraphQL, WebSocket, __NEXT_DATA__, WebMCP, public API

**Depends on:** Phase 2

## Phase 3: MCP Server (v0.3.0) ✅

**Goal:** Expose ox-browser as native MCP service for AI agents via Streamable HTTP.

- [x] `ox-mcp` crate with rmcp v1.1.0 (Streamable HTTP transport)
- [x] 4 MCP tools: `fetch`, `fetch_smart`, `analyze`, `solve_cf`
- [x] Merged with REST API at `/mcp` endpoint
- [x] `claude mcp add -s user -t http ox-browser http://127.0.0.1:8901/mcp`

**Result:** 4 MCP tools over Streamable HTTP. ~400 LOC.
**Depends on:** Phase 2

### Future MCP Tools (incremental)

- [x] `site_audit` — comprehensive audit with scores, findings, recommendations (replaces individual audit tools)
- [ ] `site_intelligence` — full Phase 2.5 report
- [x] `security_scan` — security audit (Phase 4)
- [x] `crawl` — site crawling (Phase 5)
- [x] `image_search` — image search (Phase 4.6)

## Phase 4: Security Scanner (v0.4.0-v0.5.1) ✅

**Goal:** Passive security posture assessment from a single HTTP response — Observatory-compatible scoring.

`ox-security` crate — 14 modules, ~2500 LOC, 135 tests.

### Phase 4.0: Core Security Modules (v0.4.0) ✅

8 modules, 58 tests:

- [x] Security headers analysis (15 headers) with severity grading
- [x] Cookie security audit (Secure, HttpOnly, SameSite, __Host-/__Secure- prefixes)
- [x] CSP parser and scorer (A-F grade, Observatory-compatible)
- [x] SRI checker (missing integrity on external scripts/styles)
- [x] CORS misconfiguration detection (wildcard ACAO, credentials misuse)
- [x] Supply chain risk (polyfill.io, bootcss, bootcdn)
- [x] Mixed content detection (HTTP resources on HTTPS pages)
- [x] Observatory-compatible scoring (base 100, modifiers, grades F to A+)
- [x] `POST /security` REST endpoint + `security_scan` MCP tool

### Phase 4.5: Deep Security Scanner (v0.5.0-v0.5.1) ✅

Closed all gaps vs ZAP passive rules, Mozilla Observatory, SecurityHeaders.com.
+6 new modules, enhanced 4 existing modules, integrated 6 spec-compliant crates.

**Library integrations (v0.5.0):**
- `content-security-policy` v0.6 — W3C CSP Level 3 parser (replaced regex parser)
- `ammonia` v4.1 — HTML sanitizer for XSS pattern detection
- `oxc_parser` v0.116 — JS AST analysis for dangerous patterns
- `semver` v1 — semantic version comparison for vulnerable JS detection
- `ipnet` v2.12 — CIDR-based private IP detection (replaced regex)
- `psl` v2.1 — Public Suffix List for cookie domain scoping and SRI origin checks

**New modules:**

| Module | What it detects | Tests |
|--------|----------------|-------|
| `info_disclosure` | Server version, X-Powered-By, debug headers, deprecated headers | 9 |
| `body_scan` | Private IPs (ipnet), XSS (ammonia), stack traces, source maps, CSRF forms | 21 |
| `vuln_js` | jQuery/Angular/React/Bootstrap/etc. with semver comparison | 8 |
| `dangerous_js` | AST-based: Function constructor, innerHTML, setTimeout+string (oxc_parser) | 9 |
| `redirect` | HTTP sites (Critical), HTTPS->HTTP downgrade (High), cross-host (Info) | 5 |
| `scoring/bonuses` | +5 strict Referrer-Policy, +5 HSTS preload-ready (when base >= 90) | - |

**Enhanced modules:**

| Module | Enhancement |
|--------|------------|
| `headers` | HSTS preload-readiness, Cache-Control audit, Basic Auth detection, X-XSS-Protection deprecation |
| `cookies` | PSL domain scoping (Critical on public suffixes), CSRF cookie detection |
| `csp` | W3C Level 3 parser, multiple policies, upgrade-insecure-requests, reporting detection |
| `sri` | PSL-based cross-origin check (registrable domain comparison) |

```
ox-security/src/
├── types.rs             — Severity enum (Info/Low/Medium/High/Critical)
├── headers/
│   ├── mod.rs           — analyze_headers(headers, url)
│   ├── checks.rs        — Core checks (HSTS, CSP, XCTO, XFO, Referrer, COOP, Permissions)
│   ├── checks_ext.rs    — Extended checks (Cache-Control, Basic Auth, HSTS preload)
│   └── tests.rs         — 15 tests
├── csp/
│   ├── mod.rs           — CspReport, policy_count, upgrade_insecure, reporting
│   ├── parser.rs        — W3C parser via content-security-policy crate
│   ├── checks.rs        — Bypass detection + insecure scheme + reporting
│   └── tests.rs         — 14 tests
├── cookies/
│   ├── mod.rs           — PSL domain scoping, CSRF detection, analyze_cookies(hdrs, url)
│   └── tests.rs         — 9 tests
├── cors.rs              — CORS misconfiguration (5 tests)
├── sri.rs               — SRI with PSL-based origin check (6 tests)
├── supply_chain.rs      — Risky CDN domains (4 tests)
├── mixed_content.rs     — HTTP on HTTPS (4 tests)
├── info_disclosure.rs   — Server version, debug headers, deprecated headers (9 tests)
├── body_scan/
│   ├── mod.rs           — Private IP, XSS, stack traces, source maps, CSRF forms
│   └── tests.rs         — 21 tests
├── vuln_js.rs           — Vulnerable JS with semver (8 tests)
├── dangerous_js.rs      — AST-based JS analysis via oxc_parser (9 tests)
├── redirect.rs          — HTTP/HTTPS redirect analysis (5 tests)
├── fingerprint.rs       — Legacy (moved to ox-intelligence)
├── scoring/
│   ├── mod.rs           — SecurityReport, FindingsSummary, score_to_grade()
│   ├── aggregate.rs     — analyze_security(), compute_score(), count_findings()
│   └── bonuses.rs       — Referrer-Policy +5, HSTS preload +5
└── lib.rs
```

**Result:** 14 modules, ~2500 LOC, 135 tests. Full Observatory/ZAP passive parity.
**Scoring:** Mozilla Observatory-compatible (base 100, bonuses up to +10, grades F to A+).
**Key crates:** content-security-policy, ammonia, oxc_parser, semver, ipnet, psl.

### Phase 4.5k: go-probe Integration (pending)

- [ ] `POST /security` gains `deep: true` parameter
- [ ] When deep=true, calls go-probe for TLS + DNS analysis
- [ ] Merge TLS + DNS findings into SecurityReport
- [ ] Combined weighted scoring (passive 60%, TLS 25%, DNS 15%)
- [ ] `security_scan` MCP tool gains `deep` parameter
- **Depends on:** go-probe v0.2.0

## Phase 4.6: Image Search Engine (v0.5.2) ✅

**Goal:** Scrape image search results from multiple engines using the stealth HTTP
infrastructure. Expose via REST and MCP. Primary consumer: go-imagefy.

See `docs/plans/2026-03-06-phase5-imagesearch-design.md` for full design.

- [x] `ox-imagesearch` crate with `ImageResult` + `ImageEngine` trait
- [x] Bing Images engine (`/images/async` endpoint parser)
- [x] DDG Images engine (vqd token + `/i.js` JSON API)
- [x] Openverse engine (Creative Commons API, no auth)
- [x] Pexels engine (stock photo API, requires `PEXELS_API_KEY`)
- [x] Brave Images engine (SvelteKit SPA scraper with cookie injection)
- [x] `ImageSearchEngine` fusion: parallel engines + WRR merge + dedup
- [x] `POST /images/search` REST endpoint + `image_search` MCP tool
- [x] 25 unit tests (bing 4, ddg 4, fusion 5, openverse 4, pexels 4, brave 4)
- [ ] Yandex Images engine (requires headless browser, out of scope)

**Result:** 5-engine image search with stealth scraping. ~1400 LOC, 25 tests.
**Depends on:** Phase 2

## Phase 4.7: Runtime Configuration (v0.5.3) ✅

**Goal:** All hardcoded settings configurable via TOML without Docker rebuild.

- [x] Modular config system: 10 sections in `src/config/` (26 parameters)
- [x] Priority chain: defaults → config.toml → env vars → CLI args
- [x] `EndpointDefaults` propagated to REST (`AppState`) and MCP (`OxMcpServer`)
- [x] Docker volume mount for config.toml (no rebuild on config change)
- [x] `--config` CLI flag with `OX_BROWSER_CONFIG` env fallback
- [x] 12 unit tests for config parsing, defaults, CLI overrides, builders
- [x] Clippy fixes: needless lifetime, Default derive, map-to-unit, redundant trim

**Sections:** `[server]` `[http]` `[retry]` `[cache]` `[proxy]` `[solver]` `[cloudflare]` `[log]` `[fetch]` `[images]`

**Result:** 26 runtime-configurable parameters, 0 hardcoded values. 502 tests.
**Depends on:** Phase 2

## Phase 5: Site Crawler (v0.6.0) ✅

**Goal:** Crawl websites with configurable depth/scope, streaming results,
markdown output for AI consumers (Claude, go-code).

See `docs/plans/2026-03-07-phase5-crawler-design.md` for full design.

### Phase 5.0: Core Crawl Engine ✅

- [x] `CrawlConfig`: depth, max_pages, concurrency, scope, budget per path
- [x] URL frontier: `VecDeque` + depth priority (BFS default)
- [x] URL dedup: xxHash → `HashSet<u64>` (normalized URLs)
- [x] Scope filters: same_domain, same_host
- [x] Crawl loop: tokio task pool + `mpsc` channel streaming
- [x] `CrawlResult`: url, status, title, markdown, links_found, depth, source, file_path
- [x] Reuse: `HttpClient`, `Page::links()`, `resolve_url()`, `Pool`

### Phase 5.1: Polite Crawling ✅

- [x] robots.txt: parse + per-domain cache (`robotstxt` crate)
- [x] Per-path URL budgets: `{"*": 300, "/blog": 50}`
- [x] Content dedup: blake3 hash to skip duplicate pages at different URLs

### Phase 5.2: Markdown & Extraction ✅

- [x] HTML → Markdown conversion (htmd crate)
- [x] Noise filter: nav, footer, ads stripped before conversion
- [x] Link metadata: internal/external, anchor text

### Phase 5.3: Sitemap Discovery ✅

- [x] Three discovery modes: `bfs` (default), `sitemap`, `hybrid`
- [x] Sitemap XML parsing: urlset + sitemap index (recursive)
- [x] Gzip-compressed sitemaps (flate2, magic byte detection)
- [x] Sitemap filters: `sitemap_filter` (name substring), `sitemap_since` (lastmod date)
- [x] Priority-based frontier ordering from sitemap priorities
- [x] Seed URL skip in sitemap-only mode when entries exist

### Phase 5.4: REST + MCP Integration ✅

- [x] `POST /crawl` REST endpoint with SSE streaming (`event: sitemap`, `page`, `done`)
- [x] `crawl` MCP tool (Streamable HTTP)
- [x] Discovery mode validation in both REST and MCP handlers
- [x] `output_dir` propagated to summaries (save_to_file mode)

### Phase 5.5: Output Denoising ✅

- [x] SRI findings deduplicated by registrable domain (70→1 on Stripe)
- [x] Supply chain findings deduplicated by domain (64→1 on Stripe)
- [x] Script URL deduplication in supply chain (HashSet)
- [x] JSON-LD raw truncated to 2KB (UTF-8-safe) with @graph type extraction
- [x] Headings capped at 50 (scoring computed on full set)

**Result:** Full site crawler with 3 discovery modes, SSE streaming, markdown output, sitemap support, gzip. Output denoised for MCP consumption. ~2000 LOC.
**Depends on:** Phase 1, Phase 4.7

## Phase 5.6: WebMCP + Public API + SSRF Protection (v0.7.0) ✅

**Goal:** Detect WebMCP (W3C) support and public API surfaces, fix SSRF vulnerability.

### WebMCP Detection ✅

- [x] Declarative: `<form toolname="..." tooldescription="...">` → tool name, description, inputs
- [x] Imperative: `navigator.modelContext` / `modelContext.registerTool` in scripts
- [x] `WebMcpReport`: supported, declarative_tools, imperative_detected, tool_count
- [x] 3 tests (declarative, imperative, no false positives)

### Public API Detection ✅

- [x] `<link rel="api|service|service-desc|describedby">` detection
- [x] `<a>` links matching swagger/openapi/redoc/rapidoc patterns
- [x] OpenAPI/Swagger config objects in HTML (SwaggerUI, "openapi": "3")
- [x] `.well-known/` paths: openid-configuration, ai-plugin.json, mcp.json, host-meta
- [x] GraphQL playground hints (graphiql, graphql-playground)
- [x] `PublicApiReport`: detected, openapi_url, api_links, well_known, hints
- [x] 4 tests (OpenAPI link, well-known, Swagger UI, GraphQL playground, no false positives)

### SSRF Protection ✅

- [x] `middleware_ssrf`: outermost middleware blocking private/reserved IPs
- [x] DNS resolution before check (blocks Docker service names like `redis`, `postgres`)
- [x] Blocked ranges: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 (CGNAT), ::1, fc00::/7, fe80::/10, broadcast, documentation
- [x] Scheme validation (only http/https)
- [x] 10 tests

### Module Split ✅

- [x] `api_discovery.rs` (476 lines) → directory module: mod.rs (122), webmcp.rs (64), public_api.rs (77), tests.rs (212)

**Result:** WebMCP + public API detection, SSRF fix. 17 new tests, ~360 new LOC.
**Depends on:** Phase 2.5

### Phase 5.7: Site Audit Tool ✅

- [x] Performance scoring (0-100, 10 criteria)
- [x] Audit finding generators: SEO (8 rules), performance (7 rules), accessibility (7 rules), security (adapter)
- [x] Grade system (A+ to F), overall weighted scoring, top issues collector
- [x] `site_audit` MCP tool with `focus` parameter (all/seo/performance/accessibility/security)
- [x] `POST /site-audit` REST endpoint
- [x] 9 new tests, 593 total

**Result:** Single audit tool replacing 3 planned individual tools. Rule-based, no LLM.

### Rust Edition 2024 ✅

- [x] Upgraded from edition 2021 to 2024 (Rust 1.93)
- [x] Fixed implicit borrowing patterns (`ref` removal)
- [x] Wrapped `set_var`/`remove_var` in `unsafe` blocks (process-wide mutation)
- [x] 584 tests pass

## Phase 6: Polish (v1.0.0)

**Goal:** Production-ready quality.

- [x] CI/CD: GitHub Actions (test, lint, build, release) — `release.yml` builds x86_64+aarch64
- [ ] Benchmarks (parsing, analysis, CF solve time)
- [ ] Crate documentation (rustdoc, 60%+ coverage)
- [x] Binary releases via GitHub Actions (cross-compiled, 2 targets)

**Depends on:** Phases 1-5

## Crate Architecture

```
ox-browser/crates/
├── core/           — Page, DOM (dom_query), forms, navigation, URL resolution
├── http/           — HTTP client (wreq+BoringSSL), proxy, cookies, CF detection, SSRF protection, middleware
├── intelligence/   — Web intelligence: fingerprint, SEO, perf, a11y, content, media, fonts, PWA, API
├── security/       — Security: 14 modules, Observatory scoring, AST analysis, 6 crate integrations
├── imagesearch/    — Image search: Bing, DDG parsers + WRR fusion (13 tests)
├── js/             — REST API: /health, /solve, /fetch, /fetch-smart, /analyze, /security, /images/search
├── mcp/            — MCP server (rmcp v1.1.0, Streamable HTTP, 9 tools)
├── crawler/        — Site crawler (BFS/DFS, robots.txt, rate limiting, markdown output)
└── src/            — Binary: CLI + server startup
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
| TLS fingerprinting | wreq+BoringSSL | tls-client | Via Chrome |
| CF bypass | JS + Turnstile + Block + HTTP 200 | JS + Turnstile | Via Chrome |
| Tech detection | 7,000+ (rswappalyzer) | No | No |
| Web intelligence | 9 modules (SEO, perf, a11y, ...) | No | No |
| Security audit | 14 modules, 135 tests, Observatory | No | No |
| MCP server | 9 tools, Streamable HTTP | No | No |
| HTTP API | /fetch, /analyze, /security | No | No |

**Ecosystem:**
- **ox-browser** — web intelligence, passive security audit, CF bypass, no Chrome dependency
- **go-probe** — active TLS + DNS security probing (complements ox-browser)
- **go-stealth** — stealth HTTP requests without DOM/JS, delegates CF to ox-browser
- **go-browser** — SPA rendering, full JS, screenshot/PDF (needs Chromium)
