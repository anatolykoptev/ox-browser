# Phase 5: Site Crawler — Design Document

**Date:** 2026-03-07
**Version:** v0.6.0
**Consumers:** Claude (MCP), go-code, REST API

## Research Summary

Analyzed 7 crawlers across 4 languages:

| Crawler | Lang | Stars | Key Innovation |
|---------|------|-------|---------------|
| spider-rs | Rust | 4k | Streaming via mpsc, per-path budgets, feature flags |
| Scrapy | Python | 54k | Middleware chain, AutoThrottle, DUPEFILTER |
| Crawl4AI | Python | 61k | fit_markdown (BM25 noise removal), URL scoring |
| Crawlee | TypeScript | 22k | Adaptive HTTP→browser, AutoscaledPool, SessionPool |
| Firecrawl | TS+Rust | 89k | /map endpoint, Rust core for perf-critical paths |
| colly | Go | 21k | Callback API, Storage trait, FNV dedup |
| katana | Go | 12k | Pipeline arch, depth-priority queue, cycle detection |

## Architecture

### Reused from ox-browser

| Component | Source | Usage |
|-----------|--------|-------|
| `HttpClient` | ox-http | All page fetches (middleware chain, TLS, proxy) |
| `Page::links()` | ox-core | Link extraction from DOM |
| `resolve_url()` | ox-core | Relative → absolute URL |
| `is_same_origin()` | ox-core | Scope filtering |
| `DomainLimiter` | ox-http | Per-domain rate limiting |
| `RetryConfig` | ox-http | Retry on 429/5xx |
| `Pool` | ox-core | Concurrency control (tokio semaphore) |
| Config system | src/config | `[crawler]` TOML section |

### New modules in ox-crawler

```
ox-crawler/src/
├── lib.rs          — Public API: Crawler::new(), crawl() → CrawlStream
├── config.rs       — CrawlConfig, CrawlScope, default values
├── frontier.rs     — URL frontier: VecDeque + depth tracking
├── dedup.rs        — URL dedup (xxHash) + content dedup (blake3)
├── scope.rs        — Domain/path/regex filters + cycle detection
├── robots.rs       — robots.txt parser + per-domain cache
├── markdown.rs     — HTML→Markdown + fit_markdown noise filter
├── result.rs       — CrawlResult struct
└── budget.rs       — Per-path URL budgets
```

## Key Types

```rust
/// Crawl configuration.
pub struct CrawlConfig {
    pub max_depth: u32,              // default: 3
    pub max_pages: usize,            // default: 100
    pub concurrency: usize,          // default: 5
    pub scope: CrawlScope,           // same_domain | same_host | regex
    pub budget: HashMap<String, u32>,// per-path: {"*": 300, "/blog": 50}
    pub respect_robots: bool,        // default: true
    pub include_markdown: bool,      // default: true
    pub delay_ms: u64,               // default: 200
    pub user_agent: Option<String>,  // for robots.txt identification
}

/// Scope control.
pub enum CrawlScope {
    SameDomain,                      // same registrable domain
    SameHost,                        // exact hostname match
    Custom {
        allow: Vec<Regex>,
        block: Vec<Regex>,
    },
}

/// Result for each crawled page.
pub struct CrawlResult {
    pub url: String,
    pub status: u16,
    pub depth: u32,
    pub title: String,
    pub markdown: String,            // clean markdown
    pub content_length: usize,
    pub links_found: usize,
    pub is_redirect: bool,
    pub elapsed_ms: u64,
    pub error: Option<String>,       // non-fatal errors
}

/// Streaming API.
pub struct CrawlStream {
    rx: mpsc::Receiver<CrawlResult>,
    stats: Arc<CrawlStats>,
}
```

## Crawl Loop

```
seed URL
    ↓
[Frontier: VecDeque sorted by depth (BFS)]
    ↓  dequeue
[Filter chain in enqueue()]:
  1. Parse + normalize URL (url::Url, strip fragment, sort params)
  2. Depth check (BEFORE dedup — katana pattern)
  3. xxHash → check visited HashSet
  4. Scope check (domain/host/regex)
  5. Budget check (per-path counter)
  6. Cycle detection (repeating path segments)
  7. Extension filter (skip .pdf, .zip, .jpg, etc.)
    ↓  pass
[Rate limiter]: DomainLimiter.wait()
    ↓
[robots.txt]: lazy per-host cache, check allow/disallow
    ↓
[Fetch]: HttpClient.get(url)
    ↓
[Process]:
  - Parse HTML → Page
  - Extract links → resolve_url() → enqueue()
  - Convert to markdown (if enabled)
  - Build CrawlResult
    ↓
[Stream]: mpsc::Sender → consumer
```

## Adopted Patterns

| Pattern | Source | Why |
|---------|--------|-----|
| Streaming via `mpsc` channel | spider-rs | Process pages as they arrive |
| Per-path URL budgets | spider-rs | Scope control without filter callbacks |
| Depth-priority queue (BFS) | katana | Breadth-first by default |
| Depth check before dedup | katana | Avoid caching deep URLs |
| Cycle detection | katana | Cheap protection from crawler traps |
| xxHash for URL dedup | colly | 8 bytes per URL vs 50-200 for strings |
| robots.txt lazy cache | colly | RwLock + parse once per host |
| fit_markdown noise removal | Crawl4AI | Clean output for LLM consumers |
| Content dedup via hash | katana | Skip same content at different URLs |

## YAGNI — Not Building

- Browser/headless mode (wreq+BoringSSL sufficient)
- Distributed/decentralized mode
- LLM extraction (consumers handle this)
- Screenshots
- Cron scheduling
- Sitemap parsing (can add later)
- Adaptive HTTP→browser (no browser to upgrade to)

## Dependencies (new)

```toml
[dependencies]
ox-http = { path = "../http" }
ox-core = { path = "../core" }
tokio = { workspace = true }
url = "2"
regex = "1"
xxhash-rust = { version = "0.8", features = ["xxh3"] }
blake3 = "1"
texting_robots = "0.2"     # robots.txt parser (well-maintained)
htmd = "0.1"               # HTML→Markdown converter
```

## REST + MCP

### REST: `POST /crawl`
```json
{
  "url": "https://example.com",
  "max_depth": 3,
  "max_pages": 50,
  "scope": "same_domain",
  "include_markdown": true
}
```
Response: SSE stream of `CrawlResult` objects, final event = stats summary.

### MCP: `crawl` tool
Same parameters, returns aggregated results (MCP doesn't support streaming yet in rmcp).

### Config: `[crawler]` section
```toml
[crawler]
default_max_depth = 3
default_max_pages = 100
default_concurrency = 5
default_delay_ms = 200
respect_robots = true
include_markdown = true
```
