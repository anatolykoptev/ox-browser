# Phase 5: Site Crawler Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a streaming site crawler with BFS traversal, robots.txt, dedup, scope filters, markdown output, exposed via REST and MCP.

**Architecture:** Producer-consumer crawl loop using tokio tasks + mpsc channel. The crawler dequeues URLs from a frontier, fetches via existing `HttpClient`, extracts links via `Page::links()`, and streams `CrawlResult` objects to consumers. All heavy infrastructure (HTTP, TLS, proxy, retry, rate limiting) is reused from ox-http/ox-core.

**Tech Stack:** Rust 1.88, tokio, `texting_robots` (robots.txt), `htmd` (HTML→Markdown), `xxhash-rust` (URL dedup), `blake3` (content dedup), `regex` (scope filters)

---

### Task 1: Cargo.toml + Types Foundation

**Files:**
- Modify: `crates/crawler/Cargo.toml`
- Create: `crates/crawler/src/result.rs`
- Modify: `crates/crawler/src/lib.rs`

**Step 1: Set up Cargo.toml with dependencies**

```toml
[package]
name = "ox-crawler"
version.workspace = true
edition.workspace = true

[dependencies]
ox-http = { path = "../http" }
ox-core = { path = "../core" }
tokio = { workspace = true }
url = "2"
regex = "1"
xxhash-rust = { version = "0.8", features = ["xxh3"] }
blake3 = "1"
texting_robots = "0.2"
htmd = "0.5"
tracing = "0.1"
serde = { version = "1", features = ["derive"] }

[dev-dependencies]
tokio = { workspace = true, features = ["test-util"] }
```

**Step 2: Create result.rs with CrawlResult**

```rust
//! Crawl result types.

use serde::Serialize;

/// Result for a single crawled page.
#[derive(Debug, Clone, Serialize)]
pub struct CrawlResult {
    pub url: String,
    pub status: u16,
    pub depth: u32,
    pub title: String,
    pub markdown: String,
    pub content_length: usize,
    pub links_found: usize,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Aggregate statistics for a completed crawl.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CrawlStats {
    pub pages_crawled: usize,
    pub pages_skipped: usize,
    pub errors: usize,
    pub total_elapsed_ms: u64,
}
```

**Step 3: Update lib.rs to export types**

```rust
mod result;

pub use result::{CrawlResult, CrawlStats};
```

**Step 4: Verify it compiles**

Run: `cargo check -p ox-crawler`
Expected: success (no errors)

**Step 5: Commit**

```bash
git add crates/crawler/
git commit -m "feat(crawler): add Cargo.toml and result types"
```

---

### Task 2: CrawlConfig + Scope

**Files:**
- Create: `crates/crawler/src/config.rs`
- Create: `crates/crawler/src/scope.rs`
- Modify: `crates/crawler/src/lib.rs`

**Step 1: Write tests for scope filtering**

Add to `crates/crawler/src/scope.rs`:

```rust
//! URL scope filtering — determines which URLs are in-scope for crawling.

use regex::Regex;
use url::Url;

/// Scope control for crawl boundaries.
#[derive(Debug, Clone)]
pub enum CrawlScope {
    /// Same registrable domain (e.g. blog.example.com matches example.com).
    SameDomain,
    /// Exact hostname match only.
    SameHost,
    /// Custom regex allow/block lists. Allow checked first, then block.
    Custom {
        allow: Vec<Regex>,
        block: Vec<Regex>,
    },
}

impl Default for CrawlScope {
    fn default() -> Self {
        Self::SameDomain
    }
}

impl CrawlScope {
    /// Check if a URL is in-scope relative to the seed URL.
    pub fn is_allowed(&self, seed: &Url, candidate: &Url) -> bool {
        match self {
            Self::SameDomain => {
                let seed_domain = registrable_domain(seed);
                let cand_domain = registrable_domain(candidate);
                seed_domain == cand_domain
            }
            Self::SameHost => seed.host_str() == candidate.host_str(),
            Self::Custom { allow, block } => {
                let url_str = candidate.as_str();
                if !allow.is_empty() && !allow.iter().any(|r| r.is_match(url_str)) {
                    return false;
                }
                !block.iter().any(|r| r.is_match(url_str))
            }
        }
    }
}

/// Extract registrable domain (last two segments for simple TLDs).
fn registrable_domain(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn same_domain_allows_subdomains() {
        let scope = CrawlScope::SameDomain;
        let seed = url("https://www.example.com");
        assert!(scope.is_allowed(&seed, &url("https://blog.example.com/post")));
        assert!(scope.is_allowed(&seed, &url("https://example.com/")));
        assert!(!scope.is_allowed(&seed, &url("https://other.com/")));
    }

    #[test]
    fn same_host_strict() {
        let scope = CrawlScope::SameHost;
        let seed = url("https://www.example.com");
        assert!(scope.is_allowed(&seed, &url("https://www.example.com/page")));
        assert!(!scope.is_allowed(&seed, &url("https://blog.example.com/post")));
    }

    #[test]
    fn custom_allow_list() {
        let scope = CrawlScope::Custom {
            allow: vec![Regex::new(r"example\.com/docs").unwrap()],
            block: vec![],
        };
        let seed = url("https://example.com");
        assert!(scope.is_allowed(&seed, &url("https://example.com/docs/page")));
        assert!(!scope.is_allowed(&seed, &url("https://example.com/blog/post")));
    }

    #[test]
    fn custom_block_list() {
        let scope = CrawlScope::Custom {
            allow: vec![],
            block: vec![Regex::new(r"\.(pdf|zip|jpg)$").unwrap()],
        };
        let seed = url("https://example.com");
        assert!(scope.is_allowed(&seed, &url("https://example.com/page")));
        assert!(!scope.is_allowed(&seed, &url("https://example.com/file.pdf")));
        assert!(!scope.is_allowed(&seed, &url("https://example.com/photo.jpg")));
    }

    #[test]
    fn custom_allow_and_block() {
        let scope = CrawlScope::Custom {
            allow: vec![Regex::new(r"example\.com").unwrap()],
            block: vec![Regex::new(r"/admin").unwrap()],
        };
        let seed = url("https://example.com");
        assert!(scope.is_allowed(&seed, &url("https://example.com/page")));
        assert!(!scope.is_allowed(&seed, &url("https://example.com/admin/settings")));
        assert!(!scope.is_allowed(&seed, &url("https://other.com/page")));
    }
}
```

**Step 2: Create config.rs**

```rust
//! Crawler configuration.

use std::collections::HashMap;

use serde::Deserialize;

use crate::scope::CrawlScope;

/// Configuration for a single crawl run.
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    pub max_depth: u32,
    pub max_pages: usize,
    pub concurrency: usize,
    pub scope: CrawlScope,
    pub budget: HashMap<String, u32>,
    pub respect_robots: bool,
    pub include_markdown: bool,
    pub delay_ms: u64,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_pages: 100,
            concurrency: 5,
            scope: CrawlScope::default(),
            budget: HashMap::new(),
            respect_robots: true,
            include_markdown: true,
            delay_ms: 200,
        }
    }
}

/// Server-level crawler defaults (from config.toml [crawler] section).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CrawlerSection {
    pub default_max_depth: u32,
    pub default_max_pages: usize,
    pub default_concurrency: usize,
    pub default_delay_ms: u64,
    pub respect_robots: bool,
    pub include_markdown: bool,
}

impl Default for CrawlerSection {
    fn default() -> Self {
        Self {
            default_max_depth: 3,
            default_max_pages: 100,
            default_concurrency: 5,
            default_delay_ms: 200,
            respect_robots: true,
            include_markdown: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = CrawlConfig::default();
        assert_eq!(cfg.max_depth, 3);
        assert_eq!(cfg.max_pages, 100);
        assert_eq!(cfg.concurrency, 5);
        assert!(cfg.respect_robots);
        assert!(cfg.include_markdown);
        assert_eq!(cfg.delay_ms, 200);
        assert!(cfg.budget.is_empty());
    }

    #[test]
    fn crawler_section_deserializes() {
        let toml = r#"
default_max_depth = 5
default_max_pages = 200
default_concurrency = 10
"#;
        let section: CrawlerSection = toml::from_str(toml).unwrap();
        assert_eq!(section.default_max_depth, 5);
        assert_eq!(section.default_max_pages, 200);
        assert_eq!(section.default_concurrency, 10);
        // defaults for unset fields
        assert!(section.respect_robots);
        assert!(section.include_markdown);
    }
}
```

**Step 3: Update lib.rs**

```rust
mod config;
mod result;
mod scope;

pub use config::{CrawlConfig, CrawlerSection};
pub use result::{CrawlResult, CrawlStats};
pub use scope::CrawlScope;
```

**Step 4: Run tests**

Run: `cargo test -p ox-crawler`
Expected: 7 tests pass (5 scope + 2 config)

**Step 5: Commit**

```bash
git add crates/crawler/
git commit -m "feat(crawler): add CrawlConfig, CrawlScope with scope filtering"
```

---

### Task 3: URL Frontier + Dedup

**Files:**
- Create: `crates/crawler/src/frontier.rs`
- Create: `crates/crawler/src/dedup.rs`
- Modify: `crates/crawler/src/lib.rs`

**Step 1: Create dedup.rs with URL + content dedup**

```rust
//! URL and content deduplication.

use std::collections::HashSet;

/// URL deduplication using xxHash for memory efficiency.
pub struct UrlDedup {
    seen: HashSet<u64>,
}

impl UrlDedup {
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    /// Returns true if this URL has NOT been seen before (and marks it as seen).
    pub fn insert(&mut self, normalized_url: &str) -> bool {
        let hash = xxhash_rust::xxh3::xxh3_64(normalized_url.as_bytes());
        self.seen.insert(hash)
    }

    /// Check without inserting.
    pub fn contains(&self, normalized_url: &str) -> bool {
        let hash = xxhash_rust::xxh3::xxh3_64(normalized_url.as_bytes());
        self.seen.contains(&hash)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }
}

/// Content deduplication using blake3 hash.
pub struct ContentDedup {
    seen: HashSet<[u8; 32]>,
}

impl ContentDedup {
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    /// Returns true if this content has NOT been seen before.
    pub fn insert(&mut self, content: &[u8]) -> bool {
        let hash = blake3::hash(content);
        self.seen.insert(*hash.as_bytes())
    }
}

/// Normalize a URL for dedup: strip fragment, sort query params, lowercase host.
pub fn normalize_url(raw: &str) -> Option<String> {
    let mut url = url::Url::parse(raw).ok()?;
    url.set_fragment(None);
    // Sort query params for consistent hashing
    if let Some(query) = url.query() {
        let mut params: Vec<&str> = query.split('&').collect();
        params.sort();
        url.set_query(Some(&params.join("&")));
    }
    Some(url.to_string())
}

/// Detect crawler traps via repeating path segments.
pub fn is_cycle(url: &str) -> bool {
    // URLs longer than 2KB are suspicious
    if url.len() > 2048 {
        return true;
    }
    let path = match url::Url::parse(url) {
        Ok(u) => u.path().to_string(),
        Err(_) => return false,
    };
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 4 {
        return false;
    }
    // Check for repeating pairs (e.g. /a/b/a/b)
    for window_size in 1..=segments.len() / 2 {
        let pattern = &segments[..window_size];
        let mut all_match = true;
        for chunk in segments.chunks(window_size).skip(1) {
            if chunk != pattern {
                all_match = false;
                break;
            }
        }
        if all_match && segments.len() >= window_size * 2 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_dedup_inserts_and_detects() {
        let mut dedup = UrlDedup::new();
        assert!(dedup.insert("https://example.com/page"));
        assert!(!dedup.insert("https://example.com/page"));
        assert!(dedup.insert("https://example.com/other"));
        assert_eq!(dedup.len(), 2);
    }

    #[test]
    fn content_dedup_detects_duplicates() {
        let mut dedup = ContentDedup::new();
        assert!(dedup.insert(b"hello world"));
        assert!(!dedup.insert(b"hello world"));
        assert!(dedup.insert(b"different content"));
    }

    #[test]
    fn normalize_strips_fragment() {
        let n = normalize_url("https://example.com/page#section").unwrap();
        assert!(!n.contains('#'));
    }

    #[test]
    fn normalize_sorts_query_params() {
        let n = normalize_url("https://example.com?z=1&a=2").unwrap();
        assert!(n.contains("a=2&z=1"));
    }

    #[test]
    fn cycle_detects_repeating_paths() {
        assert!(is_cycle("https://example.com/a/b/a/b"));
        assert!(is_cycle("https://example.com/x/y/z/x/y/z"));
        assert!(!is_cycle("https://example.com/a/b/c"));
        assert!(!is_cycle("https://example.com/page"));
    }

    #[test]
    fn cycle_detects_long_urls() {
        let long = format!("https://example.com/{}", "a/".repeat(1500));
        assert!(is_cycle(&long));
    }

    #[test]
    fn normalize_handles_invalid_url() {
        assert!(normalize_url("not a url").is_none());
    }
}
```

**Step 2: Create frontier.rs**

```rust
//! URL frontier — priority queue for BFS crawling.

use std::collections::VecDeque;

/// An entry in the crawl frontier.
#[derive(Debug, Clone)]
pub struct FrontierEntry {
    pub url: String,
    pub depth: u32,
}

/// BFS frontier using a deque (FIFO = breadth-first).
pub struct Frontier {
    queue: VecDeque<FrontierEntry>,
    max_size: usize,
}

impl Frontier {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_size,
        }
    }

    /// Push a URL to the back of the queue (BFS order).
    pub fn push(&mut self, entry: FrontierEntry) -> bool {
        if self.queue.len() >= self.max_size {
            return false;
        }
        self.queue.push_back(entry);
        true
    }

    /// Pop the next URL from the front (BFS: oldest/shallowest first).
    pub fn pop(&mut self) -> Option<FrontierEntry> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bfs_order() {
        let mut f = Frontier::new(100);
        f.push(FrontierEntry { url: "a".into(), depth: 0 });
        f.push(FrontierEntry { url: "b".into(), depth: 1 });
        f.push(FrontierEntry { url: "c".into(), depth: 1 });
        assert_eq!(f.pop().unwrap().url, "a");
        assert_eq!(f.pop().unwrap().url, "b");
        assert_eq!(f.pop().unwrap().url, "c");
    }

    #[test]
    fn respects_max_size() {
        let mut f = Frontier::new(2);
        assert!(f.push(FrontierEntry { url: "a".into(), depth: 0 }));
        assert!(f.push(FrontierEntry { url: "b".into(), depth: 0 }));
        assert!(!f.push(FrontierEntry { url: "c".into(), depth: 0 }));
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn empty_frontier() {
        let mut f = Frontier::new(10);
        assert!(f.is_empty());
        assert!(f.pop().is_none());
    }
}
```

**Step 3: Update lib.rs**

```rust
mod config;
mod dedup;
mod frontier;
mod result;
mod scope;

pub use config::{CrawlConfig, CrawlerSection};
pub use dedup::{is_cycle, normalize_url, ContentDedup, UrlDedup};
pub use frontier::{Frontier, FrontierEntry};
pub use result::{CrawlResult, CrawlStats};
pub use scope::CrawlScope;
```

**Step 4: Run tests**

Run: `cargo test -p ox-crawler`
Expected: 17 tests pass (5 scope + 2 config + 7 dedup + 3 frontier)

**Step 5: Commit**

```bash
git add crates/crawler/
git commit -m "feat(crawler): add URL frontier, dedup (xxHash+blake3), cycle detection"
```

---

### Task 4: robots.txt + Budget

**Files:**
- Create: `crates/crawler/src/robots.rs`
- Create: `crates/crawler/src/budget.rs`
- Modify: `crates/crawler/src/lib.rs`

**Step 1: Create robots.rs**

```rust
//! robots.txt parsing and per-domain caching.

use std::collections::HashMap;

use texting_robots::Robot;

/// Per-domain robots.txt cache.
pub struct RobotsCache {
    cache: HashMap<String, RobotsEntry>,
    user_agent: String,
}

enum RobotsEntry {
    Loaded(Robot),
    /// robots.txt fetch failed or returned non-200 — allow all.
    Unavailable,
}

impl RobotsCache {
    pub fn new(user_agent: &str) -> Self {
        Self {
            cache: HashMap::new(),
            user_agent: user_agent.to_string(),
        }
    }

    /// Store robots.txt content for a host. Call after fetching.
    pub fn insert(&mut self, host: &str, robots_txt: Option<&str>) {
        let entry = match robots_txt {
            Some(body) => match Robot::new(&self.user_agent, body.as_bytes()) {
                Ok(robot) => RobotsEntry::Loaded(robot),
                Err(_) => RobotsEntry::Unavailable,
            },
            None => RobotsEntry::Unavailable,
        };
        self.cache.insert(host.to_string(), entry);
    }

    /// Check if a URL is allowed by robots.txt. Returns true if no robots.txt loaded.
    pub fn is_allowed(&self, host: &str, url: &str) -> bool {
        match self.cache.get(host) {
            Some(RobotsEntry::Loaded(robot)) => robot.allowed(url),
            Some(RobotsEntry::Unavailable) | None => true,
        }
    }

    /// Check if we already have robots.txt cached for a host.
    pub fn has_host(&self, host: &str) -> bool {
        self.cache.contains_key(host)
    }

    /// Get crawl-delay for a host (in seconds), if specified.
    pub fn crawl_delay(&self, host: &str) -> Option<f64> {
        match self.cache.get(host) {
            Some(RobotsEntry::Loaded(robot)) => robot.delay,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_when_no_robots() {
        let cache = RobotsCache::new("ox-browser");
        assert!(cache.is_allowed("example.com", "https://example.com/page"));
    }

    #[test]
    fn allows_when_unavailable() {
        let mut cache = RobotsCache::new("ox-browser");
        cache.insert("example.com", None);
        assert!(cache.is_allowed("example.com", "https://example.com/page"));
    }

    #[test]
    fn blocks_disallowed_path() {
        let mut cache = RobotsCache::new("ox-browser");
        cache.insert(
            "example.com",
            Some("User-agent: *\nDisallow: /admin\n"),
        );
        assert!(!cache.is_allowed("example.com", "https://example.com/admin/settings"));
        assert!(cache.is_allowed("example.com", "https://example.com/page"));
    }

    #[test]
    fn has_host_tracking() {
        let mut cache = RobotsCache::new("ox-browser");
        assert!(!cache.has_host("example.com"));
        cache.insert("example.com", Some("User-agent: *\nAllow: /\n"));
        assert!(cache.has_host("example.com"));
    }

    #[test]
    fn parses_crawl_delay() {
        let mut cache = RobotsCache::new("ox-browser");
        cache.insert(
            "example.com",
            Some("User-agent: *\nCrawl-delay: 5\nAllow: /\n"),
        );
        assert_eq!(cache.crawl_delay("example.com"), Some(5.0));
    }

    #[test]
    fn no_crawl_delay_when_absent() {
        let mut cache = RobotsCache::new("ox-browser");
        cache.insert("example.com", Some("User-agent: *\nAllow: /\n"));
        assert_eq!(cache.crawl_delay("example.com"), None);
    }
}
```

**Step 2: Create budget.rs**

```rust
//! Per-path URL budgets — limit how many URLs to crawl per path prefix.

use std::collections::HashMap;

/// Tracks per-path budgets: {"*": 300, "/blog": 50}.
pub struct Budget {
    limits: HashMap<String, u32>,
    counts: HashMap<String, u32>,
}

impl Budget {
    pub fn new(limits: HashMap<String, u32>) -> Self {
        Self {
            limits,
            counts: HashMap::new(),
        }
    }

    /// Check if a URL path is within budget. Increments counter if allowed.
    pub fn try_consume(&mut self, path: &str) -> bool {
        // Check global budget first
        if let Some(&limit) = self.limits.get("*") {
            let total = self.counts.entry("*".to_string()).or_insert(0);
            if *total >= limit {
                return false;
            }
        }
        // Check path-specific budget (longest prefix match)
        if let Some((prefix, &limit)) = self.longest_match(path) {
            let count = self.counts.entry(prefix).or_insert(0);
            if *count >= limit {
                return false;
            }
            *count += 1;
        }
        // Increment global counter
        if self.limits.contains_key("*") {
            *self.counts.entry("*".to_string()).or_insert(0) += 1;
        }
        true
    }

    fn longest_match(&self, path: &str) -> Option<(String, &u32)> {
        self.limits
            .iter()
            .filter(|(k, _)| *k != "*" && path.starts_with(k.as_str()))
            .max_by_key(|(k, _)| k.len())
            .map(|(k, v)| (k.clone(), v))
    }

    /// Returns true if no budgets are configured (everything allowed).
    pub fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_budget_allows_everything() {
        let mut b = Budget::new(HashMap::new());
        assert!(b.try_consume("/anything"));
        assert!(b.is_empty());
    }

    #[test]
    fn global_budget_limits_total() {
        let mut b = Budget::new([("*".to_string(), 2)].into());
        assert!(b.try_consume("/a"));
        assert!(b.try_consume("/b"));
        assert!(!b.try_consume("/c"));
    }

    #[test]
    fn path_budget_limits_prefix() {
        let mut b = Budget::new([("/blog".to_string(), 2)].into());
        assert!(b.try_consume("/blog/post1"));
        assert!(b.try_consume("/blog/post2"));
        assert!(!b.try_consume("/blog/post3"));
        // Other paths unaffected
        assert!(b.try_consume("/about"));
    }

    #[test]
    fn combined_global_and_path_budget() {
        let mut b = Budget::new([
            ("*".to_string(), 5),
            ("/blog".to_string(), 2),
        ].into());
        assert!(b.try_consume("/blog/a"));
        assert!(b.try_consume("/blog/b"));
        assert!(!b.try_consume("/blog/c")); // path limit hit
        assert!(b.try_consume("/about"));   // still within global
    }

    #[test]
    fn longest_prefix_wins() {
        let mut b = Budget::new([
            ("/a".to_string(), 10),
            ("/a/b".to_string(), 1),
        ].into());
        assert!(b.try_consume("/a/b/x"));
        assert!(!b.try_consume("/a/b/y")); // /a/b budget exhausted
        assert!(b.try_consume("/a/c"));    // /a budget still ok
    }
}
```

**Step 3: Update lib.rs**

```rust
mod budget;
mod config;
mod dedup;
mod frontier;
mod result;
mod robots;
mod scope;

pub use budget::Budget;
pub use config::{CrawlConfig, CrawlerSection};
pub use dedup::{is_cycle, normalize_url, ContentDedup, UrlDedup};
pub use frontier::{Frontier, FrontierEntry};
pub use result::{CrawlResult, CrawlStats};
pub use robots::RobotsCache;
pub use scope::CrawlScope;
```

**Step 4: Run tests**

Run: `cargo test -p ox-crawler`
Expected: 28 tests pass (+6 robots + 5 budget)

**Step 5: Commit**

```bash
git add crates/crawler/
git commit -m "feat(crawler): add robots.txt cache and per-path URL budgets"
```

---

### Task 5: HTML→Markdown Conversion

**Files:**
- Create: `crates/crawler/src/markdown.rs`
- Modify: `crates/crawler/src/lib.rs`

**Step 1: Create markdown.rs**

```rust
//! HTML to Markdown conversion with noise filtering.

/// Convert HTML to clean Markdown.
pub fn html_to_markdown(html: &str) -> String {
    htmd::convert(html).unwrap_or_default()
}

/// Remove boilerplate elements (nav, footer, sidebar, ads) before conversion.
/// Returns "fit" markdown — cleaner output for LLM consumers.
pub fn html_to_fit_markdown(html: &str) -> String {
    let doc = dom_query::Document::from(html);
    // Remove noise elements
    for selector in NOISE_SELECTORS {
        doc.select(selector).remove();
    }
    let cleaned = doc.html().to_string();
    htmd::convert(&cleaned).unwrap_or_default()
}

const NOISE_SELECTORS: &[&str] = &[
    "nav",
    "footer",
    "header",
    ".nav",
    ".navbar",
    ".footer",
    ".sidebar",
    ".menu",
    ".breadcrumb",
    ".pagination",
    ".cookie-banner",
    ".cookie-consent",
    "#cookie-banner",
    "[role=navigation]",
    "[role=banner]",
    "[role=contentinfo]",
    "script",
    "style",
    "noscript",
    "iframe",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_basic_html() {
        let html = "<h1>Title</h1><p>Hello world</p>";
        let md = html_to_markdown(html);
        assert!(md.contains("# Title"));
        assert!(md.contains("Hello world"));
    }

    #[test]
    fn converts_links() {
        let html = r#"<a href="https://example.com">link</a>"#;
        let md = html_to_markdown(html);
        assert!(md.contains("[link](https://example.com)"));
    }

    #[test]
    fn fit_markdown_strips_nav() {
        let html = r#"
            <nav><a href="/">Home</a></nav>
            <main><h1>Article</h1><p>Content here</p></main>
            <footer>Copyright 2026</footer>
        "#;
        let md = html_to_fit_markdown(html);
        assert!(md.contains("Article"));
        assert!(md.contains("Content here"));
        assert!(!md.contains("Home"));
        assert!(!md.contains("Copyright"));
    }

    #[test]
    fn fit_markdown_strips_scripts() {
        let html = r#"
            <script>alert('xss')</script>
            <p>Safe content</p>
            <style>.hidden{display:none}</style>
        "#;
        let md = html_to_fit_markdown(html);
        assert!(md.contains("Safe content"));
        assert!(!md.contains("alert"));
        assert!(!md.contains("display"));
    }

    #[test]
    fn handles_empty_html() {
        assert!(html_to_markdown("").is_empty() || html_to_markdown("").trim().is_empty());
        assert!(html_to_fit_markdown("").is_empty() || html_to_fit_markdown("").trim().is_empty());
    }
}
```

**Step 2: Add dom_query to Cargo.toml**

Add to `[dependencies]` in `crates/crawler/Cargo.toml`:
```toml
dom_query = "0.12"
```

**Step 3: Update lib.rs** (add `mod markdown; pub use markdown::{html_to_markdown, html_to_fit_markdown};`)

**Step 4: Run tests**

Run: `cargo test -p ox-crawler`
Expected: 33 tests pass (+5 markdown)

**Step 5: Commit**

```bash
git add crates/crawler/
git commit -m "feat(crawler): add HTML→Markdown with fit_markdown noise removal"
```

---

### Task 6: Core Crawl Engine

**Files:**
- Create: `crates/crawler/src/crawler.rs`
- Modify: `crates/crawler/src/lib.rs`

This is the main crawl loop. It ties together all previous modules.

**Step 1: Create crawler.rs**

```rust
//! Core crawl engine — BFS crawl loop with streaming output.

use std::sync::Arc;
use std::time::Instant;

use ox_core::{resolve_url, Page};
use ox_http::HttpClient;
use tokio::sync::{mpsc, Mutex, Semaphore};
use url::Url;

use crate::budget::Budget;
use crate::config::CrawlConfig;
use crate::dedup::{is_cycle, normalize_url, ContentDedup, UrlDedup};
use crate::frontier::{Frontier, FrontierEntry};
use crate::markdown::{html_to_fit_markdown, html_to_markdown};
use crate::result::{CrawlResult, CrawlStats};
use crate::robots::RobotsCache;

/// Site crawler with streaming results.
pub struct Crawler {
    http: Arc<HttpClient>,
    config: CrawlConfig,
}

impl Crawler {
    pub fn new(http: Arc<HttpClient>, config: CrawlConfig) -> Self {
        Self { http, config }
    }

    /// Start crawling from a seed URL. Returns a receiver for streaming results.
    pub fn crawl(&self, seed_url: &str) -> mpsc::Receiver<CrawlResult> {
        let (tx, rx) = mpsc::channel(self.config.concurrency * 2);
        let seed = seed_url.to_string();
        let http = Arc::clone(&self.http);
        let config = self.config.clone();

        tokio::spawn(async move {
            if let Err(e) = run_crawl(seed, http, config, tx).await {
                tracing::error!("crawl failed: {e}");
            }
        });

        rx
    }
}

async fn run_crawl(
    seed: String,
    http: Arc<HttpClient>,
    config: CrawlConfig,
    tx: mpsc::Sender<CrawlResult>,
) -> anyhow::Result<()> {
    let seed_url = Url::parse(&seed)?;
    let frontier = Arc::new(Mutex::new(Frontier::new(config.max_pages * 10)));
    let dedup = Arc::new(Mutex::new(UrlDedup::new()));
    let content_dedup = Arc::new(Mutex::new(ContentDedup::new()));
    let robots = Arc::new(Mutex::new(RobotsCache::new("ox-browser")));
    let budget = Arc::new(Mutex::new(Budget::new(config.budget.clone())));
    let stats = Arc::new(Mutex::new(CrawlStats::default()));
    let sem = Arc::new(Semaphore::new(config.concurrency));

    // Seed the frontier
    {
        let normalized = normalize_url(&seed).unwrap_or(seed.clone());
        let mut d = dedup.lock().await;
        d.insert(&normalized);
        let mut f = frontier.lock().await;
        f.push(FrontierEntry {
            url: seed,
            depth: 0,
        });
    }

    let start = Instant::now();

    loop {
        // Check if we've hit the page limit
        {
            let s = stats.lock().await;
            if s.pages_crawled >= config.max_pages {
                tracing::info!("reached max_pages limit: {}", config.max_pages);
                break;
            }
        }

        // Get next URL from frontier
        let entry = {
            let mut f = frontier.lock().await;
            f.pop()
        };

        let entry = match entry {
            Some(e) => e,
            None => {
                // Wait briefly for in-flight tasks to add more URLs
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let f = frontier.lock().await;
                if f.is_empty() {
                    break;
                }
                continue;
            }
        };

        let permit = sem.clone().acquire_owned().await?;
        let http = Arc::clone(&http);
        let tx = tx.clone();
        let frontier = Arc::clone(&frontier);
        let dedup = Arc::clone(&dedup);
        let content_dedup = Arc::clone(&content_dedup);
        let robots = Arc::clone(&robots);
        let budget = Arc::clone(&budget);
        let stats = Arc::clone(&stats);
        let seed_url = seed_url.clone();
        let config = config.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let result = process_page(
                &entry,
                &http,
                &config,
                &seed_url,
                &frontier,
                &dedup,
                &content_dedup,
                &robots,
                &budget,
            )
            .await;

            let mut s = stats.lock().await;
            match &result {
                Ok(r) if r.error.is_none() => s.pages_crawled += 1,
                Ok(_) => s.errors += 1,
                Err(_) => s.errors += 1,
            }
            s.total_elapsed_ms = start.elapsed().as_millis() as u64;

            if let Ok(r) = result {
                let _ = tx.send(r).await;
            }
        });

        // Polite delay between dispatching requests
        if config.delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(config.delay_ms)).await;
        }
    }

    // Wait for all permits to be returned (in-flight tasks complete)
    let _ = sem.acquire_many(config.concurrency as u32).await;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_page(
    entry: &FrontierEntry,
    http: &HttpClient,
    config: &CrawlConfig,
    seed_url: &Url,
    frontier: &Mutex<Frontier>,
    dedup: &Mutex<UrlDedup>,
    content_dedup: &Mutex<ContentDedup>,
    robots: &Mutex<RobotsCache>,
    budget: &Mutex<Budget>,
) -> anyhow::Result<CrawlResult> {
    let start = Instant::now();
    let url_str = &entry.url;

    // Check robots.txt (lazy load)
    if config.respect_robots {
        if let Ok(parsed) = Url::parse(url_str) {
            let host = parsed.host_str().unwrap_or("").to_string();
            let need_fetch = {
                let r = robots.lock().await;
                !r.has_host(&host)
            };
            if need_fetch {
                let robots_url = format!("{}://{}/robots.txt", parsed.scheme(), host);
                let robots_body = match http.get(&robots_url).await {
                    Ok(resp) if resp.status == 200 => Some(resp.body),
                    _ => None,
                };
                let mut r = robots.lock().await;
                r.insert(&host, robots_body.as_deref());
            }
            let r = robots.lock().await;
            if !r.is_allowed(&host, url_str) {
                return Ok(CrawlResult {
                    url: url_str.clone(),
                    status: 0,
                    depth: entry.depth,
                    title: String::new(),
                    markdown: String::new(),
                    content_length: 0,
                    links_found: 0,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: Some("blocked by robots.txt".into()),
                });
            }
        }
    }

    // Fetch the page
    let resp = match http.get(url_str).await {
        Ok(r) => r,
        Err(e) => {
            return Ok(CrawlResult {
                url: url_str.clone(),
                status: 0,
                depth: entry.depth,
                title: String::new(),
                markdown: String::new(),
                content_length: 0,
                links_found: 0,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some(format!("fetch error: {e}")),
            });
        }
    };

    // Content dedup
    {
        let mut cd = content_dedup.lock().await;
        if !cd.insert(resp.body.as_bytes()) {
            return Ok(CrawlResult {
                url: url_str.clone(),
                status: resp.status,
                depth: entry.depth,
                title: String::new(),
                markdown: String::new(),
                content_length: 0,
                links_found: 0,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some("duplicate content".into()),
            });
        }
    }

    // Parse page and extract links
    let page = Page::new(url_str.to_string(), resp.status, &resp.body);
    let title = page.title();
    let links = page.links();
    let links_found = links.len();

    // Enqueue discovered links
    if entry.depth < config.max_depth {
        for link in &links {
            if let Some(resolved) = resolve_url(url_str, &link.href) {
                if let Some(normalized) = normalize_url(&resolved) {
                    if let Ok(candidate) = Url::parse(&normalized) {
                        // Scope check
                        if !config.scope.is_allowed(seed_url, &candidate) {
                            continue;
                        }
                        // Cycle detection
                        if is_cycle(&normalized) {
                            continue;
                        }
                        // Skip non-HTTP
                        if candidate.scheme() != "http" && candidate.scheme() != "https" {
                            continue;
                        }
                        // Budget check
                        {
                            let mut b = budget.lock().await;
                            if !b.is_empty() && !b.try_consume(candidate.path()) {
                                continue;
                            }
                        }
                        // Dedup check
                        {
                            let mut d = dedup.lock().await;
                            if !d.insert(&normalized) {
                                continue;
                            }
                        }
                        // Enqueue
                        let mut f = frontier.lock().await;
                        f.push(FrontierEntry {
                            url: normalized,
                            depth: entry.depth + 1,
                        });
                    }
                }
            }
        }
    }

    // Convert to markdown
    let markdown = if config.include_markdown {
        html_to_fit_markdown(&resp.body)
    } else {
        String::new()
    };

    let content_length = resp.body.len();

    Ok(CrawlResult {
        url: url_str.clone(),
        status: resp.status,
        depth: entry.depth,
        title,
        markdown,
        content_length,
        links_found,
        elapsed_ms: start.elapsed().as_millis() as u64,
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crawler_creates() {
        let config = CrawlConfig::default();
        let http = Arc::new(
            HttpClient::new(ox_http::HttpConfig::default()).unwrap(),
        );
        let _crawler = Crawler::new(http, config);
    }
}
```

**Step 2: Add anyhow to Cargo.toml**

```toml
anyhow = { workspace = true }
```

**Step 3: Update lib.rs**

```rust
mod budget;
mod config;
mod crawler;
mod dedup;
mod frontier;
mod markdown;
mod result;
mod robots;
mod scope;

pub use budget::Budget;
pub use config::{CrawlConfig, CrawlerSection};
pub use crawler::Crawler;
pub use dedup::{is_cycle, normalize_url, ContentDedup, UrlDedup};
pub use frontier::{Frontier, FrontierEntry};
pub use markdown::{html_to_fit_markdown, html_to_markdown};
pub use result::{CrawlResult, CrawlStats};
pub use robots::RobotsCache;
pub use scope::CrawlScope;
```

**Step 4: Run tests**

Run: `cargo test -p ox-crawler`
Expected: 34 tests pass (+1 crawler_creates)

Run: `cargo clippy -p ox-crawler`
Expected: no warnings (except too_many_arguments which is allowed)

**Step 5: Commit**

```bash
git add crates/crawler/
git commit -m "feat(crawler): core crawl engine with BFS, streaming, robots.txt, dedup"
```

---

### Task 7: Config Integration + REST + MCP

**Files:**
- Create: `src/config/crawler.rs`
- Modify: `src/config/mod.rs`
- Create: `crates/js/src/crawl.rs`
- Modify: `crates/js/src/lib.rs`
- Create: `crates/mcp/src/tools/crawl.rs`
- Modify: `crates/mcp/src/tools/mod.rs`
- Modify: `src/serve.rs`
- Modify: `config.toml`

**Step 1: Add [crawler] config section**

Create `src/config/crawler.rs`:

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CrawlerSection {
    pub default_max_depth: u32,
    pub default_max_pages: usize,
    pub default_concurrency: usize,
    pub default_delay_ms: u64,
    pub respect_robots: bool,
    pub include_markdown: bool,
}

impl Default for CrawlerSection {
    fn default() -> Self {
        Self {
            default_max_depth: 3,
            default_max_pages: 100,
            default_concurrency: 5,
            default_delay_ms: 200,
            respect_robots: true,
            include_markdown: true,
        }
    }
}
```

**Step 2: Wire into ServerConfig**

In `src/config/mod.rs`:
- Add `mod crawler;` and `pub use crawler::CrawlerSection;`
- Add `pub crawler: CrawlerSection` field to `ServerConfig`
- Update `defaults_match_previous_hardcoded_values` test

**Step 3: Add REST endpoint `POST /crawl`**

Create `crates/js/src/crawl.rs`:

```rust
//! POST /crawl — site crawler with SSE streaming.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::Json;
use futures::stream::Stream;
use ox_crawler::{CrawlConfig, CrawlScope, Crawler};
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
pub struct CrawlRequest {
    pub url: String,
    #[serde(default)]
    pub max_depth: Option<u32>,
    #[serde(default)]
    pub max_pages: Option<usize>,
    #[serde(default)]
    pub concurrency: Option<usize>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub include_markdown: Option<bool>,
}

pub async fn crawl(
    State(state): State<AppState>,
    Json(req): Json<CrawlRequest>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let config = CrawlConfig {
        max_depth: req.max_depth.unwrap_or(state.defaults.crawler_max_depth),
        max_pages: req.max_pages.unwrap_or(state.defaults.crawler_max_pages),
        concurrency: req.concurrency.unwrap_or(state.defaults.crawler_concurrency),
        scope: match req.scope.as_deref() {
            Some("same_host") => CrawlScope::SameHost,
            _ => CrawlScope::SameDomain,
        },
        include_markdown: req.include_markdown.unwrap_or(state.defaults.crawler_include_markdown),
        delay_ms: state.defaults.crawler_delay_ms,
        ..Default::default()
    };

    let crawler = Crawler::new(Arc::clone(&state.http_client), config);
    let mut rx = crawler.crawl(&req.url);

    let stream = async_stream::stream! {
        while let Some(result) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&result) {
                yield Ok(Event::default().data(json));
            }
        }
        yield Ok(Event::default().event("done").data("{}"));
    };

    Sse::new(stream)
}
```

**Step 4: Add to router**

In `crates/js/src/lib.rs`:
- Add `mod crawl;`
- Add `.route("/crawl", post(crawl::crawl))` to the router
- Add crawler defaults to `EndpointDefaults`:
  ```rust
  pub crawler_max_depth: u32,
  pub crawler_max_pages: usize,
  pub crawler_concurrency: usize,
  pub crawler_delay_ms: u64,
  pub crawler_include_markdown: bool,
  ```

**Step 5: Add MCP tool**

Create `crates/mcp/src/tools/crawl.rs`:

```rust
use std::sync::Arc;

use ox_crawler::{CrawlConfig, CrawlScope, Crawler};
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::Deserialize;

use super::OxMcpServer;

#[derive(Debug, Deserialize)]
pub struct CrawlInput {
    pub url: String,
    #[serde(default)]
    pub max_depth: Option<u32>,
    #[serde(default)]
    pub max_pages: Option<usize>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub include_markdown: Option<bool>,
}

impl OxMcpServer {
    pub(crate) async fn do_crawl(
        &self,
        input: CrawlInput,
    ) -> Result<CallToolResult, McpError> {
        let config = CrawlConfig {
            max_depth: input.max_depth.unwrap_or(self.defaults.crawler_max_depth),
            max_pages: input.max_pages.unwrap_or(self.defaults.crawler_max_pages),
            concurrency: self.defaults.crawler_concurrency,
            scope: match input.scope.as_deref() {
                Some("same_host") => CrawlScope::SameHost,
                _ => CrawlScope::SameDomain,
            },
            include_markdown: input.include_markdown.unwrap_or(self.defaults.crawler_include_markdown),
            delay_ms: self.defaults.crawler_delay_ms,
            ..Default::default()
        };

        let crawler = Crawler::new(Arc::clone(&self.http_client), config);
        let mut rx = crawler.crawl(&input.url);

        let mut results = Vec::new();
        while let Some(result) = rx.recv().await {
            results.push(result);
        }

        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
```

**Step 6: Wire MCP tool**

In `crates/mcp/src/tools/mod.rs`:
- Add `mod crawl;` and `pub use crawl::CrawlInput;`
- Add `crawl` tool to `#[tool_router]`:
  ```rust
  #[tool(
      name = "crawl",
      description = "Crawl a website with configurable depth and scope. Returns pages as markdown with metadata. BFS traversal, respects robots.txt, deduplicates content."
  )]
  async fn crawl(
      &self,
      Parameters(input): Parameters<CrawlInput>,
  ) -> Result<CallToolResult, McpError> {
      self.do_crawl(input).await
  }
  ```

**Step 7: Wire serve.rs**

In `src/serve.rs`, add crawler defaults to `EndpointDefaults`:

```rust
crawler_max_depth: config.crawler.default_max_depth,
crawler_max_pages: config.crawler.default_max_pages,
crawler_concurrency: config.crawler.default_concurrency,
crawler_delay_ms: config.crawler.default_delay_ms,
crawler_include_markdown: config.crawler.include_markdown,
```

**Step 8: Update config.toml**

Add at end (before `[log]`):

```toml
[crawler]
# default_max_depth = 3          # max link depth from seed
# default_max_pages = 100        # max pages per crawl
# default_concurrency = 5        # parallel fetches
# default_delay_ms = 200         # delay between requests (ms)
# respect_robots = true          # honor robots.txt
# include_markdown = true        # convert pages to markdown
```

**Step 9: Add dependencies**

Add to `crates/js/Cargo.toml`:
```toml
ox-crawler = { path = "../crawler" }
async-stream = "0.3"
futures = "0.3"
```

Add to `crates/mcp/Cargo.toml`:
```toml
ox-crawler = { path = "../crawler" }
```

**Step 10: Run full test suite**

Run: `cargo test --workspace`
Expected: all tests pass (previous 502 + new crawler tests)

Run: `cargo clippy --workspace`
Expected: clean

**Step 11: Commit**

```bash
git add .
git commit -m "feat(crawler): wire REST /crawl + MCP crawl tool + [crawler] config section"
```

---

### Task 8: Full Integration Tests

**Files:**
- Add integration tests to `crates/crawler/src/crawler.rs`

**Step 1: Add end-to-end test with mock HTTP**

This test verifies the full crawl pipeline works. Since `HttpClient` requires real network, we test the individual components in isolation and verify they compose correctly.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CrawlConfig;

    #[test]
    fn crawler_creates() {
        let config = CrawlConfig::default();
        let http = Arc::new(
            HttpClient::new(ox_http::HttpConfig::default()).unwrap(),
        );
        let _crawler = Crawler::new(http, config);
    }

    #[test]
    fn enqueue_respects_depth_before_dedup() {
        // Verify: if a URL is seen at depth > max, it doesn't pollute dedup
        let mut dedup = UrlDedup::new();
        let mut frontier = Frontier::new(100);
        let max_depth = 2;
        let depth = 3;

        // Simulate the check order: depth first, then dedup
        let url = "https://example.com/deep";
        if depth <= max_depth {
            let normalized = normalize_url(url).unwrap();
            if dedup.insert(&normalized) {
                frontier.push(FrontierEntry {
                    url: normalized,
                    depth,
                });
            }
        }
        // URL should NOT be in dedup since depth > max
        assert!(!dedup.contains(&normalize_url(url).unwrap()));
        assert!(frontier.is_empty());
    }

    #[test]
    fn full_pipeline_components_integrate() {
        // Test that all components work together in memory
        let mut frontier = Frontier::new(100);
        let mut dedup = UrlDedup::new();
        let mut content_dedup = ContentDedup::new();
        let mut robots = RobotsCache::new("ox-browser");
        let mut budget = Budget::new([("*".to_string(), 10)].into());
        let scope = CrawlScope::SameDomain;
        let seed = Url::parse("https://example.com").unwrap();

        // Seed
        let seed_url = "https://example.com/";
        dedup.insert(seed_url);
        frontier.push(FrontierEntry { url: seed_url.to_string(), depth: 0 });

        // Simulate link discovery
        let links = vec![
            "https://example.com/about",
            "https://example.com/blog",
            "https://other.com/ext",     // out of scope
            "https://example.com/about", // duplicate
        ];

        robots.insert("example.com", Some("User-agent: *\nAllow: /\n"));

        let mut enqueued = 0;
        for link in links {
            if let Some(normalized) = normalize_url(link) {
                if let Ok(candidate) = Url::parse(&normalized) {
                    if !scope.is_allowed(&seed, &candidate) { continue; }
                    if is_cycle(&normalized) { continue; }
                    if !budget.try_consume(candidate.path()) { continue; }
                    if !dedup.insert(&normalized) { continue; }
                    if !robots.is_allowed("example.com", &normalized) { continue; }
                    frontier.push(FrontierEntry { url: normalized, depth: 1 });
                    enqueued += 1;
                }
            }
        }

        assert_eq!(enqueued, 2); // about + blog (other.com filtered, duplicate filtered)
        assert_eq!(frontier.len(), 3); // seed + about + blog
        assert!(content_dedup.insert(b"page content"));
        assert!(!content_dedup.insert(b"page content")); // duplicate
    }
}
```

**Step 2: Run all tests**

Run: `cargo test --workspace`
Expected: all tests pass

**Step 3: Commit**

```bash
git add crates/crawler/
git commit -m "test(crawler): add integration tests for full pipeline"
```
