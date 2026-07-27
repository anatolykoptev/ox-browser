# Sitemap Crawl Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add sitemap-based URL discovery to ox-browser crawler with three modes (bfs/sitemap/hybrid), priority frontier, and file output.

**Architecture:** New `sitemap.rs` parser (quick-xml streaming) feeds URLs into upgraded priority `Frontier` (BinaryHeap). `discovery.rs` coordinates mode selection. REST/MCP endpoints get new parameters. Output optionally saves to files.

**Tech Stack:** Rust, quick-xml 0.37, existing ox-crawler/ox-http/ox-core crates.

**Design doc:** `docs/plans/2026-03-08-sitemap-crawl-design.md`

---

### Task 1: Add quick-xml dependency + sitemap types

**Files:**
- Modify: `crates/crawler/Cargo.toml`
- Create: `crates/crawler/src/sitemap.rs`
- Modify: `crates/crawler/src/lib.rs`

**Step 1: Add quick-xml to Cargo.toml**

Add under `[dependencies]`:
```toml
quick-xml = { version = "0.37", features = ["serialize"] }
```

**Step 2: Create sitemap.rs with types and empty parse function**

```rust
//! Sitemap XML parser and auto-discovery.

use anyhow::Result;

/// A single URL entry from a sitemap urlset.
#[derive(Debug, Clone)]
pub struct SitemapEntry {
    pub url: String,
    pub lastmod: Option<String>,
    pub priority: Option<f32>,
    pub changefreq: Option<String>,
}

/// Parsed sitemap content — either an index or a urlset.
#[derive(Debug)]
pub enum SitemapContent {
    /// Sitemap index containing URLs of nested sitemaps.
    Index(Vec<String>),
    /// URL set containing page entries.
    UrlSet(Vec<SitemapEntry>),
}

/// Parse a sitemap XML document (either index or urlset).
pub fn parse_sitemap(_xml: &[u8]) -> Result<SitemapContent> {
    todo!()
}
```

**Step 3: Export from lib.rs**

Add to `crates/crawler/src/lib.rs`:
```rust
pub mod sitemap;
```
And add to the pub use block:
```rust
pub use sitemap::{SitemapContent, SitemapEntry};
```

**Step 4: Verify it compiles**

Run: `cd . && cargo check -p ox-crawler`
Expected: compiles (todo!() is fine for check)

**Step 5: Commit**

```bash
git add crates/crawler/Cargo.toml crates/crawler/src/sitemap.rs crates/crawler/src/lib.rs
git commit -m "feat(crawler): add sitemap types and quick-xml dependency"
```

---

### Task 2: Implement sitemap XML parser

**Files:**
- Modify: `crates/crawler/src/sitemap.rs`

**Step 1: Write tests for parse_sitemap**

Add at the bottom of `sitemap.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urlset() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url>
                <loc>https://example.com/page1</loc>
                <lastmod>2026-03-01</lastmod>
                <priority>0.8</priority>
                <changefreq>weekly</changefreq>
            </url>
            <url>
                <loc>https://example.com/page2</loc>
            </url>
        </urlset>"#;

        let result = parse_sitemap(xml).unwrap();
        match result {
            SitemapContent::UrlSet(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].url, "https://example.com/page1");
                assert_eq!(entries[0].lastmod.as_deref(), Some("2026-03-01"));
                assert_eq!(entries[0].priority, Some(0.8));
                assert_eq!(entries[0].changefreq.as_deref(), Some("weekly"));
                assert_eq!(entries[1].url, "https://example.com/page2");
                assert!(entries[1].lastmod.is_none());
                assert!(entries[1].priority.is_none());
            }
            _ => panic!("expected UrlSet"),
        }
    }

    #[test]
    fn parse_sitemap_index() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap>
                <loc>https://example.com/sitemap-posts.xml</loc>
            </sitemap>
            <sitemap>
                <loc>https://example.com/sitemap-pages.xml</loc>
            </sitemap>
        </sitemapindex>"#;

        let result = parse_sitemap(xml).unwrap();
        match result {
            SitemapContent::Index(urls) => {
                assert_eq!(urls.len(), 2);
                assert_eq!(urls[0], "https://example.com/sitemap-posts.xml");
                assert_eq!(urls[1], "https://example.com/sitemap-pages.xml");
            }
            _ => panic!("expected Index"),
        }
    }

    #[test]
    fn parse_empty_urlset() {
        let xml = br#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>"#;
        let result = parse_sitemap(xml).unwrap();
        match result {
            SitemapContent::UrlSet(entries) => assert!(entries.is_empty()),
            _ => panic!("expected UrlSet"),
        }
    }

    #[test]
    fn parse_invalid_xml_errors() {
        let xml = b"not xml at all";
        assert!(parse_sitemap(xml).is_err());
    }

    #[test]
    fn filter_entries_by_since() {
        let entries = vec![
            SitemapEntry {
                url: "https://a.com/old".into(),
                lastmod: Some("2025-01-01".into()),
                priority: None,
                changefreq: None,
            },
            SitemapEntry {
                url: "https://a.com/new".into(),
                lastmod: Some("2026-03-01".into()),
                priority: None,
                changefreq: None,
            },
            SitemapEntry {
                url: "https://a.com/nodate".into(),
                lastmod: None,
                priority: None,
                changefreq: None,
            },
        ];
        let filtered = filter_since(entries, "2026-01-01");
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].url, "https://a.com/new");
        assert_eq!(filtered[1].url, "https://a.com/nodate");
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cd . && cargo test -p ox-crawler sitemap -- --nocapture 2>&1 | tail -5`
Expected: FAIL — `todo!()` panics and `filter_since` not found

**Step 3: Implement parse_sitemap using quick-xml**

Replace the `todo!()` function with streaming parser:

```rust
use quick_xml::events::Event;
use quick_xml::Reader;

pub fn parse_sitemap(xml: &[u8]) -> Result<SitemapContent> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut is_index = false;
    let mut decided = false;

    // Detect type by first significant tag
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match name.as_str() {
                    "sitemapindex" => { is_index = true; decided = true; break; }
                    "urlset" => { is_index = false; decided = true; break; }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    if !decided {
        return Err(anyhow::anyhow!("no <urlset> or <sitemapindex> found"));
    }

    buf.clear();

    if is_index {
        parse_index(&mut reader, &mut buf)
    } else {
        parse_urlset(&mut reader, &mut buf)
    }
}

fn parse_index(reader: &mut Reader<&[u8]>, buf: &mut Vec<u8>) -> Result<SitemapContent> {
    let mut urls = Vec::new();
    let mut in_loc = false;

    loop {
        match reader.read_event_into(buf) {
            Ok(Event::Start(ref e)) if e.local_name().as_ref() == b"loc" => {
                in_loc = true;
            }
            Ok(Event::Text(ref e)) if in_loc => {
                urls.push(e.unescape()?.trim().to_string());
                in_loc = false;
            }
            Ok(Event::End(ref e)) if e.local_name().as_ref() == b"loc" => {
                in_loc = false;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }
    Ok(SitemapContent::Index(urls))
}

fn parse_urlset(reader: &mut Reader<&[u8]>, buf: &mut Vec<u8>) -> Result<SitemapContent> {
    let mut entries = Vec::new();
    let mut current: Option<SitemapEntry> = None;
    let mut current_tag = String::new();

    loop {
        match reader.read_event_into(buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match name.as_str() {
                    "url" => {
                        current = Some(SitemapEntry {
                            url: String::new(),
                            lastmod: None,
                            priority: None,
                            changefreq: None,
                        });
                    }
                    "loc" | "lastmod" | "priority" | "changefreq" => {
                        current_tag = name;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) => {
                if let Some(ref mut entry) = current {
                    let text = e.unescape()?.trim().to_string();
                    match current_tag.as_str() {
                        "loc" => entry.url = text,
                        "lastmod" => entry.lastmod = Some(text),
                        "priority" => entry.priority = text.parse().ok(),
                        "changefreq" => entry.changefreq = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name = e.local_name().as_ref();
                if name == b"url" {
                    if let Some(entry) = current.take() {
                        if !entry.url.is_empty() {
                            entries.push(entry);
                        }
                    }
                }
                current_tag.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }
    Ok(SitemapContent::UrlSet(entries))
}
```

**Step 4: Implement filter_since**

```rust
/// Filter sitemap entries, keeping only those with lastmod >= since or no lastmod.
pub fn filter_since(entries: Vec<SitemapEntry>, since: &str) -> Vec<SitemapEntry> {
    entries
        .into_iter()
        .filter(|e| match &e.lastmod {
            Some(date) => date.as_str() >= since,
            None => true, // keep entries without lastmod
        })
        .collect()
}
```

**Step 5: Run tests**

Run: `cd . && cargo test -p ox-crawler sitemap -- --nocapture`
Expected: all 5 tests PASS

**Step 6: Commit**

```bash
git add crates/crawler/src/sitemap.rs
git commit -m "feat(crawler): implement sitemap XML parser with quick-xml"
```

---

### Task 3: Upgrade Frontier to priority queue

**Files:**
- Modify: `crates/crawler/src/frontier.rs`
- Modify: `crates/crawler/src/lib.rs`

**Step 1: Write tests for priority ordering and EntrySource**

Add to `frontier.rs` tests:
```rust
    #[test]
    fn priority_ordering() {
        let mut f = Frontier::new(10);
        f.push_with_priority("https://low.com".into(), 0, 0.3, EntrySource::Bfs);
        f.push_with_priority("https://high.com".into(), 0, 0.9, EntrySource::Sitemap { lastmod: None });
        f.push_with_priority("https://mid.com".into(), 0, 0.5, EntrySource::Bfs);

        let first = f.pop().unwrap();
        assert_eq!(first.url, "https://high.com");
        assert_eq!(first.priority, 0.9);

        let second = f.pop().unwrap();
        assert_eq!(second.url, "https://mid.com");
    }

    #[test]
    fn fifo_within_same_priority() {
        let mut f = Frontier::new(10);
        f.push_with_priority("https://first.com".into(), 0, 0.5, EntrySource::Bfs);
        f.push_with_priority("https://second.com".into(), 0, 0.5, EntrySource::Bfs);

        let first = f.pop().unwrap();
        assert_eq!(first.url, "https://first.com");
    }

    #[test]
    fn push_backward_compat() {
        let mut f = Frontier::new(10);
        f.push("https://a.com".into(), 0);
        let entry = f.pop().unwrap();
        assert_eq!(entry.priority, 0.5);
        assert!(matches!(entry.source, EntrySource::Bfs));
    }
```

**Step 2: Run tests to verify they fail**

Run: `cd . && cargo test -p ox-crawler frontier -- --nocapture 2>&1 | tail -5`
Expected: FAIL — `push_with_priority` and `EntrySource` not found

**Step 3: Rewrite frontier.rs with BinaryHeap**

```rust
//! Priority URL frontier backed by [`BinaryHeap`].

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Source of a frontier entry.
#[derive(Debug, Clone)]
pub enum EntrySource {
    Bfs,
    Sitemap { lastmod: Option<String> },
}

/// A single entry in the crawl frontier.
#[derive(Debug, Clone)]
pub struct FrontierEntry {
    pub url: String,
    pub depth: u32,
    pub priority: f32,
    pub source: EntrySource,
    sequence: u64,
}

impl PartialEq for FrontierEntry {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}

impl Eq for FrontierEntry {}

impl PartialOrd for FrontierEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FrontierEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first; if equal, lower sequence (earlier) first
        self.priority
            .partial_cmp(&other.priority)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

/// Priority frontier with a maximum capacity.
#[derive(Debug)]
pub struct Frontier {
    heap: BinaryHeap<FrontierEntry>,
    max_size: usize,
    next_seq: u64,
}

impl Frontier {
    pub fn new(max_size: usize) -> Self {
        Self {
            heap: BinaryHeap::with_capacity(max_size.min(1024)),
            max_size,
            next_seq: 0,
        }
    }

    /// Push a URL with default priority (0.5) and BFS source.
    /// Backward-compatible with existing callers.
    pub fn push(&mut self, url: String, depth: u32) {
        self.push_with_priority(url, depth, 0.5, EntrySource::Bfs);
    }

    /// Push a URL with explicit priority and source.
    pub fn push_with_priority(
        &mut self,
        url: String,
        depth: u32,
        priority: f32,
        source: EntrySource,
    ) {
        if self.heap.len() >= self.max_size {
            return;
        }
        let sequence = self.next_seq;
        self.next_seq += 1;
        self.heap.push(FrontierEntry {
            url,
            depth,
            priority,
            source,
            sequence,
        });
    }

    /// Pop the highest-priority entry.
    pub fn pop(&mut self) -> Option<FrontierEntry> {
        self.heap.pop()
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}
```

**Step 4: Update lib.rs exports**

Add `EntrySource` to the pub use for frontier:
```rust
pub use frontier::{EntrySource, Frontier, FrontierEntry};
```

**Step 5: Run all crawler tests**

Run: `cd . && cargo test -p ox-crawler -- --nocapture`
Expected: all tests PASS (existing tests use `push()` which is backward-compatible)

**Step 6: Commit**

```bash
git add crates/crawler/src/frontier.rs crates/crawler/src/lib.rs
git commit -m "feat(crawler): upgrade frontier to priority queue with BinaryHeap"
```

---

### Task 4: Extend CrawlConfig and CrawlResult

**Files:**
- Modify: `crates/crawler/src/config.rs`
- Modify: `crates/crawler/src/result.rs`

**Step 1: Add discovery fields to CrawlConfig**

Add new fields to `CrawlConfig`:
```rust
    /// Discovery mode: "bfs", "sitemap", or "hybrid".
    pub discovery: String,
    /// Explicit sitemap URL. None = auto-discover.
    pub sitemap_url: Option<String>,
    /// Filter sitemap index entries by name (contains match).
    pub sitemap_filter: Vec<String>,
    /// Only include URLs with lastmod >= this ISO date.
    pub sitemap_since: Option<String>,
    /// Max recursion depth for sitemap index (default 3, 0 = unlimited).
    pub sitemap_max_depth: u32,
    /// Max number of sitemap files to process (default 50).
    pub sitemap_max_files: usize,
    /// Save page content to files instead of inline.
    pub save_to_file: bool,
```

Update `Default`:
```rust
    discovery: "bfs".into(),
    sitemap_url: None,
    sitemap_filter: Vec::new(),
    sitemap_since: None,
    sitemap_max_depth: 3,
    sitemap_max_files: 50,
    save_to_file: false,
```

**Step 2: Extend CrawlResult**

Add optional fields to `CrawlResult`:
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sitemap_lastmod: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sitemap_priority: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
```

**Step 3: Extend CrawlStats**

Add fields to `CrawlStats`:
```rust
    pub discovery: String,
    pub sitemaps_found: usize,
    pub sitemap_urls_total: usize,
    pub sitemap_urls_filtered: usize,
    pub output_dir: Option<String>,
```

Update `Default` for new fields (empty strings, zeros, None).

**Step 4: Fix compilation — update all CrawlResult/CrawlStats constructors in crawler.rs**

In `crates/crawler/src/crawler.rs`, every `CrawlResult { ... }` must include the new fields as `None`. Search for all `CrawlResult {` and add:
```rust
    source: None,
    sitemap_lastmod: None,
    sitemap_priority: None,
    file_path: None,
```

**Step 5: Run tests**

Run: `cd . && cargo test -p ox-crawler -- --nocapture`
Expected: all tests PASS

**Step 6: Commit**

```bash
git add crates/crawler/src/config.rs crates/crawler/src/result.rs crates/crawler/src/crawler.rs
git commit -m "feat(crawler): extend config, result, and stats for sitemap discovery"
```

---

### Task 5: Add robots.txt sitemap extraction

**Files:**
- Modify: `crates/crawler/src/robots.rs`

**Step 1: Write test for extract_sitemaps**

Add to `robots.rs` tests:
```rust
    #[test]
    fn extracts_sitemap_urls() {
        let body = b"User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml\nSitemap: https://example.com/sitemap2.xml\n";
        let urls = extract_sitemaps(body);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://example.com/sitemap.xml");
        assert_eq!(urls[1], "https://example.com/sitemap2.xml");
    }

    #[test]
    fn no_sitemaps_in_robots() {
        let body = b"User-agent: *\nDisallow: /private/\n";
        let urls = extract_sitemaps(body);
        assert!(urls.is_empty());
    }
```

**Step 2: Run tests to verify they fail**

Expected: FAIL — `extract_sitemaps` not found

**Step 3: Implement extract_sitemaps**

Add to `robots.rs` (as a standalone function, not method on RobotsCache):
```rust
/// Extract `Sitemap:` URLs from a robots.txt body.
pub fn extract_sitemaps(robots_txt: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(robots_txt);
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.len() > 8 && line[..8].eq_ignore_ascii_case("sitemap:") {
                Some(line[8..].trim().to_string())
            } else {
                None
            }
        })
        .filter(|url| !url.is_empty())
        .collect()
}
```

**Step 4: Export from lib.rs**

Add to pub use block in `lib.rs`:
```rust
pub use robots::{extract_sitemaps, RobotsCache};
```

**Step 5: Run tests**

Run: `cd . && cargo test -p ox-crawler robots -- --nocapture`
Expected: all robot tests PASS

**Step 6: Commit**

```bash
git add crates/crawler/src/robots.rs crates/crawler/src/lib.rs
git commit -m "feat(crawler): extract Sitemap: URLs from robots.txt"
```

---

### Task 6: Implement discovery coordinator

**Files:**
- Create: `crates/crawler/src/discovery.rs`
- Modify: `crates/crawler/src/lib.rs`

**Step 1: Create discovery.rs with auto-discovery + index resolution**

```rust
//! Discovery mode coordinator — finds and resolves sitemaps.

use std::collections::HashSet;
use std::sync::Arc;

use ox_http::HttpClient;
use url::Url;

use crate::config::CrawlConfig;
use crate::sitemap::{self, SitemapContent, SitemapEntry};

/// Result of sitemap discovery phase.
#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub entries: Vec<SitemapEntry>,
    pub sitemaps_found: usize,
    pub urls_total: usize,
    pub urls_filtered: usize,
}

/// Discover and resolve sitemaps for the given seed URL.
pub async fn discover_and_resolve(
    seed_url: &str,
    config: &CrawlConfig,
    http: &Arc<HttpClient>,
) -> DiscoveryResult {
    let sitemap_urls = find_sitemaps(seed_url, config, http).await;
    if sitemap_urls.is_empty() {
        tracing::info!("no sitemaps found");
        return DiscoveryResult::default();
    }

    let max_depth = if config.sitemap_max_depth == 0 {
        u32::MAX
    } else {
        config.sitemap_max_depth
    };

    let mut seen = HashSet::new();
    let mut all_entries = Vec::new();
    let mut sitemaps_found = 0usize;

    resolve_recursive(
        &sitemap_urls,
        0,
        max_depth,
        config.sitemap_max_files,
        &config.sitemap_filter,
        http,
        &mut seen,
        &mut all_entries,
        &mut sitemaps_found,
    )
    .await;

    let urls_total = all_entries.len();

    // Apply since filter
    let entries = match &config.sitemap_since {
        Some(since) => sitemap::filter_since(all_entries, since),
        None => all_entries,
    };
    let urls_filtered = urls_total - entries.len();

    tracing::info!(
        sitemaps_found,
        urls_total,
        urls_filtered,
        urls_kept = entries.len(),
        "sitemap discovery complete"
    );

    DiscoveryResult {
        entries,
        sitemaps_found,
        urls_total,
        urls_filtered,
    }
}

async fn find_sitemaps(
    seed_url: &str,
    config: &CrawlConfig,
    http: &Arc<HttpClient>,
) -> Vec<String> {
    // 1. Explicit URL
    if let Some(ref url) = config.sitemap_url {
        return vec![url.clone()];
    }

    let origin = match Url::parse(seed_url) {
        Ok(u) => format!("{}://{}", u.scheme(), u.host_str().unwrap_or("")),
        Err(_) => return Vec::new(),
    };

    // 2. Try robots.txt
    let robots_url = format!("{origin}/robots.txt");
    if let Ok(resp) = http.get(&robots_url).await {
        if resp.status == 200 {
            let urls = crate::robots::extract_sitemaps(resp.body.as_bytes());
            if !urls.is_empty() {
                tracing::info!(count = urls.len(), "found sitemaps in robots.txt");
                return urls;
            }
        }
    }

    // 3. Try standard paths
    for path in ["/sitemap.xml", "/sitemap_index.xml"] {
        let url = format!("{origin}{path}");
        if let Ok(resp) = http.get(&url).await {
            if resp.status == 200 && resp.body.contains('<') {
                tracing::info!(url = %url, "found sitemap at standard path");
                return vec![url];
            }
        }
    }

    Vec::new()
}

#[allow(clippy::too_many_arguments)]
async fn resolve_recursive(
    urls: &[String],
    depth: u32,
    max_depth: u32,
    max_files: usize,
    filter: &[String],
    http: &Arc<HttpClient>,
    seen: &mut HashSet<String>,
    entries: &mut Vec<SitemapEntry>,
    sitemaps_found: &mut usize,
) {
    for url in urls {
        if *sitemaps_found >= max_files {
            tracing::warn!(max_files, "sitemap file limit reached");
            return;
        }
        if !seen.insert(url.clone()) {
            continue; // cycle protection
        }

        let resp = match http.get(url).await {
            Ok(r) if r.status == 200 => r,
            _ => {
                tracing::warn!(url, "failed to fetch sitemap");
                continue;
            }
        };

        *sitemaps_found += 1;

        match sitemap::parse_sitemap(resp.body.as_bytes()) {
            Ok(SitemapContent::UrlSet(mut page_entries)) => {
                entries.append(&mut page_entries);
            }
            Ok(SitemapContent::Index(nested_urls)) => {
                if depth >= max_depth {
                    tracing::warn!(depth, max_depth, "sitemap index depth limit reached");
                    continue;
                }
                // Apply sitemap_filter
                let filtered: Vec<String> = if filter.is_empty() {
                    nested_urls
                } else {
                    nested_urls
                        .into_iter()
                        .filter(|u| filter.iter().any(|f| u.contains(f)))
                        .collect()
                };

                Box::pin(resolve_recursive(
                    &filtered,
                    depth + 1,
                    max_depth,
                    max_files,
                    filter,
                    http,
                    seen,
                    entries,
                    sitemaps_found,
                ))
                .await;
            }
            Err(e) => {
                tracing::warn!(url, error = %e, "failed to parse sitemap");
            }
        }
    }
}
```

Note: `resolve_recursive` uses `Box::pin` for async recursion.

**Step 2: Export from lib.rs**

```rust
pub mod discovery;
pub use discovery::DiscoveryResult;
```

**Step 3: Verify compilation**

Run: `cd . && cargo check -p ox-crawler`
Expected: compiles

**Step 4: Commit**

```bash
git add crates/crawler/src/discovery.rs crates/crawler/src/lib.rs
git commit -m "feat(crawler): add discovery coordinator with auto-discovery and index resolution"
```

---

### Task 7: Integrate discovery into crawler.rs

**Files:**
- Modify: `crates/crawler/src/crawler.rs`

**Step 1: Add discovery phase before BFS loop**

In `run_crawl()`, after frontier seeding (line 62-69), add discovery integration:

```rust
    // Discovery phase: load sitemap URLs if needed
    let discovery_mode = config.discovery.clone();
    let mut sitemap_stats = DiscoveryResult::default();

    if discovery_mode == "sitemap" || discovery_mode == "hybrid" {
        sitemap_stats = crate::discovery::discover_and_resolve(&seed, &config, &http).await;

        // Send sitemap progress event via tx if we have entries
        // (handled by caller — we just seed the frontier)

        let mut f = frontier.lock().await;
        let mut d = dedup.lock().await;
        for entry in &sitemap_stats.entries {
            if let Some(normalized) = normalize_url(&entry.url) {
                if d.insert(&normalized) {
                    let priority = entry.priority.unwrap_or(0.5);
                    let source = crate::frontier::EntrySource::Sitemap {
                        lastmod: entry.lastmod.clone(),
                    };
                    f.push_with_priority(normalized, 0, priority, source);
                }
            }
        }
    }

    // In sitemap-only mode, disable BFS link following
    let follow_links = discovery_mode != "sitemap";
```

Then in `process_page()`, conditionally skip link enqueuing:

The `process_page` function needs a `follow_links: bool` parameter. When `false`, skip the "Enqueue discovered links" block entirely.

**Step 2: Propagate source info to CrawlResult**

In `process_page`, set `source` based on the `FrontierEntry.source` that was popped. Pass `entry.source` through to `process_page` and map it:

```rust
    source: Some(match &entry_source {
        EntrySource::Bfs => "bfs".to_string(),
        EntrySource::Sitemap { .. } => "sitemap".to_string(),
    }),
    sitemap_lastmod: match &entry_source {
        EntrySource::Sitemap { lastmod } => lastmod.clone(),
        _ => None,
    },
    sitemap_priority: None, // could track but not critical
```

**Step 3: Return sitemap stats from run_crawl**

Change `run_crawl` return type to `Result<DiscoveryResult>` so the caller (REST/MCP) can include stats in the summary.

Alternatively, send stats via the channel as a special message — but simpler to return from `crawl()` method. Refactor `Crawler::crawl` to return `(Receiver<CrawlResult>, Option<DiscoveryResult>)` or include stats in the receiver as a final message.

Simplest approach: add a second channel for stats, or make `Crawler::crawl` async and return stats after seeding:

```rust
pub async fn crawl(&self, seed_url: &str) -> (mpsc::Receiver<CrawlResult>, DiscoveryResult)
```

**Step 4: Run tests**

Run: `cd . && cargo test -p ox-crawler -- --nocapture`
Expected: all tests PASS

**Step 5: Commit**

```bash
git add crates/crawler/src/crawler.rs
git commit -m "feat(crawler): integrate sitemap discovery into crawl loop"
```

---

### Task 8: Add save_to_file support in crawler

**Files:**
- Modify: `crates/crawler/src/crawler.rs`

**Step 1: Implement file saving in process_page**

When `config.save_to_file` is true and markdown is non-empty:
- Create output dir: `/tmp/ox-browser/crawl/{domain}_{timestamp}/`
- Write markdown to `page_{seq:04}.md`
- Write metadata line to `index.jsonl`
- Set `file_path` in CrawlResult, clear inline markdown

Use `ox_core::save` module pattern but with crawl-specific directory structure.

```rust
use std::sync::atomic::AtomicUsize;
use std::io::Write;

// In run_crawl, before the loop:
let output_dir = if config.save_to_file {
    let domain = seed_url.host_str().unwrap_or("unknown");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dir = format!("/tmp/ox-browser/crawl/{}_{}", domain, ts);
    std::fs::create_dir_all(&dir).ok();
    Some(dir)
} else {
    None
};
let page_counter = Arc::new(AtomicUsize::new(0));
```

In `process_page`, after markdown conversion:
```rust
let file_path = if let Some(ref dir) = output_dir {
    if !markdown.is_empty() {
        let seq = page_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let filename = format!("page_{:04}.md", seq);
        let path = format!("{}/{}", dir, filename);
        if std::fs::write(&path, &markdown).is_ok() {
            // Write index line
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true).append(true)
                .open(format!("{}/index.jsonl", dir))
            {
                let _ = writeln!(f, r#"{{"url":"{}","file":"{}","status":{}}}"#, url_str, filename, resp.status);
            }
            Some(path)
        } else { None }
    } else { None }
} else { None };
```

When `file_path` is Some, set `result.file_path` and clear `result.markdown`.

**Step 2: Run tests**

Run: `cd . && cargo test -p ox-crawler -- --nocapture`
Expected: all tests PASS

**Step 3: Commit**

```bash
git add crates/crawler/src/crawler.rs
git commit -m "feat(crawler): add save_to_file support with JSONL index"
```

---

### Task 9: Update REST endpoint

**Files:**
- Modify: `crates/js/src/crawl.rs`

**Step 1: Add new parameters to CrawlRequest**

```rust
    #[serde(default)]
    pub discovery: Option<String>,
    #[serde(default)]
    pub sitemap_url: Option<String>,
    #[serde(default)]
    pub sitemap_filter: Option<Vec<String>>,
    #[serde(default)]
    pub sitemap_since: Option<String>,
    #[serde(default)]
    pub sitemap_max_depth: Option<u32>,
    #[serde(default)]
    pub sitemap_max_files: Option<usize>,
    #[serde(default)]
    pub save_to_file: Option<bool>,
```

**Step 2: Map to CrawlConfig**

In the `crawl()` handler, set new config fields:
```rust
    let config = CrawlConfig {
        // ... existing fields ...
        discovery: req.discovery.unwrap_or_else(|| "bfs".into()),
        sitemap_url: req.sitemap_url,
        sitemap_filter: req.sitemap_filter.unwrap_or_default(),
        sitemap_since: req.sitemap_since,
        sitemap_max_depth: req.sitemap_max_depth.unwrap_or(3),
        sitemap_max_files: req.sitemap_max_files.unwrap_or(50),
        save_to_file: req.save_to_file.unwrap_or(false),
        ..Default::default()
    };
```

**Step 3: Add sitemap SSE event**

After `crawler.crawl()` returns discovery stats, emit a `sitemap` event before the page loop:
```rust
    if discovery.sitemaps_found > 0 {
        let sitemap_json = serde_json::json!({
            "phase": "discover",
            "sitemaps_found": discovery.sitemaps_found,
            "urls_found": discovery.entries.len(),
            "urls_filtered": discovery.urls_filtered,
        });
        yield Ok::<_, Infallible>(Event::default().event("sitemap").data(sitemap_json.to_string()));
    }
```

**Step 4: Extend CrawlSummary**

```rust
    pub discovery: String,
    pub sitemaps_found: usize,
    pub sitemap_urls_total: usize,
    pub sitemap_urls_filtered: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_dir: Option<String>,
```

**Step 5: Update tests**

Add test for new request parameters:
```rust
    #[test]
    fn crawl_request_sitemap_params() {
        let json = r#"{
            "url": "https://example.com",
            "discovery": "sitemap",
            "sitemap_filter": ["posts"],
            "sitemap_since": "2026-01-01",
            "save_to_file": true
        }"#;
        let req: CrawlRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.discovery.as_deref(), Some("sitemap"));
        assert_eq!(req.sitemap_filter.as_ref().unwrap()[0], "posts");
        assert_eq!(req.save_to_file, Some(true));
    }
```

**Step 6: Run tests**

Run: `cd . && cargo test -p ox-js -- --nocapture`
Expected: PASS

**Step 7: Commit**

```bash
git add crates/js/src/crawl.rs
git commit -m "feat(rest): add sitemap discovery params to /crawl endpoint"
```

---

### Task 10: Update MCP tool

**Files:**
- Modify: `crates/mcp/src/tools/crawl.rs`
- Modify: `crates/mcp/src/tools/mod.rs`

**Step 1: Add new parameters to CrawlInput**

```rust
    /// Discovery mode: "bfs" (default), "sitemap", or "hybrid".
    #[serde(default)]
    pub discovery: Option<String>,
    /// Explicit sitemap URL. Auto-discovers if not set.
    #[serde(default)]
    pub sitemap_url: Option<String>,
    /// Filter sitemap index entries by name substring.
    #[serde(default)]
    pub sitemap_filter: Option<Vec<String>>,
    /// Only URLs with lastmod >= this ISO date.
    #[serde(default)]
    pub sitemap_since: Option<String>,
    /// Save page markdown to files. Default: false.
    #[serde(default)]
    pub save_to_file: Option<bool>,
```

**Step 2: Map to CrawlConfig in do_crawl**

```rust
    let config = CrawlConfig {
        // ... existing ...
        discovery: input.discovery.unwrap_or_else(|| "bfs".into()),
        sitemap_url: input.sitemap_url,
        sitemap_filter: input.sitemap_filter.unwrap_or_default(),
        sitemap_since: input.sitemap_since,
        save_to_file: input.save_to_file.unwrap_or(false),
        ..Default::default()
    };
```

**Step 3: Extend PageSummary with new fields**

```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
```

Update `From<CrawlResult>` to include new fields.

**Step 4: Update MCP tool description**

In `mod.rs`, update the crawl tool description:
```
"Site crawler with BFS, sitemap, or hybrid discovery. Starts from seed URL, discovers pages via links or sitemap.xml. Respects robots.txt, deduplicates URLs and content, converts HTML to markdown. Supports sitemap filtering, date-based filtering, and file output."
```

**Step 5: Run tests**

Run: `cd . && cargo test --workspace -- --nocapture`
Expected: all 135+ tests PASS

**Step 6: Commit**

```bash
git add crates/mcp/src/tools/crawl.rs crates/mcp/src/tools/mod.rs
git commit -m "feat(mcp): add sitemap discovery params to crawl tool"
```

---

### Task 11: Build, deploy, and verify

**Step 1: Run full test suite**

Run: `cd . && cargo test --workspace`
Expected: all tests PASS

**Step 2: Build Docker image**

Run: `cd <deploy> && docker compose build --no-cache ox-browser`

**Step 3: Deploy**

Run: `cd <deploy> && docker compose up -d --no-deps --force-recreate ox-browser`

**Step 4: Health check**

Run: `sleep 3 && curl -sf http://127.0.0.1:8901/health`
Expected: `ok`

**Step 5: Test BFS mode (backward compat)**

```bash
curl -s -N -X POST http://127.0.0.1:8901/crawl \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","max_pages":2}' 2>&1 | head -20
```
Expected: SSE events with `event: page` and `event: done`, no sitemap fields

**Step 6: Test sitemap mode**

```bash
curl -s -N -X POST http://127.0.0.1:8901/crawl \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","discovery":"sitemap","max_pages":5}' 2>&1 | head -30
```
Expected: `event: sitemap` with discovery progress, then `event: page` events

**Step 7: Test save_to_file**

```bash
curl -s -N -X POST http://127.0.0.1:8901/crawl \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","max_pages":3,"save_to_file":true}' 2>&1 | head -20
ls /tmp/ox-browser/crawl/
```
Expected: directory with `index.jsonl` and `page_*.md` files

**Step 8: Commit final state**

```bash
git add -A && git commit -m "feat: sitemap crawl v1 — complete implementation"
```
