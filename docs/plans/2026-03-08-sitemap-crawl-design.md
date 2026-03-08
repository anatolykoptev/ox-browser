# Sitemap Crawl Design

**Date**: 2026-03-08
**Status**: Approved

## Summary

Extend `/crawl` endpoint with sitemap-based URL discovery. Three modes: BFS (current), sitemap-only, and hybrid. Sitemap parsing with priority-based frontier, filtering, recursive index resolution, and structured file output.

## Discovery Modes

Single endpoint `/crawl`, parameter `discovery: "bfs" | "sitemap" | "hybrid"` (default: `"bfs"`).

- **bfs** — current behavior, no changes
- **sitemap** — URLs from sitemap only, no BFS link following
- **hybrid** — sitemap seeds frontier, BFS discovers additional links from each page

## New Request Parameters

```rust
discovery: Option<String>,              // "bfs" | "sitemap" | "hybrid", default "bfs"
sitemap_url: Option<String>,            // explicit sitemap URL, else auto-discover
sitemap_filter: Option<Vec<String>>,    // filter sitemap index entries by name (contains match)
sitemap_since: Option<String>,          // ISO date — only URLs with lastmod >= since
sitemap_max_depth: Option<u32>,         // index recursion depth, default 3, 0 = unlimited
sitemap_max_files: Option<usize>,       // max sitemap files to process, default 50
save_to_file: Option<bool>,             // save markdown to files, return paths in SSE
```

Existing parameters (`max_pages`, `max_depth`, `scope`, `budget`, `include_markdown`) apply on top of any discovery mode.

## Sitemap Auto-Discovery

Order:
1. Parse robots.txt (already fetched via `RobotsCache`) → extract `Sitemap:` directives
2. Try `{origin}/sitemap.xml`
3. Try `{origin}/sitemap_index.xml`

Returns list of sitemap URLs found.

## Sitemap XML Parsing

**Crate**: `quick-xml` (streaming, no full DOM in memory).

**Types:**
```rust
struct SitemapEntry {
    url: String,
    lastmod: Option<String>,
    priority: Option<f32>,       // 0.0–1.0
    changefreq: Option<String>,
}

enum SitemapContent {
    Index(Vec<String>),          // nested sitemap URLs
    UrlSet(Vec<SitemapEntry>),   // page URLs
}
```

Single function `parse_sitemap(xml: &[u8]) -> Result<SitemapContent>` — detects type by first significant tag (`<sitemapindex>` vs `<urlset>`).

## Index Recursion

`resolve_sitemaps(urls, depth, max_depth, max_files, http)`:
- Recursively expands index → index → urlset
- Parallel download via semaphore (reuses crawler concurrency setting)
- Default max_depth: 3. Set 0 for unlimited.
- Default max_files: 50 (OOM protection)
- URL dedup on sitemap file URLs (cycle protection)

## Sitemap Filtering

- **sitemap_filter**: when expanding sitemap index, only process entries whose URL contains any of the filter strings. E.g. `["posts", "pages"]` keeps `sitemap-posts.xml` and `sitemap-pages.xml`.
- **sitemap_since**: during urlset parsing, skip entries with `lastmod < since`. Filtered at parse time, never enters frontier.

## Priority Frontier

`Frontier` upgraded from `VecDeque` (FIFO) to `BinaryHeap` (max-heap by priority).

```rust
struct FrontierEntry {
    url: String,
    depth: u32,
    priority: f32,              // default 0.5, sitemap priority overrides
    source: EntrySource,
    sequence: u64,              // tie-breaker for FIFO within same priority
}

enum EntrySource {
    Bfs,
    Sitemap { lastmod: Option<String> },
}
```

BFS-discovered URLs get `priority: 0.5`. Sitemap URLs use their `<priority>` value (default 0.5 if absent).

## Hybrid Mode

1. Load and parse sitemap → all URLs enter frontier with `source: Sitemap`
2. BFS loop runs as normal — page links also enter frontier with `source: Bfs`
3. `max_depth` for BFS links counts from the sitemap page (depth 0)

## Output Format

### SSE Events

Three event types:

```
event: sitemap
data: {"phase":"discover","sitemaps_found":3,"urls_found":1250}

event: page
data: {"url":"...","status":200,"source":"sitemap",...}

event: done
data: {"pages_crawled":100,"discovery":"sitemap","sitemaps_found":5,...}
```

### CrawlResult (extended)

New optional fields (skip_serializing_if None — backward compatible):
- `source: Option<String>` — "bfs" or "sitemap"
- `sitemap_lastmod: Option<String>`
- `sitemap_priority: Option<f32>`
- `file_path: Option<String>` — when save_to_file=true

### CrawlSummary (extended)

New fields:
- `discovery: String` — "bfs", "sitemap", or "hybrid"
- `sitemaps_found: usize`
- `sitemap_urls_total: usize`
- `sitemap_urls_filtered: usize`
- `output_dir: Option<String>` — when save_to_file=true

### File Output (save_to_file=true)

```
/tmp/ox-browser/crawl/{domain}_{timestamp}/
├── index.jsonl          # one JSON line per page (metadata + file_path)
├── page_0001.md         # markdown content
├── page_0002.md
└── ...
```

SSE `page` events contain metadata + `file_path`, no inline markdown.
SSE `done` event contains `output_dir` path + summary.

## File Structure

**New files:**
- `crates/crawler/src/sitemap.rs` — XML parser + auto-discovery (~150 lines)
- `crates/crawler/src/discovery.rs` — discovery mode coordinator (~80 lines)

**Modified files:**
- `crates/crawler/src/lib.rs` — export new modules
- `crates/crawler/src/frontier.rs` — BinaryHeap + priority + source (~40 lines diff)
- `crates/crawler/src/config.rs` — new fields in CrawlConfig (~15 lines)
- `crates/crawler/src/result.rs` — new fields in CrawlResult/CrawlSummary (~10 lines)
- `crates/crawler/src/crawler.rs` — integrate discovery before BFS loop (~30 lines)
- `crates/crawler/src/robots.rs` — extract_sitemaps() method (~10 lines)
- `crates/crawler/Cargo.toml` — add quick-xml
- `crates/js/src/crawl.rs` — new params in CrawlRequest + save_to_file logic (~20 lines)
- `crates/mcp/src/tools/crawl.rs` — new params in MCP tool input (~15 lines)

**New dependency:** `quick-xml = "0.37"`

## Backward Compatibility

Full. BFS mode is default. Sitemap fields are `Option` with `skip_serializing_if`. No breaking changes to existing API.
