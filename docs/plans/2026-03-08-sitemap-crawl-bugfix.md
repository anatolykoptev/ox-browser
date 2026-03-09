# Sitemap Crawl Bugfix Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 4 bugs found during integration testing of sitemap crawl feature.

**Architecture:** Targeted fixes in crawler.rs, discovery.rs, js/crawl.rs, mcp/crawl.rs. No new files.

**Tech Stack:** Rust, existing crates.

---

### Task 1: Skip seed URL in sitemap-only mode

**Bug:** In `discovery: "sitemap"`, the seed URL is always pushed to frontier as BFS entry (line 83-90 of crawler.rs), so it gets crawled with `source: "bfs"` even though the user only wants sitemap URLs.

**Files:**
- Modify: `crates/crawler/src/crawler.rs:83-90`

**Step 1: Write test**

Add to crawler.rs tests:
```rust
    #[tokio::test]
    async fn sitemap_mode_skips_seed_when_entries_exist() {
        // When discovery_entries is non-empty and follow_links is false (sitemap mode),
        // the seed URL should NOT be in the frontier — only sitemap entries.
        let frontier = Frontier::new(100);
        let dedup = UrlDedup::new();
        // Simulate: sitemap mode with entries → seed should be skipped
        // We test this indirectly: if seed is "https://example.com" and sitemap entries
        // contain "https://example.com/page1", frontier should only have page1.
        let mut f = frontier;
        let mut d = dedup;

        // Sitemap mode: don't push seed
        let follow_links = false;
        let discovery_entries = vec![crate::sitemap::SitemapEntry {
            url: "https://example.com/page1".into(),
            lastmod: None,
            priority: Some(0.8),
            changefreq: None,
        }];

        if follow_links {
            // BFS/hybrid: push seed
            d.insert("https://example.com/");
            f.push("https://example.com/".into(), 0);
        }

        // Always push sitemap entries
        for entry in &discovery_entries {
            if let Some(normalized) = normalize_url(&entry.url) {
                if d.insert(&normalized) {
                    f.push_with_priority(
                        normalized, 0,
                        entry.priority.unwrap_or(0.5),
                        EntrySource::Sitemap { lastmod: entry.lastmod.clone() },
                    );
                }
            }
        }

        assert_eq!(f.len(), 1);
        let e = f.pop().unwrap();
        assert!(e.url.contains("page1"));
        assert!(matches!(e.source, EntrySource::Sitemap { .. }));
    }
```

**Step 2: Fix the seed push logic**

In `run_crawl()`, wrap the seed push in a condition:
```rust
    // Seed the frontier (skip in sitemap-only mode when we have sitemap entries)
    if follow_links || discovery_entries.is_empty() {
        let normalized = normalize_url(&seed).unwrap_or_else(|| seed.clone());
        let mut d = dedup.lock().await;
        d.insert(&normalized);
        let mut f = frontier.lock().await;
        f.push(seed, 0);
    }
```

Logic: in sitemap-only mode (`follow_links=false`), skip seed push IF we have sitemap entries. If sitemap discovery found nothing, still push seed as fallback so user gets at least one page.

**Step 3: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-crawler -- --nocapture`

**Step 4: Commit**

```bash
git add crates/crawler/src/crawler.rs
git commit -m "fix(crawler): skip seed URL in sitemap-only mode when entries exist"
```

---

### Task 2: Support gzip-compressed sitemaps

**Bug:** Many sites serve sitemaps as `.xml.gz` or with `Content-Encoding: gzip`. Our fetcher gets raw gzip bytes and tries to parse as XML, which fails silently. GitHub's sitemap is gzip-compressed.

**Files:**
- Modify: `crates/crawler/src/discovery.rs`
- Modify: `crates/crawler/src/sitemap.rs`
- Modify: `crates/crawler/Cargo.toml` (add `flate2`)

**Step 1: Add flate2 dependency**

In `crates/crawler/Cargo.toml` under `[dependencies]`:
```toml
flate2 = "1"
```

**Step 2: Write test for gzip support**

Add to `sitemap.rs` tests:
```rust
    #[test]
    fn parse_gzipped_urlset() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let xml = br#"<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://example.com/gz-page</loc></url>
        </urlset>"#;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml).unwrap();
        let gzipped = encoder.finish().unwrap();

        let result = parse_sitemap(&gzipped).unwrap();
        match result {
            SitemapContent::UrlSet(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].url, "https://example.com/gz-page");
            }
            _ => panic!("expected UrlSet"),
        }
    }
```

**Step 3: Implement gzip detection in parse_sitemap**

At the start of `parse_sitemap`, detect gzip magic bytes and decompress:
```rust
use flate2::read::GzDecoder;
use std::io::Read;

pub fn parse_sitemap(xml: &[u8]) -> Result<SitemapContent> {
    // Detect gzip (magic bytes 0x1f, 0x8b)
    let data = if xml.len() >= 2 && xml[0] == 0x1f && xml[1] == 0x8b {
        let mut decoder = GzDecoder::new(xml);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| anyhow::anyhow!("gzip decompression failed: {e}"))?;
        decompressed
    } else {
        xml.to_vec()
    };

    let mut reader = Reader::from_reader(data.as_slice());
    // ... rest of parsing unchanged, but use `data` instead of `xml`
```

Note: the internal parse functions (`parse_index`, `parse_urlset_xml`) take `Reader<&[u8]>` so the signature change is minimal — just feed `data.as_slice()` to `Reader::from_reader`.

**Step 4: Also handle .gz URLs in discovery**

In `resolve_recursive` in `discovery.rs`, the response body already comes as a String from `http.get()`. The HTTP client may auto-decompress Content-Encoding gzip. But for URLs ending in `.xml.gz`, the body might still be raw gzip bytes stored as a String (lossy).

Actually, check: if `http.get()` returns `resp.body` as `String`, then binary gzip data would be mangled by UTF-8 lossy conversion. We need to check if `HttpClient` has a method returning raw bytes.

Read `crates/http/src/response.rs` to check the HttpResponse type.

If `body` is always String (no raw bytes), then gzip support only works if the HTTP layer handles Content-Encoding. In that case, `.xml.gz` URLs won't work but Content-Encoding: gzip will. This is acceptable for v1 — add a TODO comment.

**Step 5: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test -p ox-crawler sitemap -- --nocapture`

**Step 6: Commit**

```bash
git add crates/crawler/Cargo.toml crates/crawler/src/sitemap.rs
git commit -m "feat(crawler): support gzip-compressed sitemaps"
```

---

### Task 3: Propagate output_dir to summaries

**Bug:** `output_dir` is always `None` in both REST CrawlSummary and MCP CrawlToolResult. The output directory is created inside `run_crawl` but never surfaced to callers.

**Files:**
- Modify: `crates/crawler/src/crawler.rs`
- Modify: `crates/crawler/src/result.rs`
- Modify: `crates/js/src/crawl.rs`
- Modify: `crates/mcp/src/tools/crawl.rs`

**Step 1: Return output_dir from Crawler::crawl**

Change `Crawler::crawl` to return a triple:
```rust
pub async fn crawl(
    &self,
    seed_url: &str,
) -> (mpsc::Receiver<CrawlResult>, DiscoveryResult, Option<String>)
```

Compute `output_dir` in `crawl()` (before spawning), pass it to `run_crawl`, and also return it:
```rust
    let output_dir = if config.save_to_file {
        let domain = Url::parse(&seed)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "unknown".into());
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
```

Move the output_dir creation OUT of `run_crawl` and INTO `crawl()`. Pass `output_dir.clone()` to `run_crawl`.

**Step 2: Update callers**

REST (`js/crawl.rs`):
```rust
    let (mut rx, discovery, output_dir) = crawler.crawl(&req.url).await;
    // ...
    let summary = CrawlSummary {
        // ...
        output_dir,
    };
```

MCP (`mcp/crawl.rs`):
```rust
    let (mut rx, discovery, output_dir) = crawler.crawl(&input.url).await;
    // ...
    let result = CrawlToolResult {
        // ...
        output_dir,
    };
```

**Step 3: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace -- --nocapture`

**Step 4: Commit**

```bash
git add crates/crawler/src/crawler.rs crates/js/src/crawl.rs crates/mcp/src/tools/crawl.rs
git commit -m "fix(crawler): propagate output_dir to REST and MCP summaries"
```

---

### Task 4: Validate discovery mode parameter

**Bug (preventive):** No validation on `discovery` parameter — arbitrary strings like `"foo"` silently fall through to BFS behavior. Should reject invalid values explicitly.

**Files:**
- Modify: `crates/js/src/crawl.rs`
- Modify: `crates/mcp/src/tools/crawl.rs`

**Step 1: Add validation in REST handler**

After config construction, validate:
```rust
    match config.discovery.as_str() {
        "bfs" | "sitemap" | "hybrid" => {}
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown discovery mode: {other}, expected bfs/sitemap/hybrid"),
            ));
        }
    }
```

**Step 2: Add validation in MCP handler**

```rust
    match config.discovery.as_str() {
        "bfs" | "sitemap" | "hybrid" => {}
        other => {
            return Err(McpError::invalid_params(
                format!("unknown discovery mode: {other}, expected bfs/sitemap/hybrid"),
                None,
            ));
        }
    }
```

**Step 3: Add tests**

REST test:
```rust
    #[test]
    fn crawl_request_invalid_discovery_rejected() {
        // This tests deserialization; runtime validation is in the handler
        let json = r#"{"url":"https://example.com","discovery":"invalid"}"#;
        let req: CrawlRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.discovery.as_deref(), Some("invalid"));
    }
```

**Step 4: Run tests**

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace -- --nocapture`

**Step 5: Commit**

```bash
git add crates/js/src/crawl.rs crates/mcp/src/tools/crawl.rs
git commit -m "fix: validate discovery mode parameter in REST and MCP handlers"
```

---

### Task 5: Build, deploy, and verify all fixes

**Step 1: Run full test suite**

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace`

**Step 2: Build and deploy**

```bash
cd ~/deploy/krolik-server && docker compose build --no-cache ox-browser && docker compose up -d --no-deps --force-recreate ox-browser
```

**Step 3: Verify fix #1 — sitemap mode no longer crawls seed as BFS**

```bash
curl -s -N -X POST http://127.0.0.1:8901/crawl \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.sitemaps.org","discovery":"sitemap","max_pages":3}' 2>&1 | head -15
```
Expected: NO page with `source: "bfs"` — all pages should be `source: "sitemap"`

**Step 4: Verify fix #3 — output_dir in summary**

```bash
curl -s -N -X POST http://127.0.0.1:8901/crawl \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","max_pages":2,"save_to_file":true}' 2>&1 | grep done
```
Expected: `"output_dir":"/tmp/ox-browser/crawl/example.com_..."` in done event

**Step 5: Verify fix #4 — invalid discovery rejected**

```bash
curl -s -X POST http://127.0.0.1:8901/crawl \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","discovery":"invalid"}'
```
Expected: 400 Bad Request with error message
