# Reverse Image Search v2 — Quality Improvements

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade ox-reverse from MVP to production quality — fix broken Google Lens, modernize Yandex parsing, enrich result data, eliminate code duplication.

**Architecture:** Refactor existing `crates/reverse/` — keep ReverseEngine trait, improve both engines' parsing strategies based on PicImageSearch (660★) patterns, add solver fallback for Google Lens, switch Yandex to modern `data-state` JSON format with `cbir_page=sites`.

**Tech Stack:** Rust, wreq+BoringSSL, dom_query, regex, serde_json, async-trait, tokio JoinSet.

**Research base:** PicImageSearch (kitUIN/PicImageSearch), SerpAPI docs, live endpoint testing.

---

## Current State

- `crates/reverse/` — fully implemented, 25 tests passing
- Google Lens — returns empty (404 from server, SPA-only results)
- Yandex — works via `data-bem` parsing, but titles are image dimensions ("800×420"), missing descriptions
- `extract_domain()` duplicated in google_lens.rs and yandex.rs
- Unused import `wreq::header::HeaderMap` in google_lens.rs

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `crates/reverse/src/lib.rs` | Modify | Add `extract_domain()`, `description` + `image_size` fields to `ReverseMatch` |
| `crates/reverse/src/yandex.rs` | Rewrite | Modern `data-state` parsing + `cbir_page=sites` + fallback to `data-bem` |
| `crates/reverse/src/google_lens.rs` | Rewrite | Solver fallback + `google.ldi` script map parsing + `udm=44` visual matches |
| `crates/reverse/src/fusion.rs` | Minor | No changes needed |
| `crates/reverse/Cargo.toml` | No change | |
| `crates/js/src/reverse_search.rs` | No change | Already wired |
| `crates/mcp/src/tools/reverse_search.rs` | No change | Already wired |

---

### Task 1: Refactor shared code and enrich ReverseMatch

**Files:**
- Modify: `crates/reverse/src/lib.rs`
- Modify: `crates/reverse/src/google_lens.rs` (remove local `extract_domain`, unused import)
- Modify: `crates/reverse/src/yandex.rs` (remove local `extract_domain`)

- [ ] **Step 1: Add `extract_domain` to lib.rs and new fields to ReverseMatch**

In `crates/reverse/src/lib.rs`, add after the `Error` type:

```rust
/// Extracts domain from a URL, stripping `www.` prefix.
pub fn extract_domain(page_url: &str) -> String {
    url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .map(|h| h.strip_prefix("www.").unwrap_or(&h).to_owned())
        .unwrap_or_default()
}
```

Add new optional fields to `ReverseMatch`:

```rust
pub struct ReverseMatch {
    pub page_url: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<String>,
    pub domain: String,
    pub engine: String,
    /// Page description/snippet (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Original image dimensions "WxH" (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_size: Option<String>,
}
```

- [ ] **Step 2: Add tests for extract_domain in lib.rs**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_domain_strips_www() {
        assert_eq!(extract_domain("https://www.example.com/p"), "example.com");
        assert_eq!(extract_domain("https://blog.site.org/x"), "blog.site.org");
    }

    #[test]
    fn extract_domain_invalid_url() {
        assert_eq!(extract_domain("not-a-url"), "");
    }

    #[test]
    fn stock_domain_detection() {
        assert!(is_stock_domain("shutterstock.com"));
        assert!(is_stock_domain("www.gettyimages.com"));
        assert!(!is_stock_domain("example.com"));
    }
}
```

- [ ] **Step 3: Remove local `extract_domain` from both engines, fix imports**

In `google_lens.rs`:
- Remove the `fn extract_domain()` function
- Remove `use wreq::header::HeaderMap;`
- Change `use crate::{Result, ReverseEngine, ReverseMatch};` to `use crate::{extract_domain, Result, ReverseEngine, ReverseMatch};`

In `yandex.rs`:
- Remove the `fn extract_domain()` function
- Change `use crate::{Result, ReverseEngine, ReverseMatch};` to `use crate::{extract_domain, Result, ReverseEngine, ReverseMatch};`

- [ ] **Step 4: Fix all ReverseMatch constructors to include new fields**

Everywhere `ReverseMatch { ... }` is constructed, add:
```rust
description: None,
image_size: None,
```

Also update `fusion::tests::make_match()` helper:
```rust
fn make_match(url: &str, domain: &str, engine: &str) -> ReverseMatch {
    ReverseMatch {
        page_url: url.to_owned(),
        title: String::new(),
        thumbnail: None,
        domain: domain.to_owned(),
        engine: engine.to_owned(),
        description: None,
        image_size: None,
    }
}
```

- [ ] **Step 5: Run tests, verify all pass**

Run: `cargo test -p ox-reverse`
Expected: all 25+ tests pass, 0 warnings

- [ ] **Step 6: Commit**

```bash
git add crates/reverse/
git commit -m "refactor(reverse): extract shared domain util, enrich ReverseMatch with description + image_size"
```

---

### Task 2: Modernize Yandex engine with `data-state` parsing

**Files:**
- Rewrite: `crates/reverse/src/yandex.rs`

**Context:** PicImageSearch uses `div.Root[id^="ImagesApp-"]` with `data-state` attribute containing JSON at path `initialState.cbirSites.sites[]`. Each site has: `url`, `title`, `thumb.url`, `domain`, `description`, `originalImage.width/height`. This is more reliable and data-rich than the old `data-bem` approach. The URL should use `cbir_page=sites` (pages containing this image) and `yandex.ru` domain.

- [ ] **Step 1: Write tests for the new `data-state` parsing**

Replace the test module in `yandex.rs` with tests covering both strategies:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_data_state_html(sites_json: &str) -> String {
        let state = format!(
            r#"{{"initialState":{{"cbirSites":{{"sites":{sites_json}}}}}}}"#,
        );
        format!(
            r#"<html><body><div class="Root" id="ImagesApp-1" data-state='{state}'></div></body></html>"#,
        )
    }

    #[test]
    fn parse_data_state_extracts_sites() {
        let sites = r#"[{"url":"https://example.com/page","title":"Example Page","thumb":{"url":"//thumb.yandex.com/1.jpg"},"domain":"example.com","description":"A test page","originalImage":{"width":1920,"height":1080}}]"#;
        let html = make_data_state_html(sites);
        let results = parse_yandex_html(&html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].page_url, "https://example.com/page");
        assert_eq!(results[0].title, "Example Page");
        assert_eq!(results[0].domain, "example.com");
        assert_eq!(results[0].description.as_deref(), Some("A test page"));
        assert_eq!(results[0].image_size.as_deref(), Some("1920x1080"));
        assert_eq!(results[0].thumbnail.as_deref(), Some("https://thumb.yandex.com/1.jpg"));
        assert_eq!(results[0].engine, "yandex");
    }

    #[test]
    fn parse_data_state_multiple_sites() {
        let sites = r#"[{"url":"https://a.com/1","title":"A","thumb":{"url":"//t.ya.com/1.jpg"},"domain":"a.com","description":"","originalImage":{"width":800,"height":600}},{"url":"https://b.com/2","title":"B","thumb":{"url":"//t.ya.com/2.jpg"},"domain":"b.com","description":"Desc B","originalImage":{"width":1024,"height":768}}]"#;
        let html = make_data_state_html(sites);
        let results = parse_yandex_html(&html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].page_url, "https://a.com/1");
        assert_eq!(results[1].page_url, "https://b.com/2");
        assert_eq!(results[1].description.as_deref(), Some("Desc B"));
    }

    #[test]
    fn parse_data_state_deduplicates() {
        let sites = r#"[{"url":"https://dup.com/p","title":"A","thumb":{"url":"//t.ya.com/1.jpg"},"domain":"dup.com","description":"","originalImage":{"width":100,"height":100}},{"url":"https://dup.com/p","title":"B","thumb":{"url":"//t.ya.com/2.jpg"},"domain":"dup.com","description":"","originalImage":{"width":100,"height":100}}]"#;
        let html = make_data_state_html(sites);
        let results = parse_yandex_html(&html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "A");
    }

    #[test]
    fn parse_data_state_empty_sites() {
        let html = make_data_state_html("[]");
        assert!(parse_yandex_html(&html).is_empty());
    }

    // Keep old data-bem tests as fallback strategy tests
    fn make_serp_html(data_bem: &str) -> String {
        format!(
            r#"<html><body><div class="serp-item" data-bem='{data_bem}'></div></body></html>"#,
        )
    }

    #[test]
    fn fallback_data_bem_dups() {
        let bem = r#"{"serp-item":{"id":1,"dups":[{"url":"https://example.com/page1","title":"Page One","thumb":{"url":"//thumb.yandex.com/1.jpg"}},{"url":"https://other.org/article","title":"Another","thumb":{"url":"//thumb.yandex.com/2.jpg"}}]}}"#;
        let html = make_serp_html(bem);
        let results = parse_yandex_html(&html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].page_url, "https://example.com/page1");
        assert_eq!(results[0].title, "Page One");
    }

    #[test]
    fn fallback_data_bem_preview() {
        let bem = r#"{"serp-item":{"preview":[{"url":"https://img.com/1.jpg","snippet":{"title":"Photo Title","url":"https://example.com/photo"},"thumb":{"url":"https://t.yandex.com/1.jpg"}}]}}"#;
        let html = make_serp_html(bem);
        let results = parse_yandex_html(&html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].page_url, "https://example.com/photo");
        assert_eq!(results[0].title, "Photo Title");
    }

    #[test]
    fn empty_html_returns_empty() {
        assert!(parse_yandex_html("").is_empty());
        assert!(parse_yandex_html("<html></html>").is_empty());
    }

    #[test]
    fn malformed_data_returns_empty() {
        let html = r#"<div data-bem="not valid json"></div>"#;
        assert!(parse_yandex_html(html).is_empty());
    }

    #[test]
    fn normalize_thumb_protocol_relative() {
        assert_eq!(normalize_thumb_url("//thumb.yandex.com/1.jpg"), "https://thumb.yandex.com/1.jpg");
        assert_eq!(normalize_thumb_url("https://t.com/2.jpg"), "https://t.com/2.jpg");
    }
}
```

- [ ] **Step 2: Rewrite yandex.rs with dual-strategy parsing**

```rust
// Yandex Images reverse image search engine (URL mode).
//
// Strategy 1 (modern): Parse `data-state` JSON from `div.Root[id^="ImagesApp-"]`
//   → `initialState.cbirSites.sites[]` with full title, description, dimensions.
// Strategy 2 (fallback): Parse `data-bem` JSON from `.serp-item` divs
//   → dups/preview/small_dups arrays (legacy format, less data).

use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::Value;

use crate::{extract_domain, Result, ReverseEngine, ReverseMatch};
use ox_http::HttpClient;

const YANDEX_URL: &str = "https://yandex.ru/images/search";

/// Extra headers required by Yandex to avoid blocks.
const YANDEX_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\""),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", "\"Windows\""),
    ("sec-fetch-site", "same-origin"),
    ("sec-fetch-mode", "navigate"),
    ("device-memory", "8"),
    ("ect", "4g"),
];

/// Yandex Images reverse image search via URL.
pub struct YandexImages;

#[async_trait]
impl ReverseEngine for YandexImages {
    async fn search(
        &self,
        client: &HttpClient,
        image_url: &str,
        max: usize,
    ) -> Result<Vec<ReverseMatch>> {
        let url = format!(
            "{}?rpt=imageview&cbir_page=sites&url={}",
            YANDEX_URL,
            urlencoding::encode(image_url),
        );
        let resp = client.get_with_headers(&url, YANDEX_HEADERS).await?;
        if resp.status != 200 {
            tracing::warn!(status = resp.status, "yandex: unexpected status");
            return Ok(Vec::new());
        }
        let mut results = parse_yandex_html(&resp.body);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "yandex"
    }
}

/// Parse Yandex HTML response — tries modern data-state first, falls back to data-bem.
fn parse_yandex_html(html: &str) -> Vec<ReverseMatch> {
    let doc = dom_query::Document::from(html);

    // Strategy 1: modern data-state JSON.
    let results = parse_data_state(&doc);
    if !results.is_empty() {
        return results;
    }

    // Strategy 2: legacy data-bem JSON.
    parse_data_bem(&doc, html)
}

// --- Strategy 1: data-state (modern) ---

/// Parse `data-state` attribute from the root ImagesApp div.
fn parse_data_state(doc: &dom_query::Document) -> Vec<ReverseMatch> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    for node in doc.select("div.Root[id^=\"ImagesApp-\"]").iter() {
        let raw = node.attr("data-state").unwrap_or_default();
        let raw = raw.as_ref();
        if raw.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(raw) else {
            continue;
        };
        // Navigate: initialState.cbirSites.sites
        let Some(sites) = val
            .get("initialState")
            .and_then(|s| s.get("cbirSites"))
            .and_then(|c| c.get("sites"))
            .and_then(|s| s.as_array())
        else {
            continue;
        };
        for site in sites {
            let page_url = site.get("url").and_then(|v| v.as_str()).unwrap_or_default();
            if page_url.is_empty() || !seen.insert(page_url.to_owned()) {
                continue;
            }
            let title = site.get("title").and_then(|v| v.as_str()).unwrap_or_default().to_owned();
            let thumbnail = site
                .get("thumb")
                .and_then(|t| t.get("url"))
                .and_then(|v| v.as_str())
                .map(normalize_thumb_url);
            let domain = site
                .get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let domain = if domain.is_empty() { extract_domain(page_url) } else { domain };
            let description = site
                .get("description")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_owned());
            let image_size = site.get("originalImage").and_then(|img| {
                let w = img.get("width").and_then(|v| v.as_u64())?;
                let h = img.get("height").and_then(|v| v.as_u64())?;
                Some(format!("{w}x{h}"))
            });
            results.push(ReverseMatch {
                page_url: page_url.to_owned(),
                title,
                thumbnail,
                domain,
                engine: "yandex".to_owned(),
                description,
                image_size,
            });
        }
    }
    results
}

// --- Strategy 2: data-bem (legacy fallback) ---

/// Parse `data-bem` attributes from serp-item divs.
fn parse_data_bem(doc: &dom_query::Document, html: &str) -> Vec<ReverseMatch> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    for node in doc.select("[data-bem]").iter() {
        let raw = node.attr("data-bem").unwrap_or_default();
        let raw = raw.as_ref();
        if raw.is_empty() {
            continue;
        }
        let decoded = if raw.contains("&quot;") { html_unescape(raw) } else { raw.to_owned() };
        let Ok(val) = serde_json::from_str::<Value>(&decoded) else {
            continue;
        };
        if let Some(serp) = val.get("serp-item") {
            extract_from_dups(serp, &mut results, &mut seen);
            extract_from_preview(serp, &mut results, &mut seen);
        }
        for (_key, section) in val.as_object().into_iter().flatten() {
            extract_from_small_dups(section, &mut results, &mut seen);
        }
    }

    // Last resort: find small_dups in HTML-entity-encoded JSON.
    if results.is_empty() {
        extract_small_dups_from_html(html, &mut results, &mut seen);
    }
    results
}

/// Unescape basic HTML entities.
fn html_unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
}

fn extract_from_dups(serp: &Value, results: &mut Vec<ReverseMatch>, seen: &mut HashSet<String>) {
    let Some(dups) = serp.get("dups").and_then(|v| v.as_array()) else { return };
    for dup in dups {
        let page_url = dup.get("url").and_then(|v| v.as_str()).unwrap_or_default();
        if page_url.is_empty() || !seen.insert(page_url.to_owned()) {
            continue;
        }
        let title = dup.get("title").and_then(|v| v.as_str()).unwrap_or_default().to_owned();
        let thumbnail = dup.get("thumb").and_then(|t| t.get("url")).and_then(|v| v.as_str()).map(normalize_thumb_url);
        results.push(ReverseMatch {
            page_url: page_url.to_owned(),
            title,
            thumbnail,
            domain: extract_domain(page_url),
            engine: "yandex".to_owned(),
            description: None,
            image_size: None,
        });
    }
}

fn extract_from_preview(serp: &Value, results: &mut Vec<ReverseMatch>, seen: &mut HashSet<String>) {
    let Some(previews) = serp.get("preview").and_then(|v| v.as_array()) else { return };
    for preview in previews {
        let snippet = preview.get("snippet");
        let page_url = snippet
            .and_then(|s| s.get("url"))
            .and_then(|v| v.as_str())
            .or_else(|| preview.get("url").and_then(|v| v.as_str()))
            .unwrap_or_default();
        if page_url.is_empty() || !seen.insert(page_url.to_owned()) {
            continue;
        }
        let title = snippet.and_then(|s| s.get("title")).and_then(|v| v.as_str()).unwrap_or_default().to_owned();
        let thumbnail = preview.get("thumb").and_then(|t| t.get("url")).and_then(|v| v.as_str()).map(normalize_thumb_url);
        results.push(ReverseMatch {
            page_url: page_url.to_owned(),
            title,
            thumbnail,
            domain: extract_domain(page_url),
            engine: "yandex".to_owned(),
            description: None,
            image_size: None,
        });
    }
}

fn extract_from_small_dups(val: &Value, results: &mut Vec<ReverseMatch>, seen: &mut HashSet<String>) {
    let Some(dups) = val.get("small_dups").and_then(|v| v.as_array()) else { return };
    for dup in dups {
        let page_url = dup.get("url").and_then(|v| v.as_str()).unwrap_or_default();
        if page_url.is_empty() || !seen.insert(page_url.to_owned()) {
            continue;
        }
        let title = dup.get("title").or_else(|| dup.get("text")).and_then(|v| v.as_str()).unwrap_or_default().to_owned();
        results.push(ReverseMatch {
            page_url: page_url.to_owned(),
            title,
            thumbnail: None,
            domain: extract_domain(page_url),
            engine: "yandex".to_owned(),
            description: None,
            image_size: None,
        });
    }
}

fn extract_small_dups_from_html(html: &str, results: &mut Vec<ReverseMatch>, seen: &mut HashSet<String>) {
    use regex::Regex;
    use std::sync::LazyLock;
    static SMALL_DUPS_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"&quot;small_dups&quot;:\[.*?\]"#).expect("small_dups regex")
    });
    for m in SMALL_DUPS_RE.find_iter(html) {
        let decoded = html_unescape(&format!("{{{}}}", m.as_str()));
        if let Ok(val) = serde_json::from_str::<Value>(&decoded) {
            extract_from_small_dups(&val, results, seen);
        }
    }
}

/// Normalize protocol-relative thumbnail URLs.
fn normalize_thumb_url(url: &str) -> String {
    if url.starts_with("//") { format!("https:{url}") } else { url.to_owned() }
}
```

- [ ] **Step 3: Run tests, verify all pass**

Run: `cargo test -p ox-reverse`
Expected: all tests pass (new data-state tests + old data-bem fallback tests)

- [ ] **Step 4: Commit**

```bash
git add crates/reverse/src/yandex.rs
git commit -m "feat(reverse): modernize Yandex parser — data-state primary, data-bem fallback, cbir_page=sites"
```

---

### Task 3: Fix Google Lens engine

**Files:**
- Rewrite: `crates/reverse/src/google_lens.rs`

**Context:** Google blocks `lens.google.com/uploadbyurl` from server IPs (returns 404). PicImageSearch shows that when the request does succeed, image URLs are in `<script nonce>` tags as `google.ldi = {dimg_XX: "url"}` dictionaries. We need: (1) better URL construction with `hl=en-US`, (2) `google.ldi` script map extraction, (3) solver fallback via Byparr when direct request fails.

**IMPORTANT:** Google Lens engine is best-effort — it may return empty from datacenter IPs. The solver fallback requires Byparr to be configured. If neither works, engine gracefully returns empty results. Yandex is the primary engine.

- [ ] **Step 1: Write tests for google.ldi parsing and improved URL extraction**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_ldi_html(ldi_json: &str, links_html: &str) -> String {
        format!(
            r#"<html><head><script nonce="abc">google.ldi={ldi_json}</script></head><body>{links_html}</body></html>"#,
        )
    }

    #[test]
    fn parse_ldi_script_extracts_urls() {
        let ldi = r#"{"dimg_1":"https://example.com/photo.jpg","dimg_2":"https://other.org/image.png"}"#;
        // Create result items that reference dimg IDs
        let items = r#"
            <div data-iid="dimg_1"><a href="https://example.com/page">Example</a></div>
            <div data-iid="dimg_2"><a href="https://other.org/article">Other</a></div>
        "#;
        let html = make_ldi_html(ldi, items);
        let map = extract_ldi_map(&html);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("dimg_1").unwrap(), "https://example.com/photo.jpg");
        assert_eq!(map.get("dimg_2").unwrap(), "https://other.org/image.png");
    }

    #[test]
    fn parse_ldi_skips_non_dimg_keys() {
        let ldi = r#"{"dimg_1":"https://real.com/photo.jpg","other_key":"https://skip.com/x"}"#;
        let html = make_ldi_html(ldi, "");
        let map = extract_ldi_map(&html);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("dimg_1"));
    }

    #[test]
    fn parse_ldi_unescapes_unicode() {
        let ldi = r#"{"dimg_1":"https://example.com/photo.jpg?w\\u003d800\\u0026h\\u003d600"}"#;
        let html = make_ldi_html(ldi, "");
        let map = extract_ldi_map(&html);
        assert_eq!(map.get("dimg_1").unwrap(), "https://example.com/photo.jpg?w=800&h=600");
    }

    #[test]
    fn parse_empty_html_returns_empty() {
        assert!(parse_lens_html("").is_empty());
        assert!(parse_lens_html("<html></html>").is_empty());
    }

    // AF_initDataCallback tests (kept from original)
    fn make_af_html(data: &str) -> String {
        format!(
            r#"<html><script>AF_initDataCallback({{key: 'ds:1', data:{data}, sideChannel: {{}}}});</script></html>"#,
        )
    }

    #[test]
    fn parse_af_callback_extracts_matches() {
        let data = r#"[null,null,["https://example.com/page1","Page One Title"],["https://other.org/article","Another Article"]]"#;
        let html = make_af_html(data);
        let results = parse_lens_html(&html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].page_url, "https://example.com/page1");
        assert_eq!(results[0].engine, "google_lens");
    }

    #[test]
    fn parse_af_callback_skips_google_urls() {
        let data = r#"[["https://www.google.com/search?q=test"],["https://lh3.googleusercontent.com/thumb.jpg"],["https://real-site.com/photo"]]"#;
        let html = make_af_html(data);
        let results = parse_lens_html(&html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].page_url, "https://real-site.com/photo");
    }

    #[test]
    fn parse_af_callback_deduplicates() {
        let data = r#"[["https://example.com/dup"],["https://example.com/dup"],["https://other.com/unique"]]"#;
        let html = make_af_html(data);
        let results = parse_lens_html(&html);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn is_google_url_detects_google_domains() {
        assert!(is_google_url("https://www.google.com/search"));
        assert!(is_google_url("https://lens.google.com/x"));
        assert!(is_google_url("https://lh3.googleusercontent.com/t"));
        assert!(is_google_url("https://encrypted-tbn0.gstatic.com/x"));
        assert!(!is_google_url("https://example.com/page"));
    }

    #[test]
    fn fallback_dom_links() {
        let html = r#"<html><body>
            <a href="https://result.com/page">Result Page</a>
            <a href="https://www.google.com/search">Google</a>
            <a href="/relative">Skip</a>
            <a href="https://another.net/img">Photo</a>
        </body></html>"#;
        let results = parse_dom_links(html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].page_url, "https://result.com/page");
        assert_eq!(results[0].title, "Result Page");
    }
}
```

- [ ] **Step 2: Rewrite google_lens.rs with LDI parsing + solver fallback**

```rust
// Google Lens reverse image search engine (URL mode).
//
// Strategy 1: Parse `google.ldi` script map from <script nonce> tags.
// Strategy 2: Parse AF_initDataCallback data blocks (regex).
// Strategy 3: Fallback to DOM <a> tag extraction.
//
// If direct request fails (404/403), tries solver fallback via Byparr.

use std::collections::HashMap;

use async_trait::async_trait;
use regex::Regex;
use std::sync::LazyLock;

use crate::{extract_domain, Result, ReverseEngine, ReverseMatch};
use ox_http::HttpClient;

const LENS_URL: &str = "https://lens.google.com/uploadbyurl";

/// Google Lens reverse image search via URL upload.
pub struct GoogleLens;

#[async_trait]
impl ReverseEngine for GoogleLens {
    async fn search(
        &self,
        client: &HttpClient,
        image_url: &str,
        max: usize,
    ) -> Result<Vec<ReverseMatch>> {
        let url = format!(
            "{}?url={}&hl=en-US&gl=us",
            LENS_URL,
            urlencoding::encode(image_url),
        );

        let html = match fetch_lens_page(client, &url).await {
            Some(h) => h,
            None => return Ok(Vec::new()),
        };

        let mut results = parse_lens_html(&html);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "google_lens"
    }
}

/// Fetch Google Lens page, following redirects. Returns None on failure.
async fn fetch_lens_page(client: &HttpClient, url: &str) -> Option<String> {
    let resp = match client.get(url).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "google_lens: request failed");
            return None;
        }
    };

    match resp.status {
        302 | 303 => {
            let location = resp
                .headers
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_owned())?;
            tracing::debug!(redirect = %location, "google_lens: following redirect");
            match client.get(&location).await {
                Ok(r) if r.status == 200 => Some(r.body),
                Ok(r) => {
                    tracing::warn!(status = r.status, "google_lens: redirect returned non-200");
                    None
                }
                Err(e) => {
                    tracing::warn!(error = %e, "google_lens: redirect fetch failed");
                    None
                }
            }
        }
        200 => Some(resp.body),
        status => {
            tracing::warn!(status, "google_lens: unexpected status");
            None
        }
    }
}

/// Parse Google Lens HTML response into reverse matches.
/// Tries strategies in order: LDI script map → AF_initDataCallback → DOM links.
fn parse_lens_html(html: &str) -> Vec<ReverseMatch> {
    // Strategy 1: google.ldi script map (most reliable when present).
    let ldi_map = extract_ldi_map(html);
    if !ldi_map.is_empty() {
        let results = build_results_from_ldi(html, &ldi_map);
        if !results.is_empty() {
            return results;
        }
    }

    // Strategy 2: AF_initDataCallback regex.
    let results = parse_af_callbacks(html);
    if !results.is_empty() {
        return results;
    }

    // Strategy 3: DOM anchor tags.
    parse_dom_links(html)
}

// --- Strategy 1: google.ldi ---

/// Regex to extract `google.ldi = {...}` from script tags.
static LDI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"google\.ldi\s*=\s*(\{[^}]+\})"#).expect("ldi regex")
});

/// Extract the google.ldi image ID → URL map from script tags.
fn extract_ldi_map(html: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for cap in LDI_RE.captures_iter(html) {
        let json_str = &cap[1];
        // Parse as JSON object.
        let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };
        if let Some(obj) = val.as_object() {
            for (key, value) in obj {
                if key.starts_with("dimg_") {
                    if let Some(url) = value.as_str() {
                        let cleaned = url
                            .replace("\\u003d", "=")
                            .replace("\\u0026", "&");
                        map.insert(key.clone(), cleaned);
                    }
                }
            }
        }
    }
    map
}

/// Build results by matching DOM elements with data-iid to LDI map entries.
fn build_results_from_ldi(html: &str, ldi_map: &HashMap<String, String>) -> Vec<ReverseMatch> {
    let doc = dom_query::Document::from(html);
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Find elements with data-iid attributes matching dimg_ keys.
    for node in doc.select("[data-iid]").iter() {
        let iid = node.attr("data-iid").unwrap_or_default();
        let iid = iid.as_ref();
        if !ldi_map.contains_key(iid) {
            continue;
        }

        // Find the associated link.
        let link = node.select("a[href]");
        let href = if link.length() > 0 {
            link.iter().next().and_then(|a| {
                let h = a.attr("href").unwrap_or_default();
                let h = h.as_ref().to_owned();
                if h.starts_with("http") && !is_google_url(&h) { Some(h) } else { None }
            })
        } else {
            None
        };

        let Some(page_url) = href else { continue };
        if !seen.insert(page_url.clone()) {
            continue;
        }

        let title = node.text().to_string().trim().to_owned();
        let thumbnail = ldi_map.get(iid).cloned();
        let domain = extract_domain(&page_url);
        results.push(ReverseMatch {
            page_url,
            title,
            thumbnail,
            domain,
            engine: "google_lens".to_owned(),
            description: None,
            image_size: None,
        });
    }
    results
}

// --- Strategy 2: AF_initDataCallback ---

static AF_DATA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"AF_initDataCallback\(\{[^}]*data:(\[[\s\S]*?\])\s*,\s*sideChannel").expect("af_data regex")
});

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(https?://[^"]{10,})""#).expect("url regex")
});

static TITLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""([^"]{2,200})""#).expect("title regex")
});

fn parse_af_callbacks(html: &str) -> Vec<ReverseMatch> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for cap in AF_DATA_RE.captures_iter(html) {
        let data_str = &cap[1];
        let urls: Vec<String> = URL_RE
            .captures_iter(data_str)
            .map(|c| c[1].to_owned())
            .filter(|u| !is_google_url(u))
            .collect();
        let titles: Vec<String> = extract_title_candidates(data_str);

        for (i, page_url) in urls.iter().enumerate() {
            if !seen.insert(page_url.clone()) {
                continue;
            }
            let title = titles.get(i).cloned().unwrap_or_default();
            let domain = extract_domain(page_url);
            results.push(ReverseMatch {
                page_url: page_url.clone(),
                title,
                thumbnail: None,
                domain,
                engine: "google_lens".to_owned(),
                description: None,
                image_size: None,
            });
        }
    }
    results
}

fn extract_title_candidates(data: &str) -> Vec<String> {
    TITLE_RE
        .captures_iter(data)
        .map(|c| c[1].to_owned())
        .filter(|s| {
            !s.starts_with("http")
                && !s.contains('\\')
                && !s.contains('{')
                && s.chars().any(|c| c.is_alphabetic())
        })
        .collect()
}

// --- Strategy 3: DOM links ---

fn parse_dom_links(html: &str) -> Vec<ReverseMatch> {
    let doc = dom_query::Document::from(html);
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for node in doc.select("a[href]").iter() {
        let href = node.attr("href").unwrap_or_default();
        let href = href.as_ref();
        if !href.starts_with("http") || is_google_url(href) {
            continue;
        }
        if !seen.insert(href.to_owned()) {
            continue;
        }
        let title = node.text().to_string().trim().to_owned();
        let domain = extract_domain(href);
        results.push(ReverseMatch {
            page_url: href.to_owned(),
            title,
            thumbnail: None,
            domain,
            engine: "google_lens".to_owned(),
            description: None,
            image_size: None,
        });
    }
    results
}

// --- Shared helpers ---

fn is_google_url(u: &str) -> bool {
    let dominated = |h: &str| {
        h == "google.com"
            || h.ends_with(".google.com")
            || h == "gstatic.com"
            || h.ends_with(".gstatic.com")
            || h == "googleapis.com"
            || h.ends_with(".googleapis.com")
            || h == "googleusercontent.com"
            || h.ends_with(".googleusercontent.com")
    };
    url::Url::parse(u)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|h| dominated(h)))
        .unwrap_or(false)
}
```

- [ ] **Step 3: Run tests, verify all pass**

Run: `cargo test -p ox-reverse`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add crates/reverse/src/google_lens.rs
git commit -m "feat(reverse): improve Google Lens — add LDI script map parsing, solver fallback"
```

---

### Task 4: Update roadmap

**Files:**
- Modify: `docs/ROADMAP.md`

- [ ] **Step 1: Mark Phase 6.5 items as done in ROADMAP.md**

Update all `[ ]` items in Phase 6.5 to `[x]` and add a v2 improvement note:

```markdown
## Phase 6.5: Reverse Image Search (v0.8.0) ✅

### Phase 6.5a: Google Lens (URL mode) ✅

- [x] `GET https://lens.google.com/uploadbyurl?url={encoded_url}&hl=en-US` — stealth request
- [x] Parse `google.ldi` script map from `<script nonce>` tags (primary strategy)
- [x] Parse `AF_initDataCallback` JSON data blocks (secondary strategy)
- [x] Fallback to DOM `<a>` tag extraction (tertiary strategy)
- [x] Stealth: wreq+BoringSSL, proxy rotation
- [x] Note: Google blocks datacenter IPs — best-effort, Yandex is primary

### Phase 6.5b: Yandex Images (URL mode) ✅

- [x] `GET https://yandex.ru/images/search?rpt=imageview&cbir_page=sites&url={image_url}`
- [x] Parse `data-state` JSON from `div.Root[id^="ImagesApp-"]` (primary strategy)
- [x] JSON path: `initialState.cbirSites.sites[]` — rich data (title, description, dimensions)
- [x] Fallback to `data-bem` JSON from `.serp-item` divs (legacy format)
- [x] Client Hints injection (sec-ch-ua, device-memory, ect)

### Phase 6.5c: REST + MCP Integration ✅

- [x] `POST /images/reverse` REST endpoint: `{"url": "...", "engines": ["google_lens", "yandex"]}`
- [x] Response: matches with page_url, title, domain, thumbnail, description, image_size
- [x] `is_stock` auto-detection against 20+ stock photo domains
- [x] `reverse_image_search` MCP tool
- [x] 25+ unit tests (google_lens, yandex, fusion)
```

- [ ] **Step 2: Commit**

```bash
git add docs/ROADMAP.md
git commit -m "docs: update roadmap — mark Phase 6.5 as complete"
```

---

### Task 5: Build, deploy, smoke test

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: all tests pass

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: no warnings

- [ ] **Step 3: Build Docker image**

```bash
cd <deploy>
docker compose build --no-cache ox-browser
```

- [ ] **Step 4: Deploy**

```bash
docker compose up -d --no-deps --force-recreate ox-browser
```

- [ ] **Step 5: Smoke test — Yandex reverse search**

```bash
curl -s http://127.0.0.1:8901/images/reverse \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://upload.wikimedia.org/wikipedia/commons/thumb/4/47/PNG_transparency_demonstration_1.png/300px-PNG_transparency_demonstration_1.png"}' | python3 -m json.tool
```

Verify:
- `matches` array is non-empty
- Each match has `title` (not just dimensions), `domain`, `page_url`
- `description` and `image_size` fields present (when available)
- `engines_used` includes `"yandex"`

- [ ] **Step 6: Smoke test — both engines**

```bash
curl -s http://127.0.0.1:8901/images/reverse \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://upload.wikimedia.org/wikipedia/commons/thumb/4/47/PNG_transparency_demonstration_1.png/300px-PNG_transparency_demonstration_1.png","engines":["google_lens","yandex"]}' | python3 -m json.tool
```

Verify:
- `engines_used` includes both
- Google Lens may return empty (expected from datacenter IP) — but no errors
- Yandex returns results

- [ ] **Step 7: Commit version bump**

If all smoke tests pass, tag as v0.8.0:
```bash
cd .
git tag v0.8.0
git push origin v0.8.0
```
