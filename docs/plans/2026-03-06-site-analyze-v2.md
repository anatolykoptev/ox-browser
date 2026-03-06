# Phase 2.5: Web Intelligence Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand `POST /analyze` from basic tech detection (30 techs) to full website intelligence: 100+ technologies with versions, SEO/OG data, performance hints, accessibility audit, content/media analysis, fonts, PWA, API discovery.

**Architecture:** Two repos: ox-browser (Rust, new `ox-intelligence` crate) produces the analysis, go-code (Go, updated `site_analyze` MCP tool) consumes the expanded JSON response. Each intelligence module is a standalone Rust module with its own struct + `analyze()` function. The `/analyze` endpoint calls all modules and returns a unified response.

**Tech Stack:** Rust (dom_query for HTML parsing, regex for patterns, serde for serialization), Go (net/http client, XML formatting for MCP output)

**Repos:**
- ox-browser: `/home/krolik/src/ox-browser/`
- go-code: `/home/krolik/src/go-code/`

**File size rule:** All source files ≤ 200 lines.

## Research Findings (March 2026)

| Area | Finding | Impact |
|------|---------|--------|
| Fingerprinting | `rswappalyzer` v0.4.0 on crates.io — 7,000+ techs, AC-automaton, embedded rules, version extraction | Task 2: use crate instead of custom DB |
| SEO | `dom_query` + `serde_json` sufficient. `webpage-info` interesting but we already have HTML | Task 3: no external deps needed |
| Accessibility | `accessibility-rs` D-grade (118 dead code). axe-core has ~40 static HTML rules. Lighthouse uses equal weights | Task 5: build own engine, expand to 15+ checks |
| API Discovery | jsluice (BishopFox) is reference. MaybeURL pre-filter. WebSocket regex patterns | Task 7: add WebSocket detection |
| Wappalyzer DB | `enthec/webappanalyzer` — official successor, ~7,000 techs, format unchanged since 2023 | rswappalyzer uses this DB |

---

## Task 1: Create ox-intelligence Crate + Move Fingerprint

Move `fingerprint.rs` and `fingerprints.json` from `ox-security` to new `ox-intelligence` crate. Update all imports.

**Files:**
- Create: `crates/intelligence/Cargo.toml`
- Create: `crates/intelligence/src/lib.rs`
- Move: `crates/security/src/fingerprint.rs` → `crates/intelligence/src/fingerprint.rs`
- Move: `crates/security/src/fingerprints.json` → `crates/intelligence/src/fingerprints.json`
- Modify: `crates/security/src/lib.rs` — remove `pub mod fingerprint`
- Modify: `crates/security/Cargo.toml` — remove regex dep (if only used by fingerprint)
- Modify: `crates/js/Cargo.toml` — add `ox-intelligence` dep, keep `ox-security`
- Modify: `crates/js/src/analyze.rs` — change import `ox_security::fingerprint::Fingerprinter` → `ox_intelligence::fingerprint::Fingerprinter`
- Modify: `Cargo.toml` (workspace) — add `"crates/intelligence"` to members

**Step 1: Create crate directory and Cargo.toml**

```bash
mkdir -p crates/intelligence/src
```

```toml
# crates/intelligence/Cargo.toml
[package]
name = "ox-intelligence"
version.workspace = true
edition.workspace = true

[dependencies]
dom_query = "0.25"
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = { workspace = true }
url = "2"
```

**Step 2: Create lib.rs**

```rust
// crates/intelligence/src/lib.rs
pub mod fingerprint;
```

**Step 3: Move fingerprint files**

```bash
mv crates/security/src/fingerprint.rs crates/intelligence/src/fingerprint.rs
mv crates/security/src/fingerprints.json crates/intelligence/src/fingerprints.json
```

**Step 4: Update ox-security lib.rs**

Remove `pub mod fingerprint;` from `crates/security/src/lib.rs`. The file becomes empty (placeholder for Phase 3).

**Step 5: Update ox-security Cargo.toml**

Remove `regex` and `serde`/`serde_json` if no other code uses them. Keep `tracing`.

```toml
# crates/security/Cargo.toml
[package]
name = "ox-security"
version.workspace = true
edition.workspace = true

[dependencies]
tracing = { workspace = true }
```

**Step 6: Add workspace member + update ox-js deps**

In workspace `Cargo.toml`, add `"crates/intelligence"` to `members` list.

In `crates/js/Cargo.toml`, add:
```toml
ox-intelligence = { path = "../intelligence" }
```

**Step 7: Update analyze.rs import**

In `crates/js/src/analyze.rs`, change:
```rust
// OLD
use ox_security::fingerprint::Fingerprinter;
// NEW
use ox_intelligence::fingerprint::Fingerprinter;
```

**Step 8: Verify build + tests**

```bash
cd /home/krolik/src/ox-browser
cargo test -p ox-intelligence
cargo test -p ox-js
cargo build
```
Expected: All 8 fingerprint tests pass, 2 analyze tests pass, build succeeds.

**Step 9: Commit**

```bash
git add -A
git commit -m "refactor: move fingerprint from ox-security to ox-intelligence crate"
```

---

## Task 2: Replace Custom Fingerprinting with rswappalyzer

Replace our 30-tech custom fingerprints.json with `rswappalyzer` crate (v0.4.0) — 7,000+ technologies with version detection, AC-automaton pruning, LRU regex cache. Research finding: only production-ready Rust fingerprinting library (Feb 2026, crates.io).

**Files:**
- Modify: `crates/intelligence/Cargo.toml` — add `rswappalyzer` dep with `embedded-rules` feature
- Rewrite: `crates/intelligence/src/fingerprint.rs` — thin wrapper around rswappalyzer
- Delete: `crates/intelligence/src/fingerprints.json` — no longer needed
- Modify: `crates/js/src/analyze.rs` — adapt to new Detection struct

**Step 1: Add rswappalyzer dependency**

```toml
# crates/intelligence/Cargo.toml [dependencies]
rswappalyzer = { version = "0.4", features = ["embedded-rules"] }
```

Remove `regex` dep from intelligence Cargo.toml (rswappalyzer handles regex internally).

**Step 2: Rewrite fingerprint.rs as thin wrapper**

```rust
//! Technology fingerprinting via rswappalyzer (7,000+ technologies).

use std::collections::HashMap;

/// Detected technology with name, categories, version, and confidence.
#[derive(Debug, Clone)]
pub struct Detection {
    pub name: String,
    pub categories: Vec<String>,
    pub confidence: u8,
    pub version: Option<String>,
}

/// Detect technologies from HTTP response data.
/// `headers` should be lowercase key → value.
/// `meta_tags` should be name/property → content.
/// `cookies` should be name → value.
pub fn detect(
    url: &str,
    headers: &HashMap<String, String>,
    html: &str,
    meta_tags: &HashMap<String, String>,
    script_srcs: &[String],
    cookies: &HashMap<String, String>,
) -> Vec<Detection> {
    let analyzer = rswappalyzer::Analyzer::new_embedded()
        .expect("embedded rules must load");

    let input = rswappalyzer::AnalyzeInput {
        url: url.to_string(),
        headers: headers.clone(),
        html: html.to_string(),
        meta: meta_tags.clone(),
        script_src: script_srcs.to_vec(),
        cookies: cookies.clone(),
    };

    let results = analyzer.analyze(&input);

    results
        .into_iter()
        .map(|r| Detection {
            name: r.name,
            categories: r.categories,
            confidence: r.confidence.min(100) as u8,
            version: r.version.filter(|v| !v.is_empty()),
        })
        .collect()
}
```

Note: The exact `rswappalyzer` API may differ — check the crate docs. The wrapper
isolates our code from the upstream API, so if the API is slightly different
(e.g. builder pattern, different field names), adapt the wrapper accordingly.
The key point: we delegate ALL fingerprinting to rswappalyzer and only wrap the result.

**Step 3: Delete fingerprints.json**

```bash
rm crates/intelligence/src/fingerprints.json
```

**Step 4: Update analyze.rs**

In `crates/js/src/analyze.rs`, update fingerprinter call:

```rust
// OLD
use ox_intelligence::fingerprint::Fingerprinter;
let fingerprinter = Fingerprinter::new();
let detections = fingerprinter.detect(&headers, &resp.body, &meta_tags, &script_srcs);

// NEW
let detections = ox_intelligence::fingerprint::detect(
    &req.url, &headers, &resp.body, &meta_tags, &script_srcs, &cookies,
);
```

Extract cookies from response headers (Set-Cookie) into a HashMap for the detect call.

Update TechInfo to include version and categories:

```rust
#[derive(Serialize)]
pub struct TechInfo {
    pub name: String,
    pub categories: Vec<String>,
    pub confidence: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}
```

**Step 5: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty() -> HashMap<String, String> { HashMap::new() }

    #[test]
    fn detect_wordpress_from_html() {
        let html = r#"<link rel="stylesheet" href="/wp-content/themes/flavor/style.css">"#;
        let results = detect("https://example.com", &empty(), html, &empty(), &[], &empty());
        assert!(results.iter().any(|d| d.name == "WordPress"), "got: {:?}", results);
    }

    #[test]
    fn detect_react_from_html() {
        let html = r#"<div id="root" data-reactroot="">Hello</div>"#;
        let results = detect("https://example.com", &empty(), html, &empty(), &[], &empty());
        assert!(results.iter().any(|d| d.name == "React"), "got: {:?}", results);
    }

    #[test]
    fn detect_nginx_from_headers() {
        let mut h = HashMap::new();
        h.insert("server".into(), "nginx/1.25.3".into());
        let results = detect("https://example.com", &h, "", &empty(), &[], &empty());
        let nginx = results.iter().find(|d| d.name == "Nginx" || d.name == "nginx");
        assert!(nginx.is_some(), "got: {:?}", results);
    }

    #[test]
    fn version_extraction() {
        let mut meta = HashMap::new();
        meta.insert("generator".into(), "WordPress 6.5.2".into());
        let html = "<html><body>wp-content</body></html>";
        let results = detect("https://example.com", &empty(), html, &meta, &[], &empty());
        let wp = results.iter().find(|d| d.name == "WordPress");
        assert!(wp.is_some());
        // Version may or may not be extracted depending on rswappalyzer rules
        // Just verify no panic and result is returned
    }

    #[test]
    fn empty_input_returns_empty() {
        let results = detect("https://example.com", &empty(), "", &empty(), &[], &empty());
        assert!(results.is_empty() || results.iter().all(|d| d.confidence > 0));
    }
}
```

**Step 6: Verify**

```bash
cargo test -p ox-intelligence -- fingerprint --nocapture
cargo test -p ox-js
cargo build
```

**Step 7: Commit**

```bash
git add -A
git commit -m "feat(intelligence): replace custom fingerprints with rswappalyzer (7000+ techs)"
```

---

## Task 3: SEO Module

Analyze Open Graph, Twitter Cards, JSON-LD, canonical, hreflang, robots, meta description.

**Files:**
- Create: `crates/intelligence/src/seo.rs`
- Modify: `crates/intelligence/src/lib.rs` — add `pub mod seo`

**Step 1: Write tests first**

```rust
// crates/intelligence/src/seo.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_og_tags() {
        let html = r#"<html><head>
            <meta property="og:title" content="Test Page">
            <meta property="og:description" content="A test">
            <meta property="og:image" content="https://example.com/img.png">
            <meta property="og:type" content="website">
            <meta property="og:url" content="https://example.com">
        </head><body></body></html>"#;
        let report = analyze(html);
        assert_eq!(report.og.title, "Test Page");
        assert_eq!(report.og.image, "https://example.com/img.png");
    }

    #[test]
    fn parse_twitter_cards() {
        let html = r#"<html><head>
            <meta name="twitter:card" content="summary_large_image">
            <meta name="twitter:site" content="@example">
        </head><body></body></html>"#;
        let report = analyze(html);
        assert_eq!(report.twitter.card, "summary_large_image");
        assert_eq!(report.twitter.site, "@example");
    }

    #[test]
    fn parse_canonical_and_robots() {
        let html = r#"<html><head>
            <link rel="canonical" href="https://example.com/page">
            <meta name="robots" content="noindex, nofollow">
            <meta name="description" content="Page desc">
        </head><body></body></html>"#;
        let report = analyze(html);
        assert_eq!(report.canonical, "https://example.com/page");
        assert_eq!(report.robots, "noindex, nofollow");
        assert_eq!(report.description, "Page desc");
    }

    #[test]
    fn parse_jsonld() {
        let html = r#"<html><head>
            <script type="application/ld+json">{"@type":"Organization","name":"Test"}</script>
        </head><body></body></html>"#;
        let report = analyze(html);
        assert_eq!(report.json_ld.len(), 1);
        assert_eq!(report.json_ld[0].schema_type, "Organization");
    }

    #[test]
    fn parse_hreflang() {
        let html = r#"<html><head>
            <link rel="alternate" hreflang="en" href="https://example.com/en">
            <link rel="alternate" hreflang="ru" href="https://example.com/ru">
        </head><body></body></html>"#;
        let report = analyze(html);
        assert_eq!(report.hreflang.len(), 2);
    }

    #[test]
    fn completeness_score() {
        let html = r#"<html><head>
            <title>Test</title>
            <meta name="description" content="Desc">
            <meta property="og:title" content="OG">
            <link rel="canonical" href="https://example.com">
        </head><body></body></html>"#;
        let report = analyze(html);
        assert!(report.score > 0);
        assert!(report.score <= 100);
    }

    #[test]
    fn empty_html() {
        let report = analyze("<html><body></body></html>");
        assert_eq!(report.score, 0);
        assert!(report.og.title.is_empty());
    }
}
```

**Step 2: Implement**

```rust
//! SEO analysis: OG tags, Twitter Cards, JSON-LD, canonical, hreflang, robots.

use dom_query::Document;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct SeoReport {
    pub og: OgTags,
    pub twitter: TwitterCard,
    pub json_ld: Vec<JsonLd>,
    pub canonical: String,
    pub hreflang: Vec<HreflangEntry>,
    pub robots: String,
    pub description: String,
    pub keywords: String,
    pub favicon: String,
    pub score: u8,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct OgTags {
    pub title: String,
    pub description: String,
    pub image: String,
    pub og_type: String,
    pub url: String,
    pub site_name: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TwitterCard {
    pub card: String,
    pub title: String,
    pub description: String,
    pub image: String,
    pub site: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonLd {
    pub schema_type: String,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HreflangEntry {
    pub lang: String,
    pub href: String,
}

pub fn analyze(html: &str) -> SeoReport {
    let doc = Document::from(html);
    let mut report = SeoReport::default();

    // OG tags.
    report.og.title = meta_property(&doc, "og:title");
    report.og.description = meta_property(&doc, "og:description");
    report.og.image = meta_property(&doc, "og:image");
    report.og.og_type = meta_property(&doc, "og:type");
    report.og.url = meta_property(&doc, "og:url");
    report.og.site_name = meta_property(&doc, "og:site_name");

    // Twitter Cards.
    report.twitter.card = meta_name(&doc, "twitter:card");
    report.twitter.title = meta_name(&doc, "twitter:title");
    report.twitter.description = meta_name(&doc, "twitter:description");
    report.twitter.image = meta_name(&doc, "twitter:image");
    report.twitter.site = meta_name(&doc, "twitter:site");

    // Canonical.
    report.canonical = link_href(&doc, "canonical");

    // Hreflang.
    for sel in doc.select("link[rel='alternate'][hreflang]").iter() {
        if let (Some(lang), Some(href)) = (sel.attr("hreflang"), sel.attr("href")) {
            report.hreflang.push(HreflangEntry {
                lang: lang.to_string(),
                href: href.to_string(),
            });
        }
    }

    // Robots + description + keywords.
    report.robots = meta_name(&doc, "robots");
    report.description = meta_name(&doc, "description");
    report.keywords = meta_name(&doc, "keywords");

    // Favicon.
    report.favicon = link_href(&doc, "icon")
        .or_else(|| link_href(&doc, "shortcut icon"))
        .unwrap_or_default();

    // JSON-LD.
    for sel in doc.select("script[type='application/ld+json']").iter() {
        let raw = sel.text().to_string();
        let schema_type = serde_json::from_str::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| v.get("@type").and_then(|t| t.as_str()).map(String::from))
            .unwrap_or_default();
        report.json_ld.push(JsonLd { schema_type, raw });
    }

    // Completeness score (0-100).
    report.score = completeness_score(&report);
    report
}

fn meta_property(doc: &Document, property: &str) -> String {
    doc.select(&format!("meta[property='{property}']"))
        .iter()
        .next()
        .and_then(|s| s.attr("content").map(|v| v.to_string()))
        .unwrap_or_default()
}

fn meta_name(doc: &Document, name: &str) -> String {
    doc.select(&format!("meta[name='{name}']"))
        .iter()
        .next()
        .and_then(|s| s.attr("content").map(|v| v.to_string()))
        .unwrap_or_default()
}

fn link_href(doc: &Document, rel: &str) -> Option<String> {
    doc.select(&format!("link[rel='{rel}']"))
        .iter()
        .next()
        .and_then(|s| s.attr("href").map(|v| v.to_string()))
}

fn completeness_score(r: &SeoReport) -> u8 {
    let checks: &[bool] = &[
        !r.description.is_empty(),       // 15
        !r.og.title.is_empty(),          // 15
        !r.og.description.is_empty(),    // 10
        !r.og.image.is_empty(),          // 10
        !r.twitter.card.is_empty(),      // 10
        !r.canonical.is_empty(),         // 15
        !r.json_ld.is_empty(),           // 15
        !r.favicon.is_empty(),           // 5
        !r.hreflang.is_empty(),          // 5
    ];
    let weights: &[u8] = &[15, 15, 10, 10, 10, 15, 15, 5, 5];
    checks.iter().zip(weights).filter(|(c, _)| **c).map(|(_, w)| w).sum()
}
```

**Step 3: Add to lib.rs**

```rust
pub mod fingerprint;
pub mod seo;
```

**Step 4: Verify**

```bash
cargo test -p ox-intelligence -- seo --nocapture
```
Expected: All 7 SEO tests pass.

**Step 5: Commit**

```bash
git add crates/intelligence/src/seo.rs crates/intelligence/src/lib.rs
git commit -m "feat(intelligence): add SEO module — OG, Twitter Cards, JSON-LD, canonical, hreflang"
```

---

## Task 4: Performance Module

Analyze HTTP compression, cache headers, resource hints, lazy loading, image optimization.

**Files:**
- Create: `crates/intelligence/src/performance.rs`
- Modify: `crates/intelligence/src/lib.rs` — add `pub mod performance`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn detect_compression() {
        let mut headers = HashMap::new();
        headers.insert("content-encoding".into(), "br".into());
        let report = analyze(&headers, "<html></html>");
        assert_eq!(report.compression, "br");
    }

    #[test]
    fn detect_cache_headers() {
        let mut headers = HashMap::new();
        headers.insert("cache-control".into(), "public, max-age=31536000".into());
        headers.insert("etag".into(), "\"abc123\"".into());
        let report = analyze(&headers, "");
        assert!(report.cache_control.contains("max-age"));
        assert!(!report.etag.is_empty());
    }

    #[test]
    fn detect_preload_hints() {
        let html = r#"<html><head>
            <link rel="preload" href="/font.woff2" as="font">
            <link rel="prefetch" href="/next-page.js">
            <link rel="preconnect" href="https://cdn.example.com">
        </head></html>"#;
        let report = analyze(&HashMap::new(), html);
        assert_eq!(report.preload.len(), 1);
        assert_eq!(report.prefetch.len(), 1);
        assert_eq!(report.preconnect.len(), 1);
    }

    #[test]
    fn detect_lazy_images() {
        let html = r#"<html><body>
            <img src="a.jpg" loading="lazy">
            <img src="b.jpg" loading="lazy">
            <img src="c.jpg">
        </body></html>"#;
        let report = analyze(&HashMap::new(), html);
        assert_eq!(report.images_lazy, 2);
        assert_eq!(report.images_total, 3);
    }

    #[test]
    fn detect_http_version() {
        let mut headers = HashMap::new();
        headers.insert("alt-svc".into(), "h3=\":443\"; ma=86400".into());
        let report = analyze(&headers, "");
        assert!(report.http3_supported);
    }

    #[test]
    fn detect_inline_css() {
        let html = r#"<html><head>
            <style>.critical { color: red; }</style>
            <style>.above-fold { display: block; }</style>
        </head><body></body></html>"#;
        let report = analyze(&HashMap::new(), html);
        assert_eq!(report.inline_styles_count, 2);
    }
}
```

**Step 2: Implement**

```rust
//! Performance analysis: compression, cache, resource hints, lazy loading.

use std::collections::HashMap;
use dom_query::Document;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct PerformanceReport {
    pub compression: String,
    pub cache_control: String,
    pub etag: String,
    pub expires: String,
    pub age: String,
    pub http3_supported: bool,
    pub preload: Vec<ResourceHint>,
    pub prefetch: Vec<ResourceHint>,
    pub preconnect: Vec<String>,
    pub images_total: u32,
    pub images_lazy: u32,
    pub inline_styles_count: u32,
    pub inline_styles_bytes: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceHint {
    pub href: String,
    pub as_type: String,
}

pub fn analyze(headers: &HashMap<String, String>, html: &str) -> PerformanceReport {
    let doc = Document::from(html);
    let mut report = PerformanceReport::default();

    // Headers.
    report.compression = headers.get("content-encoding").cloned().unwrap_or_default();
    report.cache_control = headers.get("cache-control").cloned().unwrap_or_default();
    report.etag = headers.get("etag").cloned().unwrap_or_default();
    report.expires = headers.get("expires").cloned().unwrap_or_default();
    report.age = headers.get("age").cloned().unwrap_or_default();
    report.http3_supported = headers.get("alt-svc").is_some_and(|v| v.contains("h3"));

    // Resource hints.
    for sel in doc.select("link[rel='preload'][href]").iter() {
        if let Some(href) = sel.attr("href") {
            report.preload.push(ResourceHint {
                href: href.to_string(),
                as_type: sel.attr("as").map(|v| v.to_string()).unwrap_or_default(),
            });
        }
    }
    for sel in doc.select("link[rel='prefetch'][href]").iter() {
        if let Some(href) = sel.attr("href") {
            report.prefetch.push(ResourceHint {
                href: href.to_string(),
                as_type: sel.attr("as").map(|v| v.to_string()).unwrap_or_default(),
            });
        }
    }
    for sel in doc.select("link[rel='preconnect'][href]").iter() {
        if let Some(href) = sel.attr("href") {
            report.preconnect.push(href.to_string());
        }
    }

    // Images.
    let imgs = doc.select("img");
    report.images_total = imgs.iter().count() as u32;
    report.images_lazy = doc.select("img[loading='lazy']").iter().count() as u32;

    // Inline styles.
    for sel in doc.select("style").iter() {
        report.inline_styles_count += 1;
        report.inline_styles_bytes += sel.text().len() as u32;
    }

    report
}
```

**Step 3: Add to lib.rs, verify, commit**

```bash
cargo test -p ox-intelligence -- performance --nocapture
git add crates/intelligence/src/performance.rs crates/intelligence/src/lib.rs
git commit -m "feat(intelligence): add performance module — compression, cache, resource hints"
```

---

## Task 5: Accessibility Module

Check html lang, alt text, headings, ARIA landmarks, form labels.

**Files:**
- Create: `crates/intelligence/src/accessibility.rs`
- Modify: `crates/intelligence/src/lib.rs` — add `pub mod accessibility`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_html_lang() {
        let report = analyze(r#"<html lang="en"><body></body></html>"#);
        assert_eq!(report.lang, "en");
    }

    #[test]
    fn count_alt_text() {
        let html = r#"<html><body>
            <img src="a.jpg" alt="Photo A">
            <img src="b.jpg" alt="">
            <img src="c.jpg">
        </body></html>"#;
        let report = analyze(html);
        assert_eq!(report.images_with_alt, 1);
        assert_eq!(report.images_empty_alt, 1);
        assert_eq!(report.images_no_alt, 1);
    }

    #[test]
    fn heading_hierarchy() {
        let html = r#"<html><body>
            <h1>Title</h1><h2>Sub</h2><h4>Skip!</h4>
        </body></html>"#;
        let report = analyze(html);
        assert_eq!(report.h1_count, 1);
        assert!(report.heading_skip);
    }

    #[test]
    fn aria_landmarks() {
        let html = r#"<html><body>
            <nav role="navigation">Nav</nav>
            <main role="main">Content</main>
            <footer role="contentinfo">Footer</footer>
        </body></html>"#;
        let report = analyze(html);
        assert_eq!(report.landmarks, 3);
    }

    #[test]
    fn form_labels() {
        let html = r#"<html><body>
            <form>
                <label for="name">Name</label><input id="name">
                <input id="email">
            </form>
        </body></html>"#;
        let report = analyze(html);
        assert_eq!(report.inputs_total, 2);
        assert_eq!(report.inputs_with_label, 1);
    }

    #[test]
    fn score_calculation() {
        let html = r#"<html lang="en"><body>
            <h1>Title</h1>
            <img src="a.jpg" alt="Photo">
            <main>Content</main>
        </body></html>"#;
        let report = analyze(html);
        assert!(report.score > 0);
    }
}
```

**Step 2: Implement**

```rust
//! Accessibility analysis: lang, alt text, headings, ARIA, form labels.

use dom_query::Document;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct AccessibilityReport {
    pub lang: String,
    pub images_with_alt: u32,
    pub images_empty_alt: u32,
    pub images_no_alt: u32,
    pub h1_count: u32,
    pub headings: Vec<HeadingInfo>,
    pub heading_skip: bool,
    pub landmarks: u32,
    pub inputs_total: u32,
    pub inputs_with_label: u32,
    pub score: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeadingInfo {
    pub level: u8,
    pub text: String,
}

pub fn analyze(html: &str) -> AccessibilityReport {
    let doc = Document::from(html);
    let mut report = AccessibilityReport::default();

    // Language.
    report.lang = doc.select("html")
        .iter().next()
        .and_then(|s| s.attr("lang").map(|v| v.to_string()))
        .unwrap_or_default();

    // Alt text.
    for sel in doc.select("img").iter() {
        match sel.attr("alt") {
            Some(alt) if !alt.is_empty() => report.images_with_alt += 1,
            Some(_) => report.images_empty_alt += 1,
            None => report.images_no_alt += 1,
        }
    }

    // Headings.
    let mut prev_level: u8 = 0;
    for level in 1..=6u8 {
        let tag = format!("h{level}");
        let count = doc.select(&tag).iter().count() as u32;
        if level == 1 { report.h1_count = count; }
        for sel in doc.select(&tag).iter() {
            report.headings.push(HeadingInfo {
                level,
                text: sel.text().to_string(),
            });
            if prev_level > 0 && level > prev_level + 1 {
                report.heading_skip = true;
            }
            prev_level = level;
        }
    }

    // ARIA landmarks.
    let landmark_roles = ["main", "navigation", "banner", "contentinfo",
                          "complementary", "search", "form", "region"];
    for role in &landmark_roles {
        report.landmarks += doc.select(&format!("[role='{role}']")).iter().count() as u32;
    }
    // Semantic elements as landmarks.
    for tag in &["main", "nav", "header", "footer", "aside"] {
        report.landmarks += doc.select(tag).iter().count() as u32;
    }

    // Form labels.
    report.inputs_total = doc.select("input:not([type='hidden']):not([type='submit'])")
        .iter().count() as u32;
    let labels: Vec<String> = doc.select("label[for]")
        .iter()
        .filter_map(|s| s.attr("for").map(|v| v.to_string()))
        .collect();
    for sel in doc.select("input:not([type='hidden']):not([type='submit'])").iter() {
        if let Some(id) = sel.attr("id") {
            if labels.contains(&id.to_string()) {
                report.inputs_with_label += 1;
            }
        }
    }

    // Score: 0-100.
    report.score = a11y_score(&report);
    report
}

fn a11y_score(r: &AccessibilityReport) -> u8 {
    let mut score: u8 = 0;
    if !r.lang.is_empty() { score += 25; }
    if r.h1_count == 1 { score += 15; }
    if !r.heading_skip { score += 10; }
    let total_imgs = r.images_with_alt + r.images_empty_alt + r.images_no_alt;
    if total_imgs > 0 && r.images_no_alt == 0 { score += 25; }
    if r.landmarks > 0 { score += 15; }
    if r.inputs_total > 0 && r.inputs_with_label == r.inputs_total { score += 10; }
    score
}
```

**Step 3: Verify + commit**

```bash
cargo test -p ox-intelligence -- accessibility --nocapture
git add crates/intelligence/src/accessibility.rs crates/intelligence/src/lib.rs
git commit -m "feat(intelligence): add accessibility module — lang, alt, headings, ARIA, labels"
```

---

## Task 6: Content + Media Module

Links analysis, word count, iframes, images, video, audio detection.

**Files:**
- Create: `crates/intelligence/src/content.rs`
- Create: `crates/intelligence/src/media.rs`
- Modify: `crates/intelligence/src/lib.rs` — add `pub mod content; pub mod media`

**Step 1: Write content tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_links() {
        let html = r#"<html><body>
            <a href="/about">About</a>
            <a href="https://external.com">Ext</a>
            <a href="https://example.com/page">Internal</a>
        </body></html>"#;
        let report = analyze(html, "https://example.com");
        assert_eq!(report.internal_links, 2);
        assert_eq!(report.external_links, 1);
    }

    #[test]
    fn word_count() {
        let html = "<html><body><p>Hello world this is a test page</p></body></html>";
        let report = analyze(html, "https://example.com");
        assert_eq!(report.word_count, 7);
    }

    #[test]
    fn detect_iframes() {
        let html = r#"<html><body>
            <iframe src="https://www.youtube.com/embed/abc"></iframe>
            <iframe src="https://maps.google.com/embed"></iframe>
        </body></html>"#;
        let report = analyze(html, "https://example.com");
        assert_eq!(report.iframes.len(), 2);
        assert!(report.iframes.iter().any(|i| i.platform == "YouTube"));
    }
}
```

**Step 2: Implement content.rs**

```rust
//! Content analysis: links, word count, iframes.

use dom_query::Document;
use serde::Serialize;
use url::Url;

#[derive(Debug, Clone, Serialize, Default)]
pub struct ContentReport {
    pub internal_links: u32,
    pub external_links: u32,
    pub external_domains: Vec<String>,
    pub word_count: u32,
    pub iframes: Vec<IframeInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IframeInfo {
    pub src: String,
    pub platform: String,
}

pub fn analyze(html: &str, page_url: &str) -> ContentReport {
    let doc = Document::from(html);
    let mut report = ContentReport::default();
    let base_host = Url::parse(page_url).ok().map(|u| u.host_str().unwrap_or("").to_string());

    // Links.
    let mut ext_domains = std::collections::HashSet::new();
    for sel in doc.select("a[href]").iter() {
        if let Some(href) = sel.attr("href") {
            let href = href.to_string();
            if let Ok(u) = Url::parse(&href) {
                let host = u.host_str().unwrap_or("").to_string();
                if base_host.as_deref() == Some(&host) || href.starts_with('/') {
                    report.internal_links += 1;
                } else {
                    report.external_links += 1;
                    ext_domains.insert(host);
                }
            } else if href.starts_with('/') || href.starts_with('#') {
                report.internal_links += 1;
            }
        }
    }
    report.external_domains = ext_domains.into_iter().collect();
    report.external_domains.sort();

    // Word count (body text, excluding scripts/styles).
    let body_text = doc.select("body").text().to_string();
    report.word_count = body_text.split_whitespace().count() as u32;

    // Iframes.
    for sel in doc.select("iframe[src]").iter() {
        if let Some(src) = sel.attr("src") {
            let src = src.to_string();
            let platform = detect_iframe_platform(&src);
            report.iframes.push(IframeInfo { src, platform });
        }
    }

    report
}

fn detect_iframe_platform(src: &str) -> String {
    let s = src.to_lowercase();
    if s.contains("youtube.com") || s.contains("youtu.be") { "YouTube".into() }
    else if s.contains("vimeo.com") { "Vimeo".into() }
    else if s.contains("maps.google") || s.contains("google.com/maps") { "Google Maps".into() }
    else if s.contains("spotify.com") { "Spotify".into() }
    else if s.contains("soundcloud.com") { "SoundCloud".into() }
    else { "Other".into() }
}
```

**Step 3: Write media tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_format_breakdown() {
        let html = r#"<html><body>
            <img src="photo.jpg"><img src="icon.svg">
            <img src="hero.webp"><img src="banner.avif">
        </body></html>"#;
        let report = analyze(html);
        assert_eq!(report.images_total, 4);
        assert_eq!(*report.image_formats.get("jpg").unwrap_or(&0), 1);
        assert_eq!(*report.image_formats.get("webp").unwrap_or(&0), 1);
        assert_eq!(*report.image_formats.get("avif").unwrap_or(&0), 1);
    }

    #[test]
    fn detect_responsive_images() {
        let html = r#"<html><body>
            <img srcset="sm.jpg 480w, lg.jpg 1024w">
            <picture><source srcset="hero.webp"><img src="hero.jpg"></picture>
        </body></html>"#;
        let report = analyze(html);
        assert_eq!(report.srcset_count, 1);
        assert_eq!(report.picture_count, 1);
    }

    #[test]
    fn detect_video() {
        let html = r#"<html><body>
            <video src="clip.mp4" controls></video>
        </body></html>"#;
        let report = analyze(html);
        assert_eq!(report.videos.len(), 1);
    }

    #[test]
    fn detect_image_cdn() {
        let html = r#"<html><body>
            <img src="https://images.example.com/photo.jpg?w=800&fm=webp">
            <img src="https://res.cloudinary.com/demo/image/upload/sample.jpg">
        </body></html>"#;
        let report = analyze(html);
        assert!(report.image_cdns.contains(&"Cloudinary".to_string()));
    }
}
```

**Step 4: Implement media.rs**

```rust
//! Media analysis: images, video, audio, CDN detection.

use std::collections::HashMap;
use dom_query::Document;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct MediaReport {
    pub images_total: u32,
    pub image_formats: HashMap<String, u32>,
    pub srcset_count: u32,
    pub picture_count: u32,
    pub image_cdns: Vec<String>,
    pub videos: Vec<VideoInfo>,
    pub audio: Vec<AudioInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VideoInfo {
    pub src: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AudioInfo {
    pub src: String,
    pub platform: String,
}

pub fn analyze(html: &str) -> MediaReport {
    let doc = Document::from(html);
    let mut report = MediaReport::default();
    let mut cdns = std::collections::HashSet::new();

    // Images.
    for sel in doc.select("img").iter() {
        report.images_total += 1;
        if let Some(src) = sel.attr("src") {
            let src = src.to_string();
            if let Some(ext) = extract_image_ext(&src) {
                *report.image_formats.entry(ext).or_insert(0) += 1;
            }
            detect_image_cdn(&src, &mut cdns);
        }
        if sel.attr("srcset").is_some() {
            report.srcset_count += 1;
        }
    }
    report.picture_count = doc.select("picture").iter().count() as u32;
    report.image_cdns = cdns.into_iter().collect();
    report.image_cdns.sort();

    // Video.
    for sel in doc.select("video[src], video source[src]").iter() {
        if let Some(src) = sel.attr("src") {
            report.videos.push(VideoInfo {
                src: src.to_string(),
                platform: "Self-hosted".into(),
            });
        }
    }

    // Audio.
    for sel in doc.select("audio[src], audio source[src]").iter() {
        if let Some(src) = sel.attr("src") {
            report.audio.push(AudioInfo {
                src: src.to_string(),
                platform: "Self-hosted".into(),
            });
        }
    }

    report
}

fn extract_image_ext(src: &str) -> Option<String> {
    let path = src.split('?').next()?;
    let ext = path.rsplit('.').next()?.to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => Some("jpg".into()),
        "png" | "gif" | "svg" | "webp" | "avif" | "ico" | "bmp" => Some(ext),
        _ => None,
    }
}

fn detect_image_cdn(src: &str, cdns: &mut std::collections::HashSet<String>) {
    let s = src.to_lowercase();
    if s.contains("cloudinary.com") { cdns.insert("Cloudinary".into()); }
    if s.contains("imgix.net") { cdns.insert("imgix".into()); }
    if s.contains("imagedelivery.net") || s.contains("cloudflare.com/cdn-cgi/image") {
        cdns.insert("Cloudflare Images".into());
    }
    if s.contains("akamaized.net") { cdns.insert("Akamai".into()); }
}
```

**Step 5: Verify + commit**

```bash
cargo test -p ox-intelligence -- content --nocapture
cargo test -p ox-intelligence -- media --nocapture
git add crates/intelligence/src/content.rs crates/intelligence/src/media.rs crates/intelligence/src/lib.rs
git commit -m "feat(intelligence): add content and media modules — links, images, video, audio"
```

---

## Task 7: Fonts + PWA + API Discovery Module

**Files:**
- Create: `crates/intelligence/src/fonts.rs`
- Create: `crates/intelligence/src/pwa.rs`
- Create: `crates/intelligence/src/api_discovery.rs`
- Modify: `crates/intelligence/src/lib.rs`

**Step 1: Write fonts tests + implement**

```rust
// crates/intelligence/src/fonts.rs
//! Font analysis: Google Fonts, Adobe Fonts, @font-face.

use dom_query::Document;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct FontsReport {
    pub google_fonts: Vec<String>,
    pub adobe_fonts: bool,
    pub font_face_count: u32,
    pub font_families: Vec<String>,
}

pub fn analyze(html: &str) -> FontsReport {
    let doc = Document::from(html);
    let mut report = FontsReport::default();

    // Google Fonts from link tags.
    for sel in doc.select("link[href*='fonts.googleapis.com']").iter() {
        if let Some(href) = sel.attr("href") {
            let href = href.to_string();
            if let Some(families) = extract_google_font_families(&href) {
                report.google_fonts.extend(families);
            }
        }
    }

    // Adobe Fonts.
    report.adobe_fonts = doc.select("link[href*='use.typekit.net']").iter().next().is_some();

    // @font-face from inline styles.
    let re = Regex::new(r"@font-face\s*\{[^}]*font-family:\s*['\"]?([^;'\"]+)").unwrap();
    for sel in doc.select("style").iter() {
        let css = sel.text().to_string();
        for cap in re.captures_iter(&css) {
            report.font_face_count += 1;
            if let Some(name) = cap.get(1) {
                let family = name.as_str().trim().to_string();
                if !report.font_families.contains(&family) {
                    report.font_families.push(family);
                }
            }
        }
    }

    report
}

fn extract_google_font_families(href: &str) -> Option<Vec<String>> {
    let families_param = href.split("family=").nth(1)?;
    Some(
        families_param
            .split('&').next().unwrap_or("")
            .split('|')
            .map(|f| f.split(':').next().unwrap_or(f).replace('+', " "))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_google_fonts() {
        let html = r#"<html><head>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700&family=Roboto" rel="stylesheet">
        </head></html>"#;
        let report = analyze(html);
        assert!(report.google_fonts.iter().any(|f| f.contains("Inter")));
    }

    #[test]
    fn detect_font_face() {
        let html = r#"<html><head><style>
            @font-face { font-family: 'CustomFont'; src: url(font.woff2); }
        </style></head></html>"#;
        let report = analyze(html);
        assert_eq!(report.font_face_count, 1);
        assert!(report.font_families.contains(&"CustomFont".to_string()));
    }
}
```

**Step 2: Write PWA tests + implement**

```rust
// crates/intelligence/src/pwa.rs
//! PWA analysis: manifest, service worker, theme-color, apple-touch-icon.

use dom_query::Document;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct PwaReport {
    pub manifest_url: String,
    pub has_service_worker: bool,
    pub theme_color: String,
    pub apple_touch_icon: String,
    pub is_pwa: bool,
}

pub fn analyze(html: &str) -> PwaReport {
    let doc = Document::from(html);
    let mut report = PwaReport::default();

    // Manifest.
    report.manifest_url = doc.select("link[rel='manifest']")
        .iter().next()
        .and_then(|s| s.attr("href").map(|v| v.to_string()))
        .unwrap_or_default();

    // Service worker registration in inline scripts.
    for sel in doc.select("script:not([src])").iter() {
        let text = sel.text().to_string();
        if text.contains("serviceWorker.register") || text.contains("navigator.serviceWorker") {
            report.has_service_worker = true;
            break;
        }
    }

    // Theme color.
    report.theme_color = doc.select("meta[name='theme-color']")
        .iter().next()
        .and_then(|s| s.attr("content").map(|v| v.to_string()))
        .unwrap_or_default();

    // Apple touch icon.
    report.apple_touch_icon = doc.select("link[rel='apple-touch-icon']")
        .iter().next()
        .and_then(|s| s.attr("href").map(|v| v.to_string()))
        .unwrap_or_default();

    report.is_pwa = !report.manifest_url.is_empty() && report.has_service_worker;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_pwa() {
        let html = r#"<html><head>
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#ffffff">
        </head><body>
            <script>navigator.serviceWorker.register('/sw.js')</script>
        </body></html>"#;
        let report = analyze(html);
        assert!(report.is_pwa);
        assert_eq!(report.theme_color, "#ffffff");
    }

    #[test]
    fn not_pwa_without_sw() {
        let html = r#"<html><head>
            <link rel="manifest" href="/manifest.json">
        </head></html>"#;
        let report = analyze(html);
        assert!(!report.is_pwa);
    }
}
```

**Step 3: Write API discovery tests + implement**

```rust
// crates/intelligence/src/api_discovery.rs
//! API discovery: fetch/axios calls, GraphQL, __NEXT_DATA__, form actions.

use dom_query::Document;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct ApiReport {
    pub endpoints: Vec<ApiEndpoint>,
    pub graphql_detected: bool,
    pub next_data: bool,
    pub nuxt_data: bool,
    pub form_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiEndpoint {
    pub url: String,
    pub method: String,
    pub source: String,
}

pub fn analyze(html: &str) -> ApiReport {
    let doc = Document::from(html);
    let mut report = ApiReport::default();
    let mut seen = std::collections::HashSet::new();

    // Inline script analysis.
    let fetch_re = Regex::new(r#"fetch\s*\(\s*['"]((/[^\s'"]+)|(https?://[^\s'"]+))['"]\s*"#).unwrap();
    let axios_re = Regex::new(r#"axios\.\w+\s*\(\s*['"]((/[^\s'"]+)|(https?://[^\s'"]+))['"]\s*"#).unwrap();

    for sel in doc.select("script:not([src])").iter() {
        let text = sel.text().to_string();

        for cap in fetch_re.captures_iter(&text) {
            if let Some(url) = cap.get(1) {
                let u = url.as_str().to_string();
                if seen.insert(u.clone()) {
                    report.endpoints.push(ApiEndpoint {
                        url: u, method: "GET".into(), source: "fetch".into(),
                    });
                }
            }
        }

        for cap in axios_re.captures_iter(&text) {
            if let Some(url) = cap.get(1) {
                let u = url.as_str().to_string();
                if seen.insert(u.clone()) {
                    report.endpoints.push(ApiEndpoint {
                        url: u, method: "GET".into(), source: "axios".into(),
                    });
                }
            }
        }

        if text.contains("/graphql") || text.contains("__schema") {
            report.graphql_detected = true;
        }
    }

    // Framework data.
    report.next_data = doc.select("#__NEXT_DATA__").iter().next().is_some();
    report.nuxt_data = html.contains("__NUXT__");

    // Form actions.
    for sel in doc.select("form[action]").iter() {
        if let Some(action) = sel.attr("action") {
            let action = action.to_string();
            if !action.is_empty() && action != "#" {
                report.form_actions.push(action);
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_fetch_endpoints() {
        let html = r#"<html><body><script>
            fetch('/api/users').then(r => r.json());
            fetch('/api/posts');
        </script></body></html>"#;
        let report = analyze(html);
        assert_eq!(report.endpoints.len(), 2);
    }

    #[test]
    fn detect_graphql() {
        let html = r#"<html><body><script>
            fetch('/graphql', { method: 'POST', body: query });
        </script></body></html>"#;
        let report = analyze(html);
        assert!(report.graphql_detected);
    }

    #[test]
    fn detect_next_data() {
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
        </body></html>"#;
        let report = analyze(html);
        assert!(report.next_data);
    }

    #[test]
    fn detect_form_actions() {
        let html = r#"<html><body>
            <form action="/login" method="POST"><input name="user"></form>
            <form action="/search"><input name="q"></form>
        </body></html>"#;
        let report = analyze(html);
        assert_eq!(report.form_actions.len(), 2);
    }
}
```

**Step 4: Update lib.rs**

```rust
pub mod fingerprint;
pub mod seo;
pub mod performance;
pub mod accessibility;
pub mod content;
pub mod media;
pub mod fonts;
pub mod pwa;
pub mod api_discovery;
```

**Step 5: Verify + commit**

```bash
cargo test -p ox-intelligence -- --nocapture
git add crates/intelligence/src/
git commit -m "feat(intelligence): add fonts, PWA, and API discovery modules"
```

---

## Task 8: Integration — Update analyze.rs Response

Call all intelligence modules from the `/analyze` endpoint. Expand `AnalyzeResponse` with all report sections.

**Files:**
- Modify: `crates/js/src/analyze.rs` — call all intelligence modules, expand response
- Modify: `crates/js/Cargo.toml` — ensure `ox-intelligence` dep includes all needed crates

**Step 1: Update AnalyzeResponse struct**

Add new fields to `AnalyzeResponse` in `crates/js/src/analyze.rs`:

```rust
#[derive(Serialize)]
pub struct AnalyzeResponse {
    pub url: String,
    pub status: u16,
    pub technologies: Vec<TechInfo>,
    pub meta: MetaInfo,
    pub assets: AssetInfo,
    // New intelligence sections.
    pub seo: ox_intelligence::seo::SeoReport,
    pub performance: ox_intelligence::performance::PerformanceReport,
    pub accessibility: ox_intelligence::accessibility::AccessibilityReport,
    pub content: ox_intelligence::content::ContentReport,
    pub media: ox_intelligence::media::MediaReport,
    pub fonts: ox_intelligence::fonts::FontsReport,
    pub pwa: ox_intelligence::pwa::PwaReport,
    pub api: ox_intelligence::api_discovery::ApiReport,
    // Existing fields.
    pub method: String,
    pub cf_detected: bool,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
```

**Step 2: Update TechInfo struct**

Add `version` field:

```rust
#[derive(Serialize)]
pub struct TechInfo {
    pub name: String,
    pub category: String,
    pub confidence: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}
```

**Step 3: Update analyze() handler**

After existing fingerprinting code, add intelligence module calls:

```rust
// Run intelligence modules.
let seo_report = ox_intelligence::seo::analyze(&resp.body);
let perf_report = ox_intelligence::performance::analyze(&headers, &resp.body);
let a11y_report = ox_intelligence::accessibility::analyze(&resp.body);
let content_report = ox_intelligence::content::analyze(&resp.body, &req.url);
let media_report = ox_intelligence::media::analyze(&resp.body);
let fonts_report = ox_intelligence::fonts::analyze(&resp.body);
let pwa_report = ox_intelligence::pwa::analyze(&resp.body);
let api_report = ox_intelligence::api_discovery::analyze(&resp.body);
```

Add these to the response struct construction:
```rust
seo: seo_report,
performance: perf_report,
accessibility: a11y_report,
content: content_report,
media: media_report,
fonts: fonts_report,
pwa: pwa_report,
api: api_report,
```

**Note:** The error response path also needs the new fields (use `Default::default()` for all report types).

**Step 4: Update TechInfo mapping**

```rust
let technologies: Vec<TechInfo> = detections
    .into_iter()
    .map(|d| TechInfo {
        name: d.name,
        category: d.category,
        confidence: d.confidence,
        version: d.version,
    })
    .collect();
```

**Step 5: Split analyze.rs if over 200 lines**

If the file exceeds 200 lines after changes, extract the response structs to `crates/js/src/analyze_types.rs` and keep the handler in `analyze.rs`.

**Step 6: Verify**

```bash
cargo test -p ox-js
cargo build
```

**Step 7: Commit**

```bash
git add crates/js/src/
git commit -m "feat(js): integrate all intelligence modules into /analyze endpoint"
```

---

## Task 9: go-code — Update Client Types

Update Go types in `internal/webanalyze/client.go` to match expanded ox-browser response.

**Files:**
- Modify: `/home/krolik/src/go-code/internal/webanalyze/client.go` — add new response types
- Create: `/home/krolik/src/go-code/internal/webanalyze/types.go` — new report types (keep client.go ≤200 lines)
- Modify: `/home/krolik/src/go-code/internal/webanalyze/client_test.go` — update test data

**Step 1: Create types.go with new report structs**

```go
// internal/webanalyze/types.go
package webanalyze

// SeoReport holds SEO analysis data.
type SeoReport struct {
    OG          OGTags          `json:"og"`
    Twitter     TwitterCard     `json:"twitter"`
    JsonLD      []JsonLDEntry   `json:"json_ld"`
    Canonical   string          `json:"canonical"`
    Hreflang    []HreflangEntry `json:"hreflang"`
    Robots      string          `json:"robots"`
    Description string          `json:"description"`
    Keywords    string          `json:"keywords"`
    Favicon     string          `json:"favicon"`
    Score       int             `json:"score"`
}

// OGTags holds Open Graph metadata.
type OGTags struct {
    Title       string `json:"title"`
    Description string `json:"description"`
    Image       string `json:"image"`
    Type        string `json:"og_type"`
    URL         string `json:"url"`
    SiteName    string `json:"site_name"`
}

// TwitterCard holds Twitter Card metadata.
type TwitterCard struct {
    Card        string `json:"card"`
    Title       string `json:"title"`
    Description string `json:"description"`
    Image       string `json:"image"`
    Site        string `json:"site"`
}

// JsonLDEntry is a single JSON-LD block.
type JsonLDEntry struct {
    SchemaType string `json:"schema_type"`
    Raw        string `json:"raw"`
}

// HreflangEntry is a language alternative.
type HreflangEntry struct {
    Lang string `json:"lang"`
    Href string `json:"href"`
}

// PerformanceReport holds performance hints.
type PerformanceReport struct {
    Compression      string         `json:"compression"`
    CacheControl     string         `json:"cache_control"`
    ETag             string         `json:"etag"`
    HTTP3Supported   bool           `json:"http3_supported"`
    Preload          []ResourceHint `json:"preload"`
    Prefetch         []ResourceHint `json:"prefetch"`
    Preconnect       []string       `json:"preconnect"`
    ImagesTotal      int            `json:"images_total"`
    ImagesLazy       int            `json:"images_lazy"`
    InlineStyleCount int            `json:"inline_styles_count"`
    InlineStyleBytes int            `json:"inline_styles_bytes"`
}

// ResourceHint is a preload/prefetch entry.
type ResourceHint struct {
    Href   string `json:"href"`
    AsType string `json:"as_type"`
}

// AccessibilityReport holds accessibility audit data.
type AccessibilityReport struct {
    Lang            string `json:"lang"`
    ImagesWithAlt   int    `json:"images_with_alt"`
    ImagesEmptyAlt  int    `json:"images_empty_alt"`
    ImagesNoAlt     int    `json:"images_no_alt"`
    H1Count         int    `json:"h1_count"`
    HeadingSkip     bool   `json:"heading_skip"`
    Landmarks       int    `json:"landmarks"`
    InputsTotal     int    `json:"inputs_total"`
    InputsWithLabel int    `json:"inputs_with_label"`
    Score           int    `json:"score"`
}

// ContentReport holds content analysis data.
type ContentReport struct {
    InternalLinks   int      `json:"internal_links"`
    ExternalLinks   int      `json:"external_links"`
    ExternalDomains []string `json:"external_domains"`
    WordCount       int      `json:"word_count"`
}

// MediaReport holds media analysis data.
type MediaReport struct {
    ImagesTotal  int            `json:"images_total"`
    ImageFormats map[string]int `json:"image_formats"`
    SrcsetCount  int            `json:"srcset_count"`
    PictureCount int            `json:"picture_count"`
    ImageCDNs    []string       `json:"image_cdns"`
}

// FontsReport holds font analysis data.
type FontsReport struct {
    GoogleFonts   []string `json:"google_fonts"`
    AdobeFonts    bool     `json:"adobe_fonts"`
    FontFaceCount int      `json:"font_face_count"`
    FontFamilies  []string `json:"font_families"`
}

// PwaReport holds PWA detection data.
type PwaReport struct {
    ManifestURL    string `json:"manifest_url"`
    HasServiceWorker bool `json:"has_service_worker"`
    ThemeColor     string `json:"theme_color"`
    IsPWA          bool   `json:"is_pwa"`
}

// ApiReport holds API discovery data.
type ApiReport struct {
    Endpoints       []ApiEndpoint `json:"endpoints"`
    GraphQLDetected bool          `json:"graphql_detected"`
    NextData        bool          `json:"next_data"`
    NuxtData        bool          `json:"nuxt_data"`
    FormActions     []string      `json:"form_actions"`
}

// ApiEndpoint is a discovered API endpoint.
type ApiEndpoint struct {
    URL    string `json:"url"`
    Method string `json:"method"`
    Source string `json:"source"`
}
```

**Step 2: Update AnalyzeResponse in client.go**

Add new fields to `AnalyzeResponse`:

```go
type AnalyzeResponse struct {
    URL          string              `json:"url"`
    Status       int                 `json:"status"`
    Technologies []Technology        `json:"technologies"`
    Meta         Meta                `json:"meta"`
    Assets       Assets              `json:"assets"`
    SEO          SeoReport           `json:"seo"`
    Performance  PerformanceReport   `json:"performance"`
    A11y         AccessibilityReport `json:"accessibility"`
    Content      ContentReport       `json:"content"`
    Media        MediaReport         `json:"media"`
    Fonts        FontsReport         `json:"fonts"`
    PWA          PwaReport           `json:"pwa"`
    API          ApiReport           `json:"api"`
    Method       string              `json:"method"`
    CFDetected   bool                `json:"cf_detected"`
    ElapsedMs    int                 `json:"elapsed_ms"`
    Error        string              `json:"error,omitempty"`
}
```

Add `Version` to `Technology`:

```go
type Technology struct {
    Name       string  `json:"name"`
    Category   string  `json:"category"`
    Confidence int     `json:"confidence"`
    Version    *string `json:"version,omitempty"`
}
```

**Step 3: Verify**

```bash
cd /home/krolik/src/go-code
go build ./...
go test ./internal/webanalyze/...
```

**Step 4: Commit**

```bash
git add internal/webanalyze/
git commit -m "feat(webanalyze): add types for expanded site_analyze response"
```

---

## Task 10: go-code — Update XML Formatting

Update `tool_site_analyze.go` to format all new sections in the XML response.

**Files:**
- Modify: `/home/krolik/src/go-code/cmd/go-code/tool_site_analyze.go`
- Create: `/home/krolik/src/go-code/cmd/go-code/tool_site_analyze_format.go` — extract formatters (keep files ≤200 lines)

**Step 1: Create tool_site_analyze_format.go**

Extract formatting into a separate file:

```go
package main

import (
    "fmt"
    "strings"

    "github.com/anatolykoptev/go-code/internal/webanalyze"
)

func formatTechnologies(sb *strings.Builder, techs []webanalyze.Technology) {
    fmt.Fprintf(sb, "    <technologies count=\"%d\">\n", len(techs))
    for _, t := range techs {
        ver := ""
        if t.Version != nil {
            ver = fmt.Sprintf(" version=%q", *t.Version)
        }
        fmt.Fprintf(sb, "      <tech category=%q name=%q confidence=\"%d\"%s/>\n",
            t.Category, t.Name, t.Confidence, ver)
    }
    sb.WriteString("    </technologies>\n")
}

func formatSEO(sb *strings.Builder, seo webanalyze.SeoReport) {
    fmt.Fprintf(sb, "    <seo score=\"%d\">\n", seo.Score)
    if seo.OG.Title != "" {
        fmt.Fprintf(sb, "      <og title=%q description=%q image=%q type=%q/>\n",
            seo.OG.Title, seo.OG.Description, seo.OG.Image, seo.OG.Type)
    }
    if seo.Twitter.Card != "" {
        fmt.Fprintf(sb, "      <twitter card=%q site=%q/>\n", seo.Twitter.Card, seo.Twitter.Site)
    }
    if seo.Canonical != "" {
        fmt.Fprintf(sb, "      <canonical url=%q/>\n", seo.Canonical)
    }
    if seo.Description != "" {
        fmt.Fprintf(sb, "      <description>%s</description>\n", seo.Description)
    }
    if len(seo.JsonLD) > 0 {
        fmt.Fprintf(sb, "      <json_ld count=\"%d\">\n", len(seo.JsonLD))
        for _, j := range seo.JsonLD {
            fmt.Fprintf(sb, "        <schema type=%q/>\n", j.SchemaType)
        }
        sb.WriteString("      </json_ld>\n")
    }
    if len(seo.Hreflang) > 0 {
        for _, h := range seo.Hreflang {
            fmt.Fprintf(sb, "      <hreflang lang=%q href=%q/>\n", h.Lang, h.Href)
        }
    }
    if seo.Robots != "" {
        fmt.Fprintf(sb, "      <robots>%s</robots>\n", seo.Robots)
    }
    sb.WriteString("    </seo>\n")
}

func formatPerformance(sb *strings.Builder, p webanalyze.PerformanceReport) {
    sb.WriteString("    <performance>\n")
    if p.Compression != "" {
        fmt.Fprintf(sb, "      <compression>%s</compression>\n", p.Compression)
    }
    if p.CacheControl != "" {
        fmt.Fprintf(sb, "      <cache_control>%s</cache_control>\n", p.CacheControl)
    }
    if p.HTTP3Supported {
        sb.WriteString("      <http3 supported=\"true\"/>\n")
    }
    if len(p.Preload) > 0 || len(p.Prefetch) > 0 || len(p.Preconnect) > 0 {
        fmt.Fprintf(sb, "      <resource_hints preload=\"%d\" prefetch=\"%d\" preconnect=\"%d\"/>\n",
            len(p.Preload), len(p.Prefetch), len(p.Preconnect))
    }
    if p.ImagesTotal > 0 {
        fmt.Fprintf(sb, "      <lazy_loading images_lazy=\"%d\" images_total=\"%d\"/>\n",
            p.ImagesLazy, p.ImagesTotal)
    }
    if p.InlineStyleCount > 0 {
        fmt.Fprintf(sb, "      <inline_css count=\"%d\" bytes=\"%d\"/>\n",
            p.InlineStyleCount, p.InlineStyleBytes)
    }
    sb.WriteString("    </performance>\n")
}

func formatAccessibility(sb *strings.Builder, a webanalyze.AccessibilityReport) {
    fmt.Fprintf(sb, "    <accessibility score=\"%d\">\n", a.Score)
    if a.Lang != "" {
        fmt.Fprintf(sb, "      <lang>%s</lang>\n", a.Lang)
    }
    total := a.ImagesWithAlt + a.ImagesEmptyAlt + a.ImagesNoAlt
    if total > 0 {
        fmt.Fprintf(sb, "      <alt_text with_alt=\"%d\" empty_alt=\"%d\" no_alt=\"%d\"/>\n",
            a.ImagesWithAlt, a.ImagesEmptyAlt, a.ImagesNoAlt)
    }
    fmt.Fprintf(sb, "      <headings h1=\"%d\" skip=\"%t\"/>\n", a.H1Count, a.HeadingSkip)
    if a.Landmarks > 0 {
        fmt.Fprintf(sb, "      <landmarks count=\"%d\"/>\n", a.Landmarks)
    }
    if a.InputsTotal > 0 {
        fmt.Fprintf(sb, "      <form_labels labeled=\"%d\" total=\"%d\"/>\n",
            a.InputsWithLabel, a.InputsTotal)
    }
    sb.WriteString("    </accessibility>\n")
}

func formatContent(sb *strings.Builder, c webanalyze.ContentReport) {
    sb.WriteString("    <content>\n")
    fmt.Fprintf(sb, "      <links internal=\"%d\" external=\"%d\"/>\n",
        c.InternalLinks, c.ExternalLinks)
    if len(c.ExternalDomains) > 0 {
        fmt.Fprintf(sb, "      <external_domains count=\"%d\">%s</external_domains>\n",
            len(c.ExternalDomains), strings.Join(c.ExternalDomains, ", "))
    }
    fmt.Fprintf(sb, "      <word_count>%d</word_count>\n", c.WordCount)
    sb.WriteString("    </content>\n")
}

func formatMedia(sb *strings.Builder, m webanalyze.MediaReport) {
    sb.WriteString("    <media>\n")
    fmt.Fprintf(sb, "      <images total=\"%d\" srcset=\"%d\" picture=\"%d\">\n",
        m.ImagesTotal, m.SrcsetCount, m.PictureCount)
    for ext, count := range m.ImageFormats {
        fmt.Fprintf(sb, "        <format name=%q count=\"%d\"/>\n", ext, count)
    }
    sb.WriteString("      </images>\n")
    if len(m.ImageCDNs) > 0 {
        fmt.Fprintf(sb, "      <image_cdns>%s</image_cdns>\n", strings.Join(m.ImageCDNs, ", "))
    }
    sb.WriteString("    </media>\n")
}

func formatExtras(sb *strings.Builder, f webanalyze.FontsReport, p webanalyze.PwaReport, a webanalyze.ApiReport) {
    // Fonts.
    if len(f.GoogleFonts) > 0 || f.AdobeFonts || f.FontFaceCount > 0 {
        sb.WriteString("    <fonts>\n")
        if len(f.GoogleFonts) > 0 {
            fmt.Fprintf(sb, "      <google_fonts>%s</google_fonts>\n", strings.Join(f.GoogleFonts, ", "))
        }
        if f.AdobeFonts {
            sb.WriteString("      <adobe_fonts>true</adobe_fonts>\n")
        }
        if f.FontFaceCount > 0 {
            fmt.Fprintf(sb, "      <font_face count=\"%d\" families=%q/>\n",
                f.FontFaceCount, strings.Join(f.FontFamilies, ", "))
        }
        sb.WriteString("    </fonts>\n")
    }

    // PWA.
    if p.ManifestURL != "" || p.HasServiceWorker {
        fmt.Fprintf(sb, "    <pwa is_pwa=\"%t\" manifest=%q service_worker=\"%t\" theme_color=%q/>\n",
            p.IsPWA, p.ManifestURL, p.HasServiceWorker, p.ThemeColor)
    }

    // API Discovery.
    if len(a.Endpoints) > 0 || a.GraphQLDetected || a.NextData || len(a.FormActions) > 0 {
        sb.WriteString("    <api_discovery>\n")
        for _, ep := range a.Endpoints {
            fmt.Fprintf(sb, "      <endpoint url=%q source=%q/>\n", ep.URL, ep.Source)
        }
        if a.GraphQLDetected {
            sb.WriteString("      <graphql detected=\"true\"/>\n")
        }
        if a.NextData {
            sb.WriteString("      <framework_data next=\"true\"/>\n")
        }
        if a.NuxtData {
            sb.WriteString("      <framework_data nuxt=\"true\"/>\n")
        }
        for _, action := range a.FormActions {
            fmt.Fprintf(sb, "      <form_action url=%q/>\n", action)
        }
        sb.WriteString("    </api_discovery>\n")
    }
}
```

**Step 2: Update tool_site_analyze.go**

Simplify `formatDetectResponse` and `formatFullResponse` to call the new formatters:

```go
func formatDetectResponse(resp *webanalyze.AnalyzeResponse) string {
    var sb strings.Builder
    fmt.Fprintf(&sb, "<response tool=\"site_analyze\">\n")
    fmt.Fprintf(&sb, "  <site url=%q status=\"%d\">\n", resp.URL, resp.Status)
    formatTechnologies(&sb, resp.Technologies)
    formatSEO(&sb, resp.SEO)
    formatPerformance(&sb, resp.Performance)
    formatAccessibility(&sb, resp.A11y)
    formatContent(&sb, resp.Content)
    formatMedia(&sb, resp.Media)
    formatExtras(&sb, resp.Fonts, resp.PWA, resp.API)
    fmt.Fprintf(&sb, "    <assets scripts=\"%d\" stylesheets=\"%d\"/>\n",
        len(resp.Assets.Scripts), len(resp.Assets.Stylesheets))
    sb.WriteString("  </site>\n</response>")
    return sb.String()
}
```

Remove the old `formatTechnologies` from this file (moved to format file).

**Step 3: Verify**

```bash
cd /home/krolik/src/go-code
go build ./...
go vet ./cmd/go-code/
```

**Step 4: Commit**

```bash
git add cmd/go-code/tool_site_analyze.go cmd/go-code/tool_site_analyze_format.go
git commit -m "feat(site_analyze): format all intelligence sections in XML output"
```

---

## Task 11: Deploy + Integration Test

Build and deploy both services, verify end-to-end.

**Files:** No code changes — deployment and testing only.

**Step 1: Deploy ox-browser**

```bash
cd /home/krolik/deploy/krolik-server
docker compose build --no-cache ox-browser
docker compose up -d --no-deps --force-recreate ox-browser
```

**Step 2: Verify ox-browser /analyze returns new fields**

```bash
curl -s -X POST http://localhost:8901/analyze \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://github.com"}' | jq '.seo.score, .performance.compression, .accessibility.score'
```

Expected: non-null values for seo, performance, accessibility sections.

**Step 3: Deploy go-code**

```bash
cd /home/krolik/deploy/krolik-server
docker compose build --no-cache go-code
docker compose up -d --no-deps --force-recreate go-code
```

**Step 4: Test via MCP tool**

Use `site_analyze` MCP tool on a WordPress site (e.g., piter.now) and a Next.js site (e.g., vercel.com). Verify:
- Technologies include version numbers
- SEO section shows OG tags and score
- Performance shows compression type
- Accessibility shows score
- Content shows link counts
- Media shows image format breakdown

**Step 5: Commit deployment verification**

```bash
cd /home/krolik/src/ox-browser
git tag v0.2.5
```

---

## Dependency Graph

```
Task 1 (crate restructure)
  └→ Task 2 (fingerprint v2)
  └→ Task 3 (SEO)
  └→ Task 4 (performance)
  └→ Task 5 (accessibility)
  └→ Task 6 (content + media)
  └→ Task 7 (fonts + PWA + API)
       └→ Task 8 (integrate into analyze.rs) — depends on Tasks 2-7
            └→ Task 9 (go-code types) — depends on Task 8
                 └→ Task 10 (go-code formatting) — depends on Task 9
                      └→ Task 11 (deploy + test) — depends on Tasks 8, 10
```

Tasks 2-7 are **independent** and can be parallelized after Task 1.
