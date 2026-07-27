# Output Denoising Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 5 output noise issues found during integration testing — SRI/supply-chain finding dedup, JSON-LD truncation, heading limits, script URL dedup.

**Architecture:** Targeted fixes in security (sri.rs, supply_chain.rs), intelligence (seo.rs, accessibility.rs), fingerprint.rs. No new files.

**Tech Stack:** Rust, existing crates.

---

### Task 1: Deduplicate SRI findings by domain

**Bug:** 64 identical "External script missing integrity attribute" findings for b.stripecdn.com. Should group by registrable domain.

**Files:**
- Modify: `crates/security/src/sri.rs:82-103`

**Step 1: Write test**

Add to sri.rs tests:
```rust
    #[test]
    fn test_findings_grouped_by_domain() {
        let html = concat!(
            r#"<script src="https://cdn.other.com/a.js"></script>"#,
            r#"<script src="https://cdn.other.com/b.js"></script>"#,
            r#"<script src="https://cdn.other.com/c.js"></script>"#,
            r#"<script src="https://cdn.third.com/x.js"></script>"#,
        );
        let r = analyze_sri(html, "https://www.example.com/page");
        assert_eq!(r.total_external_scripts, 4);
        // Should be 2 findings (one per domain), not 4
        assert_eq!(r.findings.len(), 2);
        assert!(r.findings.iter().any(|f| f.description.contains("cdn.other.com") && f.description.contains("3")));
        assert!(r.findings.iter().any(|f| f.description.contains("cdn.third.com")));
    }
```

**Step 2: Implement domain grouping**

After the script and style loops (after line 125), replace the per-resource findings with grouped findings. Change approach:

1. During the loops, instead of pushing individual findings, collect missing URLs into a `HashMap<String, Vec<String>>` keyed by registrable domain.
2. After both loops, generate one finding per domain.

Replace lines 82-125 logic with:

```rust
    let mut findings = Vec::new();
    let (mut ext_scripts, mut sri_scripts) = (0usize, 0usize);
    let (mut ext_styles, mut sri_styles) = (0usize, 0usize);
    // Group missing SRI by registrable domain
    let mut missing_by_domain: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for cap in script_re.captures_iter(html) {
        let attrs = &cap[1];
        if let Some(src_cap) = src_re.captures(attrs) {
            let url = &src_cap[1];
            if is_cross_origin(url, page_url) {
                ext_scripts += 1;
                if integrity_re.is_match(attrs) {
                    sri_scripts += 1;
                } else {
                    let domain = Url::parse(url)
                        .or_else(|_| Url::parse(&format!("https:{url}")))
                        .ok()
                        .and_then(|u| u.host_str().map(|h| {
                            registrable_domain(h).unwrap_or_else(|| h.to_string())
                        }))
                        .unwrap_or_else(|| "unknown".into());
                    *missing_by_domain.entry(domain).or_insert(0) += 1;
                }
            }
        }
    }

    for cap in style_re.captures_iter(html) {
        let attrs = &cap[1];
        if !rel_ss_re.is_match(attrs) {
            continue;
        }
        if let Some(href_cap) = href_re.captures(attrs) {
            let url = &href_cap[1];
            if is_cross_origin(url, page_url) {
                ext_styles += 1;
                if integrity_re.is_match(attrs) {
                    sri_styles += 1;
                } else {
                    let domain = Url::parse(url)
                        .or_else(|_| Url::parse(&format!("https:{url}")))
                        .ok()
                        .and_then(|u| u.host_str().map(|h| {
                            registrable_domain(h).unwrap_or_else(|| h.to_string())
                        }))
                        .unwrap_or_else(|| "unknown".into());
                    *missing_by_domain.entry(domain).or_insert(0) += 1;
                }
            }
        }
    }

    // Generate one finding per domain
    for (domain, count) in &missing_by_domain {
        let desc = if *count == 1 {
            format!("External resource from {domain} missing integrity attribute")
        } else {
            format!("{count} external resources from {domain} missing integrity attribute")
        };
        findings.push(SriFinding {
            resource: domain.clone(),
            description: desc,
            severity: Severity::Medium,
        });
    }
```

The rest of the function (score_modifier, severity upgrade) stays the same.

**Step 3: Run tests**

Run: `cd . && cargo test -p ox-security -- --nocapture`

Fix any broken tests — existing tests that check for single findings should still pass since 1 script from 1 domain = 1 finding.

**Step 4: Commit**

```bash
git add crates/security/src/sri.rs
git commit -m "fix(security): deduplicate SRI findings by domain"
```

---

### Task 2: Deduplicate supply chain findings by domain

**Bug:** 64 identical "Third-party script from b.stripecdn.com missing SRI" findings. Same dedup needed.

**Files:**
- Modify: `crates/security/src/supply_chain.rs:56-107`

**Step 1: Write test**

Add to supply_chain.rs tests:
```rust
    #[test]
    fn test_findings_grouped_by_domain() {
        let html = concat!(
            r#"<script src="https://cdn.other.com/a.js"></script>"#,
            r#"<script src="https://cdn.other.com/b.js"></script>"#,
            r#"<script src="https://cdn.other.com/c.js"></script>"#,
            r#"<script src="https://cdn.third.com/x.js"></script>"#,
        );
        let r = analyze_supply_chain(html, "example.com");
        // All 4 scripts still tracked individually
        assert_eq!(r.total_third_party, 4);
        // But findings grouped: 2 domains, not 4 scripts
        assert_eq!(r.findings.len(), 2);
        assert!(r.findings.iter().any(|f| f.description.contains("cdn.other.com") && f.description.contains("3")));
    }
```

**Step 2: Implement domain grouping**

Replace the per-script missing-SRI finding push (lines 92-98) with a `HashMap<String, usize>` collecting missing counts by domain, then generate findings after the loop.

In `analyze_supply_chain()`:

1. Add `let mut missing_sri_by_domain: HashMap<String, usize> = HashMap::new();` before the loop.
2. Replace lines 92-98 with:
```rust
        if !has_integrity {
            *missing_sri_by_domain.entry(domain.clone()).or_insert(0) += 1;
        }
```
3. After the loop (after line 107), add:
```rust
    for (domain, count) in &missing_sri_by_domain {
        let desc = if *count == 1 {
            format!("Third-party script from {domain} missing SRI integrity attribute")
        } else {
            format!("{count} third-party scripts from {domain} missing SRI integrity attribute")
        };
        findings.push(SupplyChainFinding {
            description: desc,
            severity: Severity::Medium,
        });
    }
```

Note: risky domain findings (lines 84-90) stay per-script — those are critical and should be individually visible.

**Step 3: Run tests**

Run: `cd . && cargo test -p ox-security -- --nocapture`

**Step 4: Commit**

```bash
git add crates/security/src/supply_chain.rs
git commit -m "fix(security): deduplicate supply chain SRI findings by domain"
```

---

### Task 3: Truncate JSON-LD raw content

**Bug:** `seo.json_ld[].raw` can be 43KB+ (piter.now), making the entire analyze response too large for MCP.

**Files:**
- Modify: `crates/intelligence/src/seo.rs:92-103`

**Step 1: Write test**

Add to seo.rs tests:
```rust
    #[test]
    fn jsonld_raw_truncated() {
        let big_json = format!(
            r#"{{"@context":"https://schema.org","@type":"Article","text":"{}"}}"#,
            "x".repeat(5000)
        );
        let html = format!(
            r#"<html><head><script type="application/ld+json">{big_json}</script></head></html>"#
        );
        let r = analyze(&html);
        assert_eq!(r.json_ld.len(), 1);
        assert_eq!(r.json_ld[0].schema_type, "Article");
        assert!(r.json_ld[0].raw.len() <= 2048 + 20, "raw should be truncated");
    }
```

**Step 2: Implement truncation**

In `analyze()`, modify the json_ld mapping (lines 92-103). After extracting `raw`, truncate it:

```rust
    let json_ld: Vec<JsonLd> = doc
        .select("script[type=\"application/ld+json\"]")
        .iter()
        .map(|n| {
            let raw_full = n.text().to_string();
            let schema_type = serde_json::from_str::<serde_json::Value>(&raw_full)
                .ok()
                .and_then(|v| {
                    v.get("@type").and_then(|t| t.as_str()).map(String::from)
                        .or_else(|| {
                            // Handle @graph arrays: extract first @type
                            v.get("@graph")
                                .and_then(|g| g.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|item| item.get("@type"))
                                .and_then(|t| t.as_str())
                                .map(String::from)
                        })
                })
                .unwrap_or_default();
            let raw = if raw_full.len() > 2048 {
                format!("{}... ({} bytes truncated)", &raw_full[..2048], raw_full.len() - 2048)
            } else {
                raw_full
            };
            JsonLd { schema_type, raw }
        })
        .collect();
```

Note: also improved `@type` extraction to handle `@graph` arrays (common pattern — Stripe, WordPress).

**Step 3: Run tests**

Run: `cd . && cargo test -p ox-intelligence -- --nocapture`

**Step 4: Commit**

```bash
git add crates/intelligence/src/seo.rs
git commit -m "fix(intelligence): truncate JSON-LD raw to 2KB, support @graph type extraction"
```

---

### Task 4: Limit headings output

**Bug:** `a11y.headings` can be 21KB+ on content-heavy pages (piter.now with hundreds of headings).

**Files:**
- Modify: `crates/intelligence/src/accessibility.rs:73-89`

**Step 1: Write test**

Add to accessibility.rs tests:
```rust
    #[test]
    fn headings_capped_at_50() {
        let headings_html: String = (0..100)
            .map(|i| format!("<h2>Heading {i}</h2>"))
            .collect();
        let html = format!("<html><body><h1>Main</h1>{headings_html}</body></html>");
        let r = analyze(&html);
        assert!(r.headings.len() <= 50, "got {} headings", r.headings.len());
        assert_eq!(r.h1_count, 1);
        // heading_skip should still be computed on full set
        assert!(!r.heading_skip);
    }
```

**Step 2: Implement cap**

In `analyze_headings()`, after collecting all headings (for scoring/skip detection), truncate the returned vector:

```rust
fn analyze_headings(doc: &Document) -> (Vec<HeadingInfo>, u32, bool) {
    let mut headings = Vec::new();
    for level in 1u8..=6 {
        for el in doc.select(&format!("h{level}")).iter() {
            headings.push(HeadingInfo { level, text: el.text().trim().to_string() });
        }
    }
    headings.sort_by_key(|h| h.level);

    let h1_count = headings.iter().filter(|h| h.level == 1).count() as u32;

    let mut levels: Vec<u8> = headings.iter().map(|h| h.level).collect();
    levels.sort_unstable();
    levels.dedup();
    let heading_skip = levels.windows(2).any(|w| w[1] > w[0] + 1);

    // Cap output to prevent bloated responses
    headings.truncate(50);

    (headings, h1_count, heading_skip)
}
```

The `headings.truncate(50)` is placed AFTER h1_count and heading_skip are computed on the full set, so scoring remains accurate.

**Step 3: Run tests**

Run: `cd . && cargo test -p ox-intelligence -- --nocapture`

**Step 4: Commit**

```bash
git add crates/intelligence/src/accessibility.rs
git commit -m "fix(intelligence): cap headings output at 50 to prevent response bloat"
```

---

### Task 5: Deduplicate script URLs in SRI

**Bug:** piter.now has `googletagmanager.com/gtag/js?id=G-P4848D418S` appearing twice in SRI findings — duplicate `<script>` tags in HTML.

**Files:**
- Modify: `crates/security/src/sri.rs` (already touched in Task 1)

This is implicitly fixed by Task 1's domain grouping — two scripts from the same domain collapse into one finding with count=2. No additional work needed.

However, the `third_party_scripts` list in supply_chain.rs should also dedup by URL. Add dedup:

**Step 1: Write test**

Add to supply_chain.rs tests:
```rust
    #[test]
    fn test_duplicate_script_url_deduped() {
        let html = concat!(
            r#"<script src="https://cdn.other.com/app.js"></script>"#,
            r#"<script src="https://cdn.other.com/app.js"></script>"#,
        );
        let r = analyze_supply_chain(html, "example.com");
        assert_eq!(r.total_third_party, 1, "duplicate URL should be counted once");
        assert_eq!(r.third_party_scripts.len(), 1);
    }
```

**Step 2: Implement URL dedup**

In `analyze_supply_chain()`, add a `HashSet<String>` to track seen URLs:

Before the loop (after line 65):
```rust
    let mut seen_urls = std::collections::HashSet::new();
```

At the start of the script loop body (after line 71):
```rust
        if !seen_urls.insert(url.to_string()) {
            continue; // skip duplicate script URL
        }
```

**Step 3: Run tests**

Run: `cd . && cargo test -p ox-security -- --nocapture`

**Step 4: Commit**

```bash
git add crates/security/src/supply_chain.rs
git commit -m "fix(security): deduplicate script URLs in supply chain analysis"
```

---

### Task 6: Build, deploy, verify

**Step 1: Run full test suite**

Run: `cd . && cargo test --workspace`

**Step 2: Build and deploy**

```bash
cd <deploy> && docker compose build --no-cache ox-browser && docker compose up -d --no-deps --force-recreate ox-browser
```

**Step 3: Verify SRI dedup (Stripe)**

```bash
curl -s -X POST http://127.0.0.1:8901/mcp \
  ... (use MCP security_scan on stripe.com)
```
Expected: ~2-3 SRI findings (per domain), NOT 64+

**Step 4: Verify JSON-LD truncation (piter.now)**

```bash
curl -s -X POST http://127.0.0.1:8901/mcp \
  ... (use MCP analyze on piter.now)
```
Expected: Response fits in MCP output (no file overflow), json_ld[].raw ≤ 2KB

**Step 5: Verify headings cap**

Expected: headings array ≤ 50 items for piter.now
