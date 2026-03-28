# Site Audit v2 — Scoring Fixes + Richer Checks

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix misleading security scoring (30/100 with 0 findings), add modern performance checks (speculation rules, font preload, image formats), enrich accessibility detection (decorative images, skip links, reduced-motion), and add actionable fix snippets to audit findings.

**Architecture:** Incremental improvements to ox-intelligence and ox-security crates. Each task modifies one module, adds tests, and is independently deployable. No new crates or external dependencies.

**Tech Stack:** Rust, dom_query, ox-intelligence, ox-security, cargo test

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `crates/security/src/scoring/aggregate.rs` | Modify | Rebalance security score: cap CSP penalty, weight headers presence |
| `crates/security/src/scoring/mod.rs` | Modify | Add `normalize_score` for 0-100 mapping |
| `crates/intelligence/src/performance.rs` | Modify | Add speculation rules, font preload, image format checks |
| `crates/intelligence/src/accessibility.rs` | Modify | Add decorative images, skip link, reduced-motion checks |
| `crates/intelligence/src/audit/findings.rs` | Modify | Add fix snippets, enrich finding messages |
| `crates/intelligence/src/audit/tests.rs` | Modify | Tests for new scoring and findings |

---

### Task 1: Rebalance Security Scoring

**Problem:** CSP with `unsafe-inline` (style-src) returns score 0 from CSP evaluator. Combined with base 100 + CSP modifier 0 = 100, but then `unsafe-inline` in script-src returns -20, making final ~30. A site with ALL headers correct + CSP present should score ≥ 60.

**Root cause in `crates/security/src/scoring/aggregate.rs`:** `compute_score` starts at 100 and applies CSP score as additive modifier. CSP score of -20 (unsafe-inline without nonce) wipes 20 points, plus style-src unsafe-inline returns 0 (no bonus). The problem is that missing CSP = -25 and bad CSP ≈ -20, so having CSP is barely better than not having it.

**Files:**
- Modify: `crates/security/src/scoring/aggregate.rs:111-158`
- Modify: `crates/security/src/scoring/mod.rs` (add score normalization)
- Test: `crates/security/src/scoring/mod.rs` (existing tests)

- [ ] **Step 1: Write failing test for rebalanced scoring**

In `crates/security/src/scoring/mod.rs`, add test at the end of the `#[cfg(test)]` module:

```rust
#[test]
fn test_all_headers_present_with_weak_csp() {
    // All security headers present + CSP with unsafe-inline
    // should score at least 60 (not 30)
    let hdrs = h(&[
        ("strict-transport-security", "max-age=31536000; includeSubDomains"),
        ("content-security-policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "SAMEORIGIN"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("permissions-policy", "camera=(), microphone=()"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-resource-policy", "same-origin"),
    ]);
    let report = analyze_security("https://example.com", &hdrs, &[], "");
    assert!(
        report.score >= 60,
        "All headers present + weak CSP should score >= 60, got {}",
        report.score
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/krolik/src/ox-browser && cargo test -p ox-security --lib test_all_headers_present_with_weak_csp
```

Expected: FAIL — score will be ~30.

- [ ] **Step 3: Rebalance compute_score in aggregate.rs**

Replace the `compute_score` function in `crates/security/src/scoring/aggregate.rs` (lines 111-158):

```rust
fn compute_score(
    resp_headers: &HashMap<String, String>,
    headers_report: &HeadersReport,
    csp_report: &Option<CspReport>,
    cookies_report: &CookieReport,
    cors_report: &CorsReport,
    sri_report: &SriReport,
    info_disc: &info_disclosure::InfoDisclosureReport,
    body: &body_scan::BodyScanReport,
    vuln: &vuln_js::VulnJsReport,
    dangerous: &dangerous_js::DangerousJsReport,
    redirect: &redirect::RedirectReport,
) -> i32 {
    // Base: 50 points for headers presence, 50 points for policy quality.
    // This ensures a site with all headers present scores ≥50 even with weak policies.
    let mut headers_score: i32 = 50;
    let mut quality_score: i32 = 50;

    // === Headers presence (0-50) ===
    // Deduct from headers_score for missing critical headers
    for f in &headers_report.findings {
        match f.header.as_str() {
            "strict-transport-security" if f.status == HeaderStatus::Missing => headers_score -= 15,
            "strict-transport-security"
                if f.status == HeaderStatus::Present && f.severity == Severity::Medium =>
            {
                headers_score -= 5;
            }
            "x-content-type-options" if f.status == HeaderStatus::Missing => headers_score -= 3,
            "x-frame-options" if f.status == HeaderStatus::Missing => headers_score -= 10,
            "referrer-policy" if f.status == HeaderStatus::Missing => headers_score -= 3,
            "content-security-policy" if f.status == HeaderStatus::Missing => headers_score -= 15,
            _ => {}
        }
    }

    // === Policy quality (0-50) ===
    // CSP quality: ranges from -25 (absent/terrible) to +10 (perfect)
    // Map to 0-30 range within the quality bucket
    match csp_report {
        Some(csp) => {
            // CSP score ranges: -25 (worst) to +10 (best). Map to 0-30.
            let csp_contribution = ((csp.score + 25) * 30 / 35).clamp(0, 30);
            quality_score = quality_score - 30 + csp_contribution;
        }
        None => quality_score -= 30,
    }

    // Other quality modifiers (capped impact)
    quality_score += cookies_report.score_modifier.clamp(-10, 0);
    quality_score += cors_report.score_modifier.clamp(-10, 0);
    quality_score += sri_report.score_modifier.clamp(-5, 0);
    quality_score += info_disc.score_modifier.clamp(-5, 0);
    quality_score += body.score_modifier.clamp(-5, 0);
    quality_score += vuln.score_modifier.clamp(-10, 0);
    quality_score += dangerous.score_modifier.clamp(-10, 0);
    quality_score += redirect.score_modifier.clamp(-5, 0);

    let score = headers_score.max(0) + quality_score.max(0);
    let score = super::bonuses::apply_bonuses(score, resp_headers);
    score.max(0)
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/krolik/src/ox-browser && cargo test -p ox-security --lib test_all_headers_present_with_weak_csp
```

Expected: PASS — score should be ~65-75.

- [ ] **Step 5: Run all security tests to check for regressions**

```bash
cd /home/krolik/src/ox-browser && cargo test -p ox-security
```

Expected: All pass. The `test_perfect_score` test may need adjustment if the new formula changes perfect score value.

- [ ] **Step 6: Commit**

```bash
cd /home/krolik/src/ox-browser && git add crates/security/src/scoring/aggregate.rs crates/security/src/scoring/mod.rs
git commit -m "fix(security): rebalance scoring — split headers presence (50) + policy quality (50)"
```

---

### Task 2: Performance — Speculation Rules + Font Preload + Image Formats

**Files:**
- Modify: `crates/intelligence/src/performance.rs`

- [ ] **Step 1: Add new fields to PerformanceReport**

In `crates/intelligence/src/performance.rs`, extend `PerformanceReport`:

```rust
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
    // New fields
    pub has_speculation_rules: bool,
    pub font_preloads: u32,
    pub images_modern_format: u32,  // WebP + AVIF
    pub images_legacy_format: u32,  // JPEG + PNG + GIF
    pub score: u8,
}
```

- [ ] **Step 2: Add detection in parse_html**

Add to `parse_html` function after the inline styles loop:

```rust
    // Speculation rules (prerender/prefetch via JSON).
    report.has_speculation_rules = doc
        .select("script[type='speculationrules']")
        .length() > 0;

    // Font preloads (critical for LCP).
    report.font_preloads = report.preload.iter()
        .filter(|h| h.as_type == "font")
        .count() as u32;

    // Image formats: modern (WebP/AVIF) vs legacy (JPEG/PNG/GIF).
    for img in doc.select("img[src]").iter() {
        let src = img.attr("src").unwrap_or_default().to_lowercase();
        if src.ends_with(".webp") || src.ends_with(".avif") || src.contains("/webp") || src.contains("/avif") {
            report.images_modern_format += 1;
        } else if src.ends_with(".jpg") || src.ends_with(".jpeg") || src.ends_with(".png") || src.ends_with(".gif") {
            report.images_legacy_format += 1;
        }
        // Also check <source> inside <picture>
    }
    for source in doc.select("picture source[type]").iter() {
        let t = source.attr("type").unwrap_or_default().to_lowercase();
        if t.contains("webp") || t.contains("avif") {
            report.images_modern_format += 1;
        }
    }
```

- [ ] **Step 3: Update compute_score to include new checks**

Replace `compute_score`:

```rust
fn compute_score(r: &PerformanceReport) -> u8 {
    let mut score: u32 = 0;
    if !r.compression.is_empty() { score += 15; }
    if !r.cache_control.is_empty() { score += 12; }
    if !r.etag.is_empty() || !r.expires.is_empty() { score += 10; }
    if !r.preload.is_empty() { score += 8; }
    if !r.preconnect.is_empty() { score += 5; }
    let lazy_ratio = if r.images_total > 0 { r.images_lazy * 100 / r.images_total } else { 100 };
    if lazy_ratio >= 50 { score += 8; }
    if r.inline_styles_bytes < 10_000 { score += 7; }
    if r.http3_supported { score += 5; }
    if !r.prefetch.is_empty() { score += 5; }
    if r.inline_styles_count == 0 { score += 5; }
    // New checks
    if r.has_speculation_rules { score += 5; }
    if r.font_preloads > 0 { score += 8; }
    if r.images_total > 0 && r.images_legacy_format == 0 { score += 7; }
    score.min(100) as u8
}
```

- [ ] **Step 4: Write tests**

Add at the end of `#[cfg(test)]` module:

```rust
    #[test]
    fn detect_speculation_rules() {
        let html = r#"<script type="speculationrules">{"prerender":[{"where":{"href_matches":"/*"}}]}</script>"#;
        let r = analyze(&HashMap::new(), html);
        assert!(r.has_speculation_rules);
    }

    #[test]
    fn detect_font_preloads() {
        let html = r#"
            <link rel="preload" href="/font.woff2" as="font" type="font/woff2">
            <link rel="preload" href="/other.woff2" as="font">
            <link rel="preload" href="/script.js" as="script">
        "#;
        let r = analyze(&HashMap::new(), html);
        assert_eq!(r.font_preloads, 2);
    }

    #[test]
    fn detect_image_formats() {
        let html = r#"
            <img src="/photo.webp">
            <img src="/hero.avif">
            <img src="/old.jpg">
            <img src="/icon.png">
            <picture><source type="image/webp" srcset="/x.webp"><img src="/x.jpg"></picture>
        "#;
        let r = analyze(&HashMap::new(), html);
        assert_eq!(r.images_modern_format, 3); // webp + avif + picture source
        assert_eq!(r.images_legacy_format, 2); // jpg + png (the img inside picture also counted as legacy)
    }

    #[test]
    fn score_with_new_checks() {
        let h = headers(&[
            ("content-encoding", "br"),
            ("cache-control", "max-age=3600"),
            ("etag", "\"abc\""),
            ("alt-svc", "h3=\":443\""),
        ]);
        let html = r#"
            <link rel="preload" href="/f.woff2" as="font">
            <link rel="prefetch" href="/next.js" as="script">
            <link rel="preconnect" href="https://cdn.example.com">
            <img src="a.webp" loading="lazy">
            <script type="speculationrules">{"prerender":[]}</script>
        "#;
        let r = analyze(&h, html);
        assert!(r.score >= 95, "expected >= 95, got {}", r.score);
    }
```

- [ ] **Step 5: Run tests**

```bash
cd /home/krolik/src/ox-browser && cargo test -p ox-intelligence --lib performance
```

Expected: All pass (old `performance_score_full` test may need adjustment since weights changed).

- [ ] **Step 6: Commit**

```bash
cd /home/krolik/src/ox-browser && git add crates/intelligence/src/performance.rs
git commit -m "feat(audit): add speculation rules, font preload, image format detection to performance"
```

---

### Task 3: Accessibility — Decorative Images + Skip Link + Reduced Motion

**Files:**
- Modify: `crates/intelligence/src/accessibility.rs`

- [ ] **Step 1: Add new fields to AccessibilityReport**

Extend the struct:

```rust
#[derive(Debug, Clone, Serialize, Default)]
pub struct AccessibilityReport {
    pub lang: String,
    pub images_with_alt: u32,
    pub images_empty_alt: u32,
    pub images_no_alt: u32,
    pub images_decorative: u32,  // role="presentation" or role="none"
    pub h1_count: u32,
    pub headings: Vec<HeadingInfo>,
    pub heading_skip: bool,
    pub landmarks: u32,
    pub inputs_total: u32,
    pub inputs_with_label: u32,
    pub has_skip_link: bool,
    pub has_reduced_motion: bool,
    pub score: u8,
}
```

- [ ] **Step 2: Update count_images to handle decorative images**

Replace `count_images`:

```rust
fn count_images(doc: &Document) -> (u32, u32, u32, u32) {
    let (mut with_alt, mut empty_alt, mut no_alt, mut decorative) = (0u32, 0u32, 0u32, 0u32);
    for img in doc.select("img").iter() {
        let role = img.attr("role").unwrap_or_default().to_lowercase();
        if role == "presentation" || role == "none" {
            decorative += 1;
            continue; // Decorative images don't need alt text
        }
        match img.attr("alt") {
            None => no_alt += 1,
            Some(v) if v.trim().is_empty() => empty_alt += 1,
            Some(_) => with_alt += 1,
        }
    }
    (with_alt, empty_alt, no_alt, decorative)
}
```

- [ ] **Step 3: Add skip link and reduced-motion detection**

Add two new functions:

```rust
fn detect_skip_link(doc: &Document) -> bool {
    // Skip links: <a href="#main-content"> or <a href="#content"> early in the document
    // Usually the first <a> in <body> with href starting with #
    for link in doc.select("a[href^='#']").iter() {
        let href = link.attr("href").unwrap_or_default().to_lowercase();
        let text = link.text().to_lowercase();
        if href.contains("main") || href.contains("content") || href.contains("skip")
            || text.contains("skip") || text.contains("перейти к содержан")
        {
            return true;
        }
    }
    false
}

fn detect_reduced_motion(doc: &Document) -> bool {
    // Check for prefers-reduced-motion in inline <style> tags
    for style in doc.select("style").iter() {
        if style.text().contains("prefers-reduced-motion") {
            return true;
        }
    }
    // Also check linked stylesheets (we can't read them, but presence of
    // the media query in inline styles is a strong signal)
    false
}
```

- [ ] **Step 4: Update analyze() to use new functions**

```rust
pub fn analyze(html: &str) -> AccessibilityReport {
    let doc = Document::from(html);
    let lang = extract_lang(&doc);
    let (images_with_alt, images_empty_alt, images_no_alt, images_decorative) = count_images(&doc);
    let (headings, h1_count, heading_skip) = analyze_headings(&doc);
    let landmarks = count_landmarks(&doc);
    let (inputs_total, inputs_with_label) = count_labeled_inputs(&doc);
    let has_skip_link = detect_skip_link(&doc);
    let has_reduced_motion = detect_reduced_motion(&doc);
    let mut r = AccessibilityReport {
        lang,
        images_with_alt,
        images_empty_alt,
        images_no_alt,
        images_decorative,
        headings,
        h1_count,
        heading_skip,
        landmarks,
        inputs_total,
        inputs_with_label,
        has_skip_link,
        has_reduced_motion,
        score: 0,
    };
    r.score = compute_score(&r);
    r
}
```

- [ ] **Step 5: Update compute_score with new checks**

```rust
fn compute_score(r: &AccessibilityReport) -> u8 {
    let mut score = 0u32;
    if !r.lang.is_empty() { score += 20; }
    let total_img = r.images_with_alt + r.images_empty_alt + r.images_no_alt;
    if total_img == 0 || r.images_no_alt == 0 { score += 20; }
    if r.h1_count == 1 { score += 15; }
    if !r.heading_skip { score += 10; }
    if r.landmarks > 0 { score += 10; }
    if r.inputs_total == 0 || r.inputs_with_label == r.inputs_total { score += 10; }
    if r.has_skip_link { score += 5; }
    if r.has_reduced_motion { score += 5; }
    if r.images_decorative > 0 { score += 5; } // Proper decorative image handling
    score.min(100) as u8
}
```

- [ ] **Step 6: Write tests**

```rust
    #[test]
    fn decorative_images_not_counted_as_missing_alt() {
        let r = analyze(r#"<html lang="en"><body>
            <img src="a.png" alt="photo">
            <img src="decorative.png" role="presentation">
            <img src="spacer.gif" role="none">
            <img src="missing.png">
        </body></html>"#);
        assert_eq!(r.images_with_alt, 1);
        assert_eq!(r.images_decorative, 2);
        assert_eq!(r.images_no_alt, 1); // Only missing.png
    }

    #[test]
    fn detect_skip_navigation_link() {
        let r = analyze(r#"<html lang="en"><body>
            <a href="#main-content" class="sr-only">Перейти к содержанию</a>
            <main id="main-content">Content</main>
        </body></html>"#);
        assert!(r.has_skip_link);
    }

    #[test]
    fn detect_reduced_motion_support() {
        let r = analyze(r#"<html lang="en"><body>
            <style>@media (prefers-reduced-motion: reduce) { * { animation: none !important; } }</style>
        </body></html>"#);
        assert!(r.has_reduced_motion);
    }
```

- [ ] **Step 7: Run tests**

```bash
cd /home/krolik/src/ox-browser && cargo test -p ox-intelligence --lib accessibility
```

Expected: All pass. Previous `score_calculation` test may need adjustment since score weights changed.

- [ ] **Step 8: Commit**

```bash
cd /home/krolik/src/ox-browser && git add crates/intelligence/src/accessibility.rs
git commit -m "feat(audit): decorative images, skip link, reduced-motion detection in accessibility"
```

---

### Task 4: Enrich Findings with Fix Snippets

**Files:**
- Modify: `crates/intelligence/src/audit/findings.rs`

- [ ] **Step 1: Add fix snippets to performance findings**

In `performance_findings`, replace the compression finding:

```rust
    if report.compression.is_empty() {
        out.push(AuditFinding {
            severity: "high", category: "performance",
            message: "No compression enabled".into(),
            fix: "Add to nginx: gzip on; gzip_types text/plain text/css text/xml application/javascript application/json image/svg+xml; gzip_vary on; gzip_comp_level 6;".into(),
        });
    }
    if report.cache_control.is_empty() {
        out.push(AuditFinding {
            severity: "high", category: "performance",
            message: "No Cache-Control header".into(),
            fix: "Add to nginx location: add_header Cache-Control \"public, max-age=3600\" always;".into(),
        });
    }
```

- [ ] **Step 2: Add findings for new performance checks**

Add after existing findings:

```rust
    if !report.has_speculation_rules {
        out.push(AuditFinding {
            severity: "low", category: "performance",
            message: "No speculation rules for prerendering".into(),
            fix: "Add <script type=\"speculationrules\">{\"prerender\":[{\"where\":{\"href_matches\":\"/*\"},\"eagerness\":\"moderate\"}]}</script>".into(),
        });
    }
    if report.font_preloads == 0 && !report.preload.is_empty() {
        out.push(AuditFinding {
            severity: "medium", category: "performance",
            message: "No font preloads (impacts LCP)".into(),
            fix: "Add <link rel=\"preload\" href=\"/font.woff2\" as=\"font\" type=\"font/woff2\" crossorigin>".into(),
        });
    }
    if report.images_legacy_format > 0 {
        out.push(AuditFinding {
            severity: "low", category: "performance",
            message: format!("{} images in legacy format (JPEG/PNG)", report.images_legacy_format),
            fix: "Convert images to WebP or AVIF for 25-50% smaller files".into(),
        });
    }
```

- [ ] **Step 3: Add findings for new accessibility checks**

Add to `accessibility_findings`:

```rust
    if !report.has_skip_link {
        out.push(AuditFinding {
            severity: "medium", category: "accessibility",
            message: "No skip navigation link".into(),
            fix: "Add as first element in <body>: <a href=\"#main-content\" class=\"sr-only focus:not-sr-only\">Skip to content</a>".into(),
        });
    }
    if !report.has_reduced_motion {
        out.push(AuditFinding {
            severity: "low", category: "accessibility",
            message: "No prefers-reduced-motion support".into(),
            fix: "Add CSS: @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: 0.01ms !important; } }".into(),
        });
    }
```

- [ ] **Step 4: Run all tests**

```bash
cd /home/krolik/src/ox-browser && cargo test -p ox-intelligence
```

Expected: All pass.

- [ ] **Step 5: Commit**

```bash
cd /home/krolik/src/ox-browser && git add crates/intelligence/src/audit/findings.rs
git commit -m "feat(audit): actionable fix snippets with nginx/HTML code in findings"
```

---

### Task 5: Update Existing Tests + Build + Deploy

- [ ] **Step 1: Fix any broken tests from score rebalancing**

Run full test suite:

```bash
cd /home/krolik/src/ox-browser && cargo test --workspace 2>&1 | grep -E "FAIL|test result"
```

Fix any test assertions that break due to new score weights (likely `performance_score_full`, `performance_score_empty`, `score_calculation` in accessibility).

- [ ] **Step 2: Run clippy**

```bash
cd /home/krolik/src/ox-browser && cargo clippy --workspace -- -D warnings
```

- [ ] **Step 3: Build Docker**

```bash
cd ~/deploy/krolik-server && docker compose build ox-browser
```

- [ ] **Step 4: Deploy**

```bash
cd ~/deploy/krolik-server && docker compose up -d --no-deps --force-recreate ox-browser
```

- [ ] **Step 5: Verify with site_audit**

```bash
# Wait for startup
sleep 5 && curl -s http://127.0.0.1:8901/health
```

Then test via MCP: `site_audit url=https://reklama.piter.now/ focus=all`

Expected: Security score ≥ 60 (was 30), Accessibility 100, Performance with new fields populated.

- [ ] **Step 6: Commit final state**

```bash
cd /home/krolik/src/ox-browser && git add -A && git commit -m "feat(audit): site audit v2 — rebalanced scoring, richer checks, fix snippets"
```

---

## Dependency Graph

```
Task 1 (Security scoring) ── independent
Task 2 (Performance checks) ── independent
Task 3 (Accessibility checks) ── independent
Task 4 (Fix snippets) ── depends on Tasks 2+3 (new fields)
Task 5 (Tests + Deploy) ── depends on ALL
```

**Parallelizable batches:**
- **Batch 1:** Tasks 1, 2, 3 (all independent, different files)
- **Batch 2:** Task 4 (depends on new report fields from 2+3)
- **Batch 3:** Task 5 (integration, build, deploy)
