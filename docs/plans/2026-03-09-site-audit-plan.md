# site_audit MCP Tool Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `site_audit` MCP tool — single-URL audit with scores, findings, and recommendations across SEO, performance, accessibility, and security.

**Architecture:** Reuse existing intelligence modules (`seo::analyze`, `performance::analyze`, `accessibility::analyze`) and security scanner (`ox_security::analyze_security`). New `audit.rs` in intelligence crate generates findings + recommendations from report data. New MCP tool file wires it together.

**Tech Stack:** Rust, ox-intelligence, ox-security, rmcp MCP SDK

**Design doc:** `docs/plans/2026-03-09-site-audit-design.md`

---

### Task 1: Performance scoring function

**Files:**
- Modify: `crates/intelligence/src/performance.rs`

**Step 1: Add `compute_score` function and `score` field to `PerformanceReport`**

Add `score: u8` field to `PerformanceReport` (after `inline_styles_bytes`), and call `compute_score(&report)` at end of `analyze()`.

```rust
// Add to PerformanceReport struct:
pub score: u8,

// Add after parse_html(html, &mut report); in analyze():
report.score = compute_score(&report);
report
```

Scoring function:

```rust
fn compute_score(r: &PerformanceReport) -> u8 {
    let mut score: u32 = 0;
    if !r.compression.is_empty() { score += 15; }
    if !r.cache_control.is_empty() { score += 15; }
    if !r.etag.is_empty() || !r.expires.is_empty() { score += 15; }
    if !r.preload.is_empty() { score += 10; }
    if !r.preconnect.is_empty() { score += 10; }
    let lazy_ratio = if r.images_total > 0 { r.images_lazy * 100 / r.images_total } else { 100 };
    if lazy_ratio >= 50 { score += 10; }
    if r.inline_styles_bytes < 10_000 { score += 10; }
    if r.http3_supported { score += 5; }
    if !r.prefetch.is_empty() { score += 5; }
    if r.inline_styles_count == 0 { score += 5; }
    score.min(100) as u8
}
```

**Step 2: Add test for scoring**

```rust
#[test]
fn performance_score_full() {
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
        <img src="a.jpg" loading="lazy">
    "#;
    let r = analyze(&h, html);
    assert_eq!(r.score, 100);
}

#[test]
fn performance_score_empty() {
    let r = analyze(&HashMap::new(), "");
    // No compression(0), no cache(0), no etag/expires(0), no preload(0),
    // no preconnect(0), no images so lazy_ratio=100(+10), no inline(+10), no h3(0), no prefetch(0), no inline_count(+5) = 25
    assert_eq!(r.score, 25);
}
```

**Step 3: Run tests**

Run: `cargo test -p ox-intelligence -- performance`
Expected: PASS

**Step 4: Commit**

```
git add crates/intelligence/src/performance.rs
git commit -m "feat(intelligence): add performance scoring (0-100)"
```

---

### Task 2: Audit report types and finding generator

**Files:**
- Create: `crates/intelligence/src/audit.rs`
- Modify: `crates/intelligence/src/lib.rs` (add `pub mod audit;`)

**Step 1: Create `audit.rs` with types**

```rust
//! Site audit: scores, findings, and recommendations across categories.

use serde::Serialize;

use crate::{accessibility::AccessibilityReport, performance::PerformanceReport, seo::SeoReport};

#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub severity: &'static str, // "critical", "high", "medium", "low", "info"
    pub category: &'static str, // "seo", "performance", "accessibility", "security"
    pub message: String,
    pub fix: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryAudit {
    pub score: u8,
    pub grade: String,
    pub findings: Vec<AuditFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiteAuditReport {
    pub url: String,
    pub overall_score: u8,
    pub overall_grade: String,
    pub categories: AuditCategories,
    pub top_issues: Vec<AuditFinding>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditCategories {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seo: Option<CategoryAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub performance: Option<CategoryAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessibility: Option<CategoryAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<CategoryAudit>,
}
```

**Step 2: Add SEO finding generator**

```rust
pub fn seo_findings(report: &SeoReport) -> Vec<AuditFinding> {
    let mut f = Vec::new();
    if report.description.is_empty() {
        f.push(AuditFinding {
            severity: "high", category: "seo",
            message: "Missing meta description".into(),
            fix: "Add <meta name=\"description\"> with 150-160 chars".into(),
        });
    }
    if report.og.title.is_empty() {
        f.push(AuditFinding {
            severity: "medium", category: "seo",
            message: "Missing Open Graph title".into(),
            fix: "Add <meta property=\"og:title\"> for social sharing".into(),
        });
    }
    if report.og.image.is_empty() {
        f.push(AuditFinding {
            severity: "medium", category: "seo",
            message: "Missing OG image".into(),
            fix: "Add <meta property=\"og:image\"> (1200x630px recommended)".into(),
        });
    }
    if report.canonical.is_none() {
        f.push(AuditFinding {
            severity: "medium", category: "seo",
            message: "No canonical URL".into(),
            fix: "Add <link rel=\"canonical\"> to prevent duplicate content".into(),
        });
    }
    if report.json_ld.is_empty() {
        f.push(AuditFinding {
            severity: "low", category: "seo",
            message: "No structured data (JSON-LD)".into(),
            fix: "Add JSON-LD schema markup for rich snippets".into(),
        });
    }
    if report.favicon.is_none() {
        f.push(AuditFinding {
            severity: "low", category: "seo",
            message: "No favicon".into(),
            fix: "Add <link rel=\"icon\" href=\"/favicon.ico\">".into(),
        });
    }
    if report.twitter.card.is_empty() {
        f.push(AuditFinding {
            severity: "low", category: "seo",
            message: "Missing Twitter Card".into(),
            fix: "Add <meta name=\"twitter:card\" content=\"summary_large_image\">".into(),
        });
    }
    if report.robots.contains("noindex") {
        f.push(AuditFinding {
            severity: "info", category: "seo",
            message: "Page set to noindex".into(),
            fix: "Remove noindex if page should appear in search results".into(),
        });
    }
    f
}
```

**Step 3: Add performance finding generator**

```rust
pub fn performance_findings(report: &PerformanceReport) -> Vec<AuditFinding> {
    let mut f = Vec::new();
    if report.compression.is_empty() {
        f.push(AuditFinding {
            severity: "high", category: "performance",
            message: "No compression enabled".into(),
            fix: "Enable gzip or brotli compression on the server".into(),
        });
    }
    if report.cache_control.is_empty() {
        f.push(AuditFinding {
            severity: "high", category: "performance",
            message: "No Cache-Control header".into(),
            fix: "Set Cache-Control with appropriate max-age for static assets".into(),
        });
    }
    if report.images_total > 0 && report.images_lazy == 0 {
        f.push(AuditFinding {
            severity: "medium", category: "performance",
            message: format!("{} images without lazy loading", report.images_total),
            fix: "Add loading=\"lazy\" to below-the-fold images".into(),
        });
    }
    if report.preconnect.is_empty() && report.preload.len() + report.prefetch.len() == 0 {
        f.push(AuditFinding {
            severity: "medium", category: "performance",
            message: "No resource hints (preload/preconnect/prefetch)".into(),
            fix: "Add <link rel=\"preconnect\"> for third-party origins".into(),
        });
    }
    if report.inline_styles_bytes > 10_000 {
        f.push(AuditFinding {
            severity: "medium", category: "performance",
            message: format!("Large inline CSS ({} bytes)", report.inline_styles_bytes),
            fix: "Extract inline styles to external stylesheet".into(),
        });
    }
    if !report.http3_supported {
        f.push(AuditFinding {
            severity: "low", category: "performance",
            message: "HTTP/3 not available".into(),
            fix: "Enable HTTP/3 via alt-svc header for faster connections".into(),
        });
    }
    if report.images_total > 0 {
        let lazy_pct = report.images_lazy * 100 / report.images_total;
        if lazy_pct > 0 && lazy_pct < 50 {
            f.push(AuditFinding {
                severity: "low", category: "performance",
                message: format!("Only {}% of images use lazy loading", lazy_pct),
                fix: "Add loading=\"lazy\" to more below-fold images".into(),
            });
        }
    }
    f
}
```

**Step 4: Add accessibility finding generator**

```rust
pub fn accessibility_findings(report: &AccessibilityReport) -> Vec<AuditFinding> {
    let mut f = Vec::new();
    if report.lang.is_empty() {
        f.push(AuditFinding {
            severity: "high", category: "accessibility",
            message: "Missing html lang attribute".into(),
            fix: "Add lang attribute to <html> element (e.g. lang=\"en\")".into(),
        });
    }
    if report.images_no_alt > 0 {
        f.push(AuditFinding {
            severity: "high", category: "accessibility",
            message: format!("{} images missing alt text", report.images_no_alt),
            fix: "Add descriptive alt text to all <img> elements".into(),
        });
    }
    if report.h1_count == 0 {
        f.push(AuditFinding {
            severity: "high", category: "accessibility",
            message: "No H1 heading on page".into(),
            fix: "Add exactly one <h1> heading per page".into(),
        });
    }
    if report.h1_count > 1 {
        f.push(AuditFinding {
            severity: "medium", category: "accessibility",
            message: format!("Multiple H1 headings ({})", report.h1_count),
            fix: "Use only one <h1> per page, use <h2>+ for subsections".into(),
        });
    }
    if report.heading_skip {
        f.push(AuditFinding {
            severity: "medium", category: "accessibility",
            message: "Heading levels are skipped".into(),
            fix: "Use sequential heading levels (h1 -> h2 -> h3, no gaps)".into(),
        });
    }
    if report.landmarks == 0 {
        f.push(AuditFinding {
            severity: "medium", category: "accessibility",
            message: "No landmark elements found".into(),
            fix: "Add semantic elements: <main>, <nav>, <header>, <footer>".into(),
        });
    }
    if report.inputs_total > 0 && report.inputs_with_label < report.inputs_total {
        let missing = report.inputs_total - report.inputs_with_label;
        f.push(AuditFinding {
            severity: "medium", category: "accessibility",
            message: format!("{} form inputs without labels", missing),
            fix: "Add <label for=\"id\"> or aria-label to all form inputs".into(),
        });
    }
    f
}
```

**Step 5: Add grade + overall scoring functions**

```rust
pub fn audit_grade(score: u8) -> String {
    match score {
        97..=100 => "A+", 93..=96 => "A", 90..=92 => "A-",
        87..=89 => "B+", 83..=86 => "B", 80..=82 => "B-",
        77..=79 => "C+", 73..=76 => "C", 70..=72 => "C-",
        67..=69 => "D+", 63..=66 => "D", 60..=62 => "D-",
        _ => "F",
    }.to_string()
}

/// Compute overall score as weighted average of category scores.
pub fn overall_score(seo: u8, perf: u8, a11y: u8, security: u8) -> u8 {
    let total = seo as u32 + perf as u32 + a11y as u32 + security as u32;
    (total / 4) as u8
}

/// Collect top issues sorted by severity, capped at `max`.
pub fn top_issues(categories: &AuditCategories, max: usize) -> Vec<AuditFinding> {
    let mut all: Vec<AuditFinding> = Vec::new();
    for cat in [&categories.seo, &categories.performance, &categories.accessibility, &categories.security] {
        if let Some(c) = cat {
            all.extend(c.findings.iter().cloned());
        }
    }
    all.sort_by_key(|f| match f.severity {
        "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4,
    });
    all.truncate(max);
    all
}
```

**Step 6: Add to `lib.rs`**

Add `pub mod audit;` to `crates/intelligence/src/lib.rs`.

**Step 7: Add tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{seo, performance, accessibility};
    use std::collections::HashMap;

    #[test]
    fn seo_findings_missing_all() {
        let report = seo::analyze("");
        let findings = seo_findings(&report);
        assert!(findings.iter().any(|f| f.message.contains("meta description")));
        assert!(findings.iter().any(|f| f.message.contains("canonical")));
        assert!(findings.iter().any(|f| f.severity == "high"));
    }

    #[test]
    fn seo_findings_perfect() {
        let html = r#"<html><head>
            <meta name="description" content="Desc">
            <meta property="og:title" content="T">
            <meta property="og:image" content="I">
            <meta name="twitter:card" content="summary">
            <link rel="canonical" href="https://example.com/">
            <script type="application/ld+json">{"@type":"WebPage"}</script>
            <link rel="icon" href="/favicon.ico">
        </head></html>"#;
        let report = seo::analyze(html);
        let findings = seo_findings(&report);
        assert!(findings.is_empty(), "expected no findings, got {:?}", findings);
    }

    #[test]
    fn performance_findings_no_compression() {
        let report = performance::analyze(&HashMap::new(), "");
        let findings = performance_findings(&report);
        assert!(findings.iter().any(|f| f.message.contains("compression")));
    }

    #[test]
    fn accessibility_findings_no_lang() {
        let report = accessibility::analyze("<html><body></body></html>");
        let findings = accessibility_findings(&report);
        assert!(findings.iter().any(|f| f.message.contains("lang")));
    }

    #[test]
    fn grade_boundaries() {
        assert_eq!(audit_grade(100), "A+");
        assert_eq!(audit_grade(93), "A");
        assert_eq!(audit_grade(73), "C");
        assert_eq!(audit_grade(50), "F");
    }

    #[test]
    fn overall_score_average() {
        assert_eq!(overall_score(80, 60, 100, 40), 70);
    }
}
```

**Step 8: Run tests**

Run: `cargo test -p ox-intelligence -- audit`
Expected: PASS

**Step 9: Commit**

```
git add crates/intelligence/src/audit.rs crates/intelligence/src/lib.rs
git commit -m "feat(intelligence): add audit finding generators and scoring"
```

---

### Task 3: Security findings adapter

**Files:**
- Modify: `crates/intelligence/src/audit.rs`

**Step 1: Add security finding converter**

The `ox_security::SecurityReport` has typed findings in each sub-report. We need to flatten them into `AuditFinding`. The `HeaderFinding` already has `recommendation`. For others, we generate a generic message.

```rust
/// Convert ox_security findings into audit findings.
pub fn security_findings(report: &ox_security::SecurityReport) -> Vec<AuditFinding> {
    let mut f = Vec::new();

    // Header findings (have recommendations)
    for hf in &report.headers.findings {
        f.push(AuditFinding {
            severity: severity_str(&hf.severity),
            category: "security",
            message: hf.description.clone(),
            fix: hf.recommendation.clone().unwrap_or_default(),
        });
    }

    // CORS findings
    for cf in &report.cors.findings {
        f.push(AuditFinding {
            severity: severity_str(&cf.severity),
            category: "security",
            message: cf.description.clone(),
            fix: "Review CORS configuration".into(),
        });
    }

    // Cookie findings
    for cf in &report.cookies.findings {
        f.push(AuditFinding {
            severity: severity_str(&cf.severity),
            category: "security",
            message: format!("{}: {}", cf.cookie, cf.description),
            fix: "Set Secure, HttpOnly, SameSite flags on cookies".into(),
        });
    }

    // Redirect findings
    for rf in &report.redirect.findings {
        f.push(AuditFinding {
            severity: severity_str(&rf.severity),
            category: "security",
            message: rf.description.clone(),
            fix: "Enforce HTTPS redirects".into(),
        });
    }

    f
}

fn severity_str(s: &ox_security::Severity) -> &'static str {
    match s {
        ox_security::Severity::Critical => "critical",
        ox_security::Severity::High => "high",
        ox_security::Severity::Medium => "medium",
        ox_security::Severity::Low => "low",
        ox_security::Severity::Info => "info",
    }
}
```

**Step 2: Add ox-security dependency to ox-intelligence Cargo.toml**

Add to `[dependencies]` in `crates/intelligence/Cargo.toml`:
```toml
ox-security = { path = "../security" }
```

**Step 3: Add test**

```rust
#[test]
fn security_findings_from_report() {
    let report = ox_security::analyze_security(
        "http://example.com",
        &HashMap::new(),
        &[],
        "",
    );
    let findings = security_findings(&report);
    // HTTP site should have redirect finding
    assert!(findings.iter().any(|f| f.category == "security"));
}
```

**Step 4: Run tests**

Run: `cargo test -p ox-intelligence -- audit`
Expected: PASS

**Step 5: Commit**

```
git add crates/intelligence/src/audit.rs crates/intelligence/Cargo.toml
git commit -m "feat(intelligence): add security findings adapter"
```

---

### Task 4: site_audit MCP tool

**Files:**
- Create: `crates/mcp/src/tools/site_audit.rs`
- Modify: `crates/mcp/src/tools/mod.rs`

**Step 1: Create MCP tool file**

```rust
//! MCP tool: site_audit — comprehensive site audit with scores and recommendations.

use std::collections::HashMap;
use std::time::Instant;

use ox_intelligence::{accessibility, audit, performance, seo};
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::Deserialize;

use rmcp::schemars;
use schemars::JsonSchema;

use super::OxMcpServer;

/// Input parameters for the `site_audit` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SiteAuditInput {
    /// The URL to audit.
    pub url: String,
    /// Focus area: "all" (default), "seo", "performance", "accessibility", "security".
    #[serde(default)]
    pub focus: Option<String>,
}

impl OxMcpServer {
    pub(crate) async fn do_site_audit(
        &self,
        input: SiteAuditInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();
        let focus = input.focus.as_deref().unwrap_or("all");

        let resp = match self.http_client.get(&input.url).await {
            Ok(r) => r,
            Err(e) => {
                let json = serde_json::json!({
                    "url": input.url,
                    "error": e.to_string(),
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                });
                return Ok(CallToolResult::error(vec![Content::text(json.to_string())]));
            }
        };

        let headers: HashMap<String, String> = resp
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|val| (k.to_string().to_lowercase(), val.to_owned()))
            })
            .collect();

        let set_cookie_headers: Vec<String> = resp
            .headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(|s| s.to_owned()))
            .collect();

        // Run all analyzers
        let seo_report = seo::analyze(&resp.body);
        let perf_report = performance::analyze(&headers, &resp.body);
        let a11y_report = accessibility::analyze(&resp.body);
        let sec_report = ox_security::analyze_security(
            &input.url, &headers, &set_cookie_headers, &resp.body,
        );

        // Generate findings
        let seo_findings = audit::seo_findings(&seo_report);
        let perf_findings = audit::performance_findings(&perf_report);
        let a11y_findings = audit::accessibility_findings(&a11y_report);
        let sec_findings = audit::security_findings(&sec_report);

        // Security score: cap Observatory score to 0-100 range
        let sec_score = sec_report.score.clamp(0, 100) as u8;

        // Build categories based on focus
        let include = |cat: &str| focus == "all" || focus == cat;

        let categories = audit::AuditCategories {
            seo: include("seo").then(|| audit::CategoryAudit {
                score: seo_report.score,
                grade: audit::audit_grade(seo_report.score),
                findings: seo_findings,
            }),
            performance: include("performance").then(|| audit::CategoryAudit {
                score: perf_report.score,
                grade: audit::audit_grade(perf_report.score),
                findings: perf_findings,
            }),
            accessibility: include("accessibility").then(|| audit::CategoryAudit {
                score: a11y_report.score,
                grade: audit::audit_grade(a11y_report.score),
                findings: a11y_findings,
            }),
            security: include("security").then(|| audit::CategoryAudit {
                score: sec_score,
                grade: audit::audit_grade(sec_score),
                findings: sec_findings,
            }),
        };

        let overall = audit::overall_score(
            seo_report.score, perf_report.score, a11y_report.score, sec_score,
        );

        let top_issues = audit::top_issues(&categories, 10);

        let result = audit::SiteAuditReport {
            url: input.url,
            overall_score: overall,
            overall_grade: audit::audit_grade(overall),
            categories,
            top_issues,
            elapsed_ms: start.elapsed().as_millis() as u64,
        };

        let json = serde_json::to_string(&result).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
```

**Step 2: Register tool in `mod.rs`**

Add `mod site_audit;` to module list.
Add `pub use site_audit::SiteAuditInput;` to pub uses.

Add to `#[tool_router] impl OxMcpServer`:

```rust
#[tool(
    name = "site_audit",
    description = "Comprehensive site audit with scores and actionable recommendations. Analyzes SEO (meta tags, OG, structured data), performance (compression, caching, lazy loading), accessibility (lang, alt text, headings, ARIA), and security (headers, CSP, cookies, CORS). Returns overall score (0-100), per-category grades (A+ to F), prioritized findings with fix instructions. Use focus parameter to narrow: \"seo\", \"performance\", \"accessibility\", \"security\", or \"all\" (default)."
)]
async fn site_audit(
    &self,
    Parameters(input): Parameters<SiteAuditInput>,
) -> Result<CallToolResult, McpError> {
    self.do_site_audit(input).await
}
```

**Step 3: Add REST endpoint in ox-js**

Add to `crates/js/src/routes.rs` (or wherever routes are defined):

```rust
.route("/site-audit", post(handle_site_audit))
```

And handler:

```rust
async fn handle_site_audit(
    State(state): State<AppState>,
    Json(input): Json<SiteAuditInput>,
) -> impl IntoResponse {
    // Similar to security handler — delegate to the same logic
    // but via direct function calls instead of MCP
}
```

Note: REST endpoint is optional — MCP tool is the primary interface. Skip if routes.rs structure makes this complex. The MCP tool is sufficient.

**Step 4: Build check**

Run: `cargo check --workspace`
Expected: OK

**Step 5: Commit**

```
git add crates/mcp/src/tools/site_audit.rs crates/mcp/src/tools/mod.rs
git commit -m "feat(mcp): add site_audit tool with scores and recommendations"
```

---

### Task 5: Integration test + deploy

**Step 1: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests pass

**Step 2: Test locally**

```bash
cargo run -- server &
sleep 2
curl -s -X POST http://127.0.0.1:8901/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"site_audit","arguments":{"url":"https://example.com"}}}' | head -20
```

Expected: JSON with `overall_score`, `categories`, `top_issues`

**Step 3: Docker build + deploy**

```bash
cd <deploy>
docker compose build --no-cache ox-browser
docker compose up -d --no-deps --force-recreate ox-browser
```

**Step 4: Smoke test deployed**

```bash
# MCP tool
curl -s -X POST http://127.0.0.1:8901/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

**Step 5: Reconnect MCP**

```
claude mcp add -s user -t http ox-browser http://127.0.0.1:8901/mcp
```

Or `/mcp` in Claude Code to reconnect.

**Step 6: Update roadmap**

Update `docs/ROADMAP.md`:
- Mark `site_audit` as done in "Future MCP Tools" section
- Remove individual `seo_audit`, `performance_audit`, `accessibility_audit` entries (replaced by `site_audit`)
- Add entry in Phase 5.6 or create Phase 5.7

**Step 7: Commit**

```
git add docs/ROADMAP.md
git commit -m "docs: update roadmap with site_audit tool"
```

---

### Task Summary

| Task | What | Est. |
|------|------|------|
| 1 | Performance scoring | 3 min |
| 2 | Audit types + finding generators (SEO/perf/a11y) | 5 min |
| 3 | Security findings adapter | 3 min |
| 4 | MCP tool + registration | 4 min |
| 5 | Integration test + deploy | 5 min |

Total: ~20 min, 5 commits
