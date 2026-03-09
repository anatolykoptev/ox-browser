# site_audit MCP Tool — Design

## Goal

Single MCP tool that returns actionable audit report with scores, findings, and recommendations across 4 categories: SEO, performance, accessibility, security.

Unlike `analyze` (raw data dump), `site_audit` produces scored, prioritized findings with fix recommendations.

## Input

```rust
struct SiteAuditInput {
    url: String,
    focus: Option<String>, // "all" (default), "seo", "performance", "accessibility", "security"
}
```

## Output

```json
{
  "url": "https://example.com",
  "overall_score": 62,
  "overall_grade": "C",
  "categories": {
    "seo": { "score": 45, "grade": "D", "findings": [...], "recommendations": [...] },
    "performance": { "score": 70, "grade": "B-", "findings": [...], "recommendations": [...] },
    "accessibility": { "score": 85, "grade": "A-", "findings": [...], "recommendations": [...] },
    "security": { "score": 48, "grade": "D+", "findings": [...], "recommendations": [...] }
  },
  "top_issues": [
    { "severity": "high", "category": "seo", "message": "Missing meta description", "fix": "Add <meta name=\"description\"> with 150-160 chars" }
  ],
  "elapsed_ms": 340
}
```

## Scoring

- **SEO** (0-100): existing `seo::analyze().score`
- **Performance** (0-100): NEW scoring from `performance::analyze()` data
- **Accessibility** (0-100): existing `accessibility::analyze().score`
- **Security** (0-100): existing `ox_security` Observatory score (capped at 100)
- **Overall**: weighted average (SEO 25%, perf 25%, a11y 25%, security 25%)
- **Grades**: A+ (97+), A (93+), A- (90+), B+ (87+), B (83+), B- (80+), C+ (77+), C (73+), C- (70+), D+ (67+), D (63+), D- (60+), F (<60)

## Finding Generation (rule-based, no LLM)

### SEO Findings
| Condition | Severity | Message | Fix |
|-----------|----------|---------|-----|
| description empty | high | Missing meta description | Add `<meta name="description">` with 150-160 chars |
| og:title empty | medium | Missing Open Graph title | Add `<meta property="og:title">` |
| og:image empty | medium | Missing OG image | Add `<meta property="og:image">` for social sharing |
| canonical missing | medium | No canonical URL | Add `<link rel="canonical">` to prevent duplicate content |
| json_ld empty | low | No structured data | Add JSON-LD schema for rich snippets |
| favicon missing | low | No favicon | Add `<link rel="icon">` |
| twitter card empty | low | Missing Twitter Card | Add `<meta name="twitter:card">` |
| robots noindex | info | Page set to noindex | Intentional? Remove if page should be indexed |

### Performance Findings
| Condition | Severity | Message | Fix |
|-----------|----------|---------|-----|
| compression empty | high | No compression | Enable gzip/brotli compression |
| cache_control empty | high | No cache headers | Set Cache-Control with appropriate max-age |
| images_total > 0 && images_lazy == 0 | medium | No lazy loading on images | Add `loading="lazy"` to below-fold images |
| preconnect empty + scripts > 2 | medium | No preconnect hints | Add `<link rel="preconnect">` for third-party origins |
| inline_styles_bytes > 10000 | medium | Large inline CSS ({N} bytes) | Extract to external stylesheet |
| preload empty | low | No preload hints | Preload critical fonts/scripts |
| http3 not supported | low | HTTP/3 not available | Enable HTTP/3 via alt-svc header |
| images_lazy < images_total/2 | low | Only {N}% images lazy-loaded | Add lazy loading to more images |

### Accessibility Findings
| Condition | Severity | Message | Fix |
|-----------|----------|---------|-----|
| lang empty | high | Missing html lang attribute | Add `<html lang="en">` |
| images_no_alt > 0 | high | {N} images missing alt text | Add descriptive alt text to all images |
| h1_count == 0 | high | No H1 heading | Add exactly one H1 per page |
| h1_count > 1 | medium | Multiple H1 headings ({N}) | Use only one H1 per page |
| heading_skip | medium | Heading level skipped | Use sequential heading levels (h1→h2→h3) |
| landmarks == 0 | medium | No landmark elements | Add `<main>`, `<nav>`, `<header>`, `<footer>` |
| inputs_total > 0 && inputs_with_label < inputs_total | medium | {N} form inputs without labels | Add `<label>` or aria-label to all inputs |

### Security Findings
Reuse existing `ox_security::SecurityReport.findings` — already has severity + recommendations.

## Architecture

### New files
- `crates/intelligence/src/audit.rs` (~150 LOC) — `AuditReport`, finding generators, scoring
- `crates/mcp/src/tools/site_audit.rs` (~100 LOC) — MCP tool, fetches page, runs all analyzers

### Flow
1. Fetch URL (reuse `HttpClient`)
2. Parse headers + HTML (same as `analyze`)
3. Run intelligence modules: `seo::analyze`, `performance::analyze`, `accessibility::analyze`
4. Run security scanner: `ox_security::analyze_security`
5. Generate findings from each report (rule-based)
6. Compute scores, grades
7. Filter by `focus` if set
8. Sort `top_issues` by severity (critical→high→medium→low→info), cap at 10
9. Return `SiteAuditReport`

## Performance Score (NEW)

Currently `performance::analyze()` returns data but no score. Add scoring:

```
+15 compression present (gzip/br/zstd)
+15 cache-control present
+15 etag or expires present
+10 preload hints present
+10 preconnect hints present
+10 images lazy ratio >= 50%
+10 inline CSS < 10KB
+5  HTTP/3 supported
+5  prefetch hints present
+5  no inline styles at all
```

## Depends on
- Phase 2.5 (intelligence modules)
- Phase 4.5 (security scanner)
