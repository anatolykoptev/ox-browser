# Browser-Based Metrics for Site Audit — Design Spec

## Goal

Add Core Web Vitals and browser-rendered metrics to site_audit via headless Chrome, closing the gap with Google Lighthouse.

## What Lighthouse Measures (That We Can't From HTTP+HTML)

### Core Web Vitals (Performance)
| Metric | What | How Lighthouse Gets It |
|--------|------|----------------------|
| **FCP** (First Contentful Paint) | Time until first text/image renders | Chrome DevTools Performance API |
| **LCP** (Largest Contentful Paint) | Time until largest element renders | PerformanceObserver |
| **CLS** (Cumulative Layout Shift) | Visual stability score | LayoutShift entries |
| **TBT** (Total Blocking Time) | Sum of long tasks blocking main thread | Long Task API |
| **SI** (Speed Index) | How quickly content is visually displayed | Video frame analysis |
| **INP** (Interaction to Next Paint) | Input responsiveness | Event Timing API |

### Accessibility (Rendered)
| Check | What | How |
|-------|------|-----|
| Color contrast (WCAG AA/AAA) | Text vs background contrast ratio | Computed styles on rendered elements |
| Tap target sizing | Touch targets ≥ 48x48px | getBoundingClientRect() |
| Focus order | Tab key navigation sequence | document.querySelectorAll with tabindex |
| Focus-visible styles | Visible focus indicators | getComputedStyle on :focus-visible |

### Best Practices
| Check | What | How |
|-------|------|-----|
| Console errors | JS errors during load | Chrome console events |
| Deprecated APIs | Usage of deprecated web APIs | CDP Runtime.consoleAPICalled |
| Mixed content | HTTP resources on HTTPS page | Network request monitoring |
| Render-blocking resources | CSS/JS blocking first paint | CDP Network + Performance timeline |

## Architecture Options

### Option A: ox-browser Chrome Integration (Recommended)
ox-browser already has Chrome/CloakBrowser integration via `chromium_enabled` config. Add a new endpoint `/metrics` that:
1. Navigates to URL in headless Chrome
2. Injects Performance Observer for CWV
3. Waits for page load + 3s settling
4. Collects metrics via CDP
5. Returns structured CWV report

**Pros:** Reuses existing Chrome pool, consistent with ox-browser architecture
**Cons:** Adds Chrome dependency to audit (currently audit is HTTP-only)

### Option B: go-browser Integration
go-browser has rod/chromedp. Add a CWV collection function that site_audit calls.

**Pros:** Go ecosystem, easier to integrate with go-code
**Cons:** go-browser is newer, less battle-tested than ox-browser Chrome

### Option C: Separate Lighthouse Wrapper
Shell out to `lighthouse --output=json` CLI.

**Pros:** Exact same results as Lighthouse, no reimplementation
**Cons:** Node.js dependency, heavy (~500MB), slow startup

## Recommended: Option A (ox-browser)

### New Endpoint: POST /metrics

```json
// Request
{ "url": "https://example.com" }

// Response
{
  "url": "https://example.com",
  "cwv": {
    "fcp_ms": 1200,
    "lcp_ms": 2500,
    "cls": 0.05,
    "tbt_ms": 150,
    "si_ms": 1800
  },
  "console_errors": 0,
  "deprecated_apis": [],
  "render_blocking": ["style.css", "app.js"],
  "accessibility": {
    "contrast_issues": 2,
    "small_tap_targets": 0,
    "missing_focus_styles": false
  },
  "elapsed_ms": 5000
}
```

### Integration with site_audit

site_audit MCP tool gets optional `browser: bool` parameter:
- `browser: false` (default) — current HTTP+HTML analysis, fast (~1.5s)
- `browser: true` — also runs Chrome metrics, slower (~5-8s)

Browser metrics are merged into existing categories:
- Performance score: weighted average of HTTP checks + CWV
- Accessibility score: current checks + contrast + tap targets

### Chrome JavaScript for CWV Collection

```javascript
// Injected into page via CDP Runtime.evaluate
new Promise((resolve) => {
  const metrics = { fcp: 0, lcp: 0, cls: 0 };

  new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      if (entry.name === 'first-contentful-paint') metrics.fcp = entry.startTime;
    }
  }).observe({ type: 'paint', buffered: true });

  new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      metrics.lcp = Math.max(metrics.lcp, entry.startTime);
    }
  }).observe({ type: 'largest-contentful-paint', buffered: true });

  new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      if (!entry.hadRecentInput) metrics.cls += entry.value;
    }
  }).observe({ type: 'layout-shift', buffered: true });

  // Wait for load + settling
  setTimeout(() => resolve(metrics), 3000);
});
```

## Scoring Integration

### Current (HTTP-only)
Performance score = sum of boolean checks (compression, cache, images, etc.)

### With Browser Metrics
Performance score = 40% HTTP checks + 60% CWV score

CWV score (Lighthouse-compatible thresholds):
- FCP: Good < 1.8s, Needs Improvement < 3s, Poor > 3s
- LCP: Good < 2.5s, Needs Improvement < 4s, Poor > 4s
- CLS: Good < 0.1, Needs Improvement < 0.25, Poor > 0.25
- TBT: Good < 200ms, Needs Improvement < 600ms, Poor > 600ms

## Implementation Priority

1. **Phase 1:** FCP + LCP + CLS (most impactful CWV, simplest to collect)
2. **Phase 2:** TBT + console errors + render-blocking detection
3. **Phase 3:** Color contrast + tap target analysis (accessibility)

## Dependencies

- ox-browser with `chromium_enabled=true`
- Chrome/CloakBrowser available in Docker container
- `shm_size: 256m` in docker-compose (already configured)
