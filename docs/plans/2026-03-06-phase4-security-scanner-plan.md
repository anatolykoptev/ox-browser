# Phase 4: Security Scanner (v0.4.0) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Passive security audit of any URL from a single HTTP response — headers, CSP, cookies, CORS, SRI, supply chain, mixed content — with Mozilla Observatory-compatible scoring (F→A+).

**Architecture:** All analysis is passive (no active scanning). Input: HTTP response headers + HTML body (already fetched by ox-http). Output: `SecurityReport` with per-module findings, severity, recommendations, and aggregate score/grade. Integrates as `security_scan` MCP tool + `POST /security` REST endpoint.

**Tech Stack:** Rust, serde, regex, ox-core (Page/DOM), ox-http (HttpResponse)

---

### Task 1: Security headers analyzer (`headers.rs`)

**Files:**
- Create: `crates/security/src/headers.rs`
- Modify: `crates/security/src/lib.rs` — add `pub mod headers;`

**Context:** Analyze 15+ HTTP security headers from response. This is the foundation module — every other module builds on having parsed headers available. Based on Mozilla Observatory checks + modern headers (COOP/COEP/CORP/Permissions-Policy) that Observatory doesn't check.

**Headers to check (each produces a Finding):**
1. `Strict-Transport-Security` — present, max-age >= 6 months (15768000), includeSubDomains, preload
2. `Content-Security-Policy` — present (detailed analysis in csp.rs, here just presence + basic)
3. `X-Content-Type-Options` — must be `nosniff`
4. `X-Frame-Options` — DENY or SAMEORIGIN (note: superseded by CSP frame-ancestors)
5. `Referrer-Policy` — present, value check (strict-origin-when-cross-origin recommended)
6. `Permissions-Policy` — present, blocks camera/microphone/geolocation/browsing-topics
7. `Cross-Origin-Opener-Policy` — present, value (same-origin recommended)
8. `Cross-Origin-Embedder-Policy` — present, value (require-corp recommended)
9. `Cross-Origin-Resource-Policy` — present, value (same-origin or same-site)
10. `X-XSS-Protection` — should be `0` or absent (deprecated, CSP replaces it)
11. `Reporting-Endpoints` — present (modern violation reporting)
12. `NEL` (Network Error Logging) — present
13. `X-Permitted-Cross-Domain-Policies` — present, value none/master-only
14. `X-DNS-Prefetch-Control` — off recommended for privacy
15. `Cache-Control` — no-store for sensitive pages (informational)

**Data structures:**

```rust
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct HeaderFinding {
    pub header: String,
    pub status: HeaderStatus,
    pub value: Option<String>,
    pub description: String,
    pub severity: Severity,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HeaderStatus {
    Present,
    Missing,
    Invalid,
    Deprecated,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeadersReport {
    pub findings: Vec<HeaderFinding>,
    pub present_count: usize,
    pub missing_count: usize,
    pub total_checked: usize,
}

/// Analyze security headers from an HTTP response.
/// `headers` should be lowercase key → value.
pub fn analyze_headers(headers: &HashMap<String, String>) -> HeadersReport { ... }
```

**Tests (in same file, `#[cfg(test)]`):**
- `test_hsts_good` — max-age=31536000; includeSubDomains; preload → Present, Info
- `test_hsts_short` — max-age=3600 → Present, Medium (too short)
- `test_hsts_missing` → Missing, High
- `test_xcto_nosniff` → Present, Info
- `test_xcto_missing` → Missing, Medium
- `test_coop_same_origin` → Present, Info
- `test_permissions_policy_good` → Present, Info
- `test_xss_protection_deprecated` → Deprecated, Low (should be 0)
- `test_referrer_policy_good` → strict-origin-when-cross-origin, Present, Info
- `test_all_missing` → all 15 findings Missing
- `test_full_secure_headers` — all headers present with good values → all Present/Info

**Step 1:** Write `headers.rs` with `analyze_headers()` and all 11 tests.
**Step 2:** Add `pub mod headers;` to `lib.rs`.
**Step 3:** Run `cargo test -p ox-security -- headers` — all 11 pass.
**Step 4:** Commit: `feat(security): add security headers analyzer (15 headers, 11 tests)`

---

### Task 2: CSP parser and evaluator (`csp.rs`)

**Files:**
- Create: `crates/security/src/csp.rs`
- Modify: `crates/security/src/lib.rs` — add `pub mod csp;`

**Context:** Full CSP parser + evaluator inspired by Google CSP Evaluator and Mozilla Observatory. Parses CSP header string into directives, evaluates security level, detects bypasses, assigns grade (A-F). This is the most complex module.

**Data structures:**

```rust
#[derive(Debug, Clone, Serialize)]
pub struct CspReport {
    pub raw: String,
    pub directives: Vec<CspDirective>,
    pub findings: Vec<CspFinding>,
    pub grade: char,        // A-F
    pub score: i32,         // Observatory-compatible modifier (-25 to +10)
    pub has_unsafe_inline: bool,
    pub has_unsafe_eval: bool,
    pub has_nonce: bool,
    pub has_hash: bool,
    pub has_strict_dynamic: bool,
    pub missing_directives: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CspDirective {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CspFinding {
    pub directive: String,
    pub description: String,
    pub severity: Severity,  // reuse from headers.rs
}

/// Parse and evaluate a Content-Security-Policy header value.
pub fn evaluate_csp(csp_header: &str) -> CspReport { ... }

/// Parse CSP string into directives.
fn parse_csp(raw: &str) -> Vec<CspDirective> { ... }
```

**Evaluation logic (Observatory-compatible scoring):**
- `default-src 'none'` + no unsafe → score +10, grade A
- No unsafe-inline/unsafe-eval → score +5, grade A
- `unsafe-inline` in style-src only → score 0, grade B
- `unsafe-eval` present → score -10, grade C
- `unsafe-inline` in script-src → score -20, grade D
- Insecure scheme (http:) in active content → score -20, grade D
- Not implemented → score -25, grade F
- Invalid/unparseable → score -25, grade F

**Bypass detection findings:**
- `unsafe-inline` without nonce/hash → High (XSS bypass)
- `unsafe-eval` → Medium (code injection)
- Overly broad sources: `https:`, `data:`, `*` in script-src → High
- Missing `object-src` (or not 'none') → Medium (Flash/plugin bypass)
- Missing `base-uri` → Medium (base tag injection)
- Missing `form-action` → Medium (form hijacking)
- Missing `frame-ancestors` → Low (clickjacking, X-Frame-Options fallback)
- `strict-dynamic` without nonce/hash → High (misconfigured)
- `report-uri` without `report-to` → Info (deprecated directive)

**Tests:**
- `test_parse_simple_csp` — `default-src 'self'` → 1 directive, 1 value
- `test_parse_complex_csp` — multi-directive CSP → all parsed correctly
- `test_no_csp` — empty string → grade F, score -25
- `test_strict_csp_nonce` — `script-src 'nonce-abc123' 'strict-dynamic'` → grade A
- `test_unsafe_inline` — `script-src 'unsafe-inline'` → grade D, has_unsafe_inline=true
- `test_unsafe_eval` — `script-src 'unsafe-eval'` → grade C
- `test_default_src_none_no_unsafe` — grade A, score +10
- `test_missing_object_src` — finding about missing object-src
- `test_missing_form_action` — finding about form hijacking risk
- `test_overly_broad_source` — `script-src https:` → High finding
- `test_style_src_unsafe_inline_only` — score 0 (acceptable)

**Step 1:** Write `csp.rs` with `parse_csp()`, `evaluate_csp()`, and all 11 tests.
**Step 2:** Add `pub mod csp;` to `lib.rs`. Note: `Severity` is defined in `headers.rs`, so either re-export from lib.rs or move to a `types.rs`. Prefer: create `crates/security/src/types.rs` with `Severity` enum, use from both `headers.rs` and `csp.rs`.
**Step 3:** Run `cargo test -p ox-security -- csp` — all 11 pass.
**Step 4:** Commit: `feat(security): add CSP parser and evaluator (bypass detection, A-F grading, 11 tests)`

---

### Task 3: Cookies, CORS, SRI analyzers (`cookies.rs`, `cors.rs`, `sri.rs`)

**Files:**
- Create: `crates/security/src/cookies.rs`
- Create: `crates/security/src/cors.rs`
- Create: `crates/security/src/sri.rs`
- Modify: `crates/security/src/lib.rs` — add 3 `pub mod` lines

**Context:** Three smaller modules that complete the Observatory-compatible checks. Cookies uses Set-Cookie headers. CORS uses ACAO headers. SRI uses HTML body (script/link tags).

#### cookies.rs

```rust
#[derive(Debug, Clone, Serialize)]
pub struct CookieReport {
    pub cookies: Vec<CookieInfo>,
    pub findings: Vec<CookieFinding>,
    pub score_modifier: i32,  // Observatory: +5 to -40
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieInfo {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,  // Strict, Lax, None
    pub host_prefix: bool,          // __Host- prefix
    pub secure_prefix: bool,        // __Secure- prefix
    pub is_session: bool,           // session cookie detection (PHPSESSID, JSESSIONID, etc.)
    pub is_tracker: bool,           // _ga, _fbp, _gid, etc.
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieFinding {
    pub cookie: String,
    pub description: String,
    pub severity: Severity,
}

/// Analyze cookies from Set-Cookie header values.
/// `set_cookie_headers` is a list of raw Set-Cookie header values.
pub fn analyze_cookies(set_cookie_headers: &[String]) -> CookieReport { ... }
```

**Session cookie patterns:** names containing `sess`, `sid`, `token`, `auth`, `login`, `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `connect.sid`, `laravel_session`, `wp-settings-`.

**Tracker cookie patterns:** `_ga`, `_gid`, `_fbp`, `_fbc`, `__gads`, `__gpi`, `_gcl_`, `IDE`, `NID`, `fr` (Facebook).

**Cookie prefix checks:** `__Host-` requires Secure + Path=/ + no Domain. `__Secure-` requires Secure.

**Tests (6):**
- `test_secure_httponly_samesite` — all flags → score +5
- `test_session_without_httponly` → score -30, High severity
- `test_session_without_secure` → score -40, Critical
- `test_tracker_cookies_detected` — `_ga` and `_fbp` → is_tracker=true
- `test_host_prefix` — `__Host-session=abc; Secure; Path=/` → host_prefix=true
- `test_no_cookies` → score 0, empty

#### cors.rs

```rust
#[derive(Debug, Clone, Serialize)]
pub struct CorsReport {
    pub acao: Option<String>,       // Access-Control-Allow-Origin value
    pub acac: bool,                 // Access-Control-Allow-Credentials
    pub findings: Vec<CorsFinding>,
    pub score_modifier: i32,        // Observatory: 0 to -50
}

#[derive(Debug, Clone, Serialize)]
pub struct CorsFinding {
    pub description: String,
    pub severity: Severity,
}

/// Analyze CORS headers.
pub fn analyze_cors(headers: &HashMap<String, String>) -> CorsReport { ... }
```

**Checks:**
- `Access-Control-Allow-Origin: *` → -50, Critical (universal access)
- `*` + `Access-Control-Allow-Credentials: true` → Critical (impossible per spec, but misconfigured)
- Restricted origin → 0, Info
- Not present → 0, Info (no CORS)

**Tests (4):**
- `test_cors_wildcard` → score -50, Critical
- `test_cors_restricted` → score 0
- `test_cors_not_present` → score 0
- `test_cors_wildcard_with_credentials` → Critical finding

#### sri.rs

```rust
#[derive(Debug, Clone, Serialize)]
pub struct SriReport {
    pub total_external_scripts: usize,
    pub scripts_with_integrity: usize,
    pub total_external_styles: usize,
    pub styles_with_integrity: usize,
    pub coverage_percent: f32,
    pub findings: Vec<SriFinding>,
    pub score_modifier: i32,   // Observatory: +5 to -50
}

#[derive(Debug, Clone, Serialize)]
pub struct SriFinding {
    pub resource: String,
    pub description: String,
    pub severity: Severity,
}

/// Analyze Subresource Integrity from HTML.
/// `html` is the full page HTML.
pub fn analyze_sri(html: &str) -> SriReport { ... }
```

**Logic:** Parse `<script src="...">` and `<link rel="stylesheet" href="...">` tags. External = different origin OR starts with `//` or `http`. Check for `integrity` attribute. Score: all external have SRI → +5; some missing → -5 to -25; no SRI at all on external → -50.

**Tests (5):**
- `test_all_scripts_have_sri` → coverage 100%, score +5
- `test_no_external_scripts` → coverage 100% (vacuously), score 0
- `test_missing_sri_on_cdn` → finding with CDN URL, score -25
- `test_mixed_sri_coverage` → partial coverage, proportional score
- `test_styles_sri` — external stylesheet with/without integrity

**Step 1:** Create `types.rs` with shared `Severity` enum. Update `headers.rs` to use it.
**Step 2:** Write `cookies.rs` with 6 tests.
**Step 3:** Write `cors.rs` with 4 tests.
**Step 4:** Write `sri.rs` with 5 tests.
**Step 5:** Update `lib.rs` with all new modules.
**Step 6:** Run `cargo test -p ox-security` — all tests pass (11 headers + 11 csp + 15 new = 37).
**Step 7:** Commit: `feat(security): add cookies, CORS, SRI analyzers (15 tests)`

---

### Task 4: Supply chain + mixed content + scoring (`supply_chain.rs`, `mixed_content.rs`, `scoring.rs`)

**Files:**
- Create: `crates/security/src/supply_chain.rs`
- Create: `crates/security/src/mixed_content.rs`
- Create: `crates/security/src/scoring.rs`
- Modify: `crates/security/src/lib.rs` — add modules + `SecurityReport` aggregate

**Context:** These are our differentiator modules — no other passive scanner does supply chain risk or mixed content from a single response. Plus the scoring module that aggregates all findings into Observatory-compatible grade.

#### supply_chain.rs

```rust
#[derive(Debug, Clone, Serialize)]
pub struct SupplyChainReport {
    pub third_party_scripts: Vec<ThirdPartyScript>,
    pub total_third_party: usize,
    pub risky_domains: Vec<String>,
    pub sri_coverage_third_party: f32,
    pub findings: Vec<SupplyChainFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThirdPartyScript {
    pub url: String,
    pub domain: String,
    pub has_integrity: bool,
    pub is_known_risky: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplyChainFinding {
    pub description: String,
    pub severity: Severity,
}

/// Known risky or compromised CDN domains (Polyfill.io case, etc.)
const RISKY_DOMAINS: &[&str] = &[
    "polyfill.io", "cdn.polyfill.io",
    "cdn.bootcss.com", "cdn.bootcdn.net",  // compromised Chinese CDNs
];

/// Analyze third-party script supply chain risk from HTML.
pub fn analyze_supply_chain(html: &str, page_domain: &str) -> SupplyChainReport { ... }
```

**Tests (4):**
- `test_no_third_party` → empty, no findings
- `test_third_party_with_sri` → has_integrity=true, no findings
- `test_risky_domain_polyfill` → is_known_risky=true, Critical finding
- `test_third_party_without_sri` → Medium finding (supply chain risk)

#### mixed_content.rs

```rust
#[derive(Debug, Clone, Serialize)]
pub struct MixedContentReport {
    pub is_https: bool,
    pub mixed_scripts: Vec<String>,     // http:// scripts on https page
    pub mixed_styles: Vec<String>,
    pub mixed_iframes: Vec<String>,
    pub mixed_forms: Vec<String>,       // form action="http://..."
    pub mixed_media: Vec<String>,       // images/video/audio over http
    pub findings: Vec<MixedContentFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MixedContentFinding {
    pub resource: String,
    pub resource_type: String,
    pub description: String,
    pub severity: Severity,
}

/// Detect mixed content (HTTP resources on HTTPS page).
pub fn analyze_mixed_content(html: &str, page_url: &str) -> MixedContentReport { ... }
```

**Tests (4):**
- `test_https_page_clean` → no mixed content
- `test_http_script_on_https` → Critical finding (active mixed content)
- `test_http_image_on_https` → Low finding (passive mixed content)
- `test_http_page_no_mixed` → is_https=false, no findings (not applicable)

#### scoring.rs

```rust
#[derive(Debug, Clone, Serialize)]
pub struct SecurityReport {
    pub url: String,
    pub score: i32,          // 0-135 (Observatory-compatible)
    pub grade: String,       // F, D-, D, D+, C-, C, C+, B-, B, B+, A-, A, A+
    pub headers: HeadersReport,
    pub csp: Option<CspReport>,
    pub cookies: CookieReport,
    pub cors: CorsReport,
    pub sri: SriReport,
    pub supply_chain: SupplyChainReport,
    pub mixed_content: MixedContentReport,
    pub findings_summary: FindingsSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingsSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

/// Compute grade from score (Observatory-compatible).
pub fn score_to_grade(score: i32) -> String { ... }

/// Run all security checks and produce aggregate report.
pub fn analyze_security(
    url: &str,
    headers: &HashMap<String, String>,
    set_cookie_headers: &[String],
    html: &str,
) -> SecurityReport { ... }
```

**Grade table (Mozilla Observatory):**
100+ → A+, 90-99 → A, 85-89 → A-, 80-84 → B+, 70-79 → B, 65-69 → B-,
60-64 → C+, 50-59 → C, 45-49 → C-, 40-44 → D+, 30-39 → D, 25-29 → D-,
0-24 → F

**Scoring:** Start at 100. Sum all score_modifiers from: CSP (-25 to +10), cookies (+5 to -40), CORS (0 to -50), SRI (+5 to -50), HSTS (-20 to +5), redirections (-20 to +5), X-Content-Type-Options (-5 to 0), X-Frame-Options (-20 to 0), Referrer-Policy (-5 to 0). Bonus points only if base >= 90.

**Tests (5):**
- `test_grade_chart` — verify score→grade mapping for all ranges
- `test_perfect_score` — all secure headers + strict CSP + good cookies → A+
- `test_no_security` — no headers, no CSP, no SRI → F
- `test_findings_summary_counts` — verify Critical/High/Medium/Low/Info counts
- `test_moderate_security` — some headers present, basic CSP → B/C range

**Step 1:** Write `supply_chain.rs` with 4 tests.
**Step 2:** Write `mixed_content.rs` with 4 tests.
**Step 3:** Write `scoring.rs` with `SecurityReport`, `analyze_security()`, `score_to_grade()`, and 5 tests.
**Step 4:** Update `lib.rs` — add modules, re-export `SecurityReport` and `analyze_security`.
**Step 5:** Run `cargo test -p ox-security` — all tests pass (37 + 13 = 50).
**Step 6:** Commit: `feat(security): add supply chain, mixed content, scoring (Observatory-compatible, 13 tests)`

---

### Task 5: REST endpoint + MCP tool + deploy

**Files:**
- Create: `crates/js/src/security.rs` — `POST /security` endpoint
- Modify: `crates/js/src/lib.rs` — add route
- Create: `crates/mcp/src/tools/security.rs` — `security_scan` MCP tool
- Modify: `crates/mcp/src/tools/mod.rs` — register tool
- Modify: `crates/mcp/Cargo.toml` — (ox-security already a dep)

**Context:** Wire the SecurityReport into both REST API and MCP tool. Same pattern as existing fetch/analyze endpoints.

#### REST endpoint (`crates/js/src/security.rs`)

```rust
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
pub struct SecurityRequest {
    pub url: String,
}

pub async fn security_scan(
    State(state): State<AppState>,
    Json(req): Json<SecurityRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // 1. Fetch the URL with state.http_client.get()
    // 2. Extract headers as HashMap<String, String>
    // 3. Extract Set-Cookie headers as Vec<String>
    // 4. Call ox_security::analyze_security(url, headers, set_cookies, body)
    // 5. Return JSON SecurityReport
}
```

Add to router in `lib.rs`: `.route("/security", post(security::security_scan))`

#### MCP tool (`crates/mcp/src/tools/security.rs`)

```rust
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use rmcp::schemars;
use schemars::JsonSchema;
use serde::Deserialize;

use super::OxMcpServer;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SecurityScanInput {
    /// The URL to scan for security issues.
    pub url: String,
}

impl OxMcpServer {
    pub(crate) async fn do_security_scan(
        &self,
        input: SecurityScanInput,
    ) -> Result<CallToolResult, McpError> {
        // 1. Fetch URL
        // 2. Extract headers + set-cookie + body
        // 3. Call ox_security::analyze_security()
        // 4. Serialize to JSON, return CallToolResult::success
    }
}
```

Register in `mod.rs`:
```rust
mod security;
pub use security::SecurityScanInput;

// In #[tool_router] impl:
#[tool(
    name = "security_scan",
    description = "Passive security audit of a URL. Checks 15+ HTTP security headers, CSP (with bypass detection), cookies, CORS, SRI, supply chain risk, and mixed content. Returns Observatory-compatible score (F to A+) and detailed findings with severity."
)]
async fn security_scan(
    &self,
    Parameters(input): Parameters<SecurityScanInput>,
) -> Result<CallToolResult, McpError> {
    self.do_security_scan(input).await
}
```

**Cargo.toml changes:** `crates/js/Cargo.toml` needs `ox-security = { path = "../security" }` added.

**Tests:** No new unit tests (integration only). Smoke test after deploy:
```bash
# REST
curl -s -X POST http://127.0.0.1:8901/security \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}' | jq '.grade, .score'

# MCP tools/list — should show 5 tools now
```

**Step 1:** Create `crates/js/src/security.rs`, add route in `lib.rs`, add ox-security dep to js/Cargo.toml.
**Step 2:** Create `crates/mcp/src/tools/security.rs`, register in `mod.rs`.
**Step 3:** Run `cargo build` — ensure it compiles.
**Step 4:** Run `cargo test` — all tests pass (existing + new security tests).
**Step 5:** Docker build + deploy: `cd ~/deploy/krolik-server && docker compose build --no-cache ox-browser && docker compose up -d --no-deps --force-recreate ox-browser`
**Step 6:** Smoke test REST `/security` endpoint.
**Step 7:** Smoke test MCP `tools/list` shows 5 tools.
**Step 8:** Bump version to v0.4.0 in workspace Cargo.toml.
**Step 9:** Commit: `feat(security): add security_scan REST endpoint + MCP tool`
**Step 10:** `git tag v0.4.0 && git push origin main --tags`
