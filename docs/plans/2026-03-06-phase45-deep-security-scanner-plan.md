# Phase 4.5: Deep Security Scanner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close all passive security scanning gaps vs ZAP, Observatory, SecurityHeaders — add info disclosure, body scanning, vulnerable JS detection, and enhanced existing modules.

**Architecture:** Three new modules (`info_disclosure`, `body_scan`, `vuln_js`) plus enhancements to existing modules (`cors`, `headers`). All passive — from single HTTP response. Each module returns typed findings with severity. Aggregator updated to include new modules in scoring.

**Tech Stack:** Rust, regex crate (already dep), serde (already dep). No new dependencies.

---

### Task 1: Information Disclosure Module

Detect headers that leak internal infrastructure details. Two categories: headers that **should not exist** (X-Powered-By, debug headers) and headers with **too much detail** (Server with version).

**Files:**
- Create: `crates/security/src/info_disclosure.rs`
- Modify: `crates/security/src/lib.rs`
- Modify: `crates/security/src/scoring/mod.rs` (add field to SecurityReport)
- Modify: `crates/security/src/scoring/aggregate.rs` (call new module, update scoring)

**Step 1: Write the failing test**

Add to `crates/security/src/info_disclosure.rs`:

```rust
use std::collections::HashMap;
use crate::types::Severity;

#[derive(Debug, Clone, serde::Serialize)]
pub struct InfoDisclosureReport {
    pub findings: Vec<InfoDisclosureFinding>,
    pub score_modifier: i32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct InfoDisclosureFinding {
    pub header: String,
    pub value: String,
    pub description: String,
    pub severity: Severity,
}

pub fn analyze_info_disclosure(headers: &HashMap<String, String>) -> InfoDisclosureReport {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn test_server_with_version() {
        let headers = h(&[("server", "nginx/1.18.0")]);
        let report = analyze_info_disclosure(&headers);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Medium);
        assert!(report.findings[0].description.contains("version"));
    }

    #[test]
    fn test_server_without_version() {
        let headers = h(&[("server", "nginx")]);
        let report = analyze_info_disclosure(&headers);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_x_powered_by() {
        let headers = h(&[("x-powered-by", "PHP/8.1.2")]);
        let report = analyze_info_disclosure(&headers);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_debug_headers_high_severity() {
        let headers = h(&[
            ("x-debug-token", "abc123"),
            ("x-debug-token-link", "/_profiler/abc123"),
        ]);
        let report = analyze_info_disclosure(&headers);
        assert_eq!(report.findings.len(), 2);
        assert!(report.findings.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_backend_server_disclosure() {
        let headers = h(&[("x-backend-server", "web-prod-03.internal.example.com")]);
        let report = analyze_info_disclosure(&headers);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::High);
    }

    #[test]
    fn test_aspnet_version() {
        let headers = h(&[
            ("x-aspnet-version", "4.0.30319"),
            ("x-aspnetmvc-version", "5.2"),
        ]);
        let report = analyze_info_disclosure(&headers);
        assert_eq!(report.findings.len(), 2);
    }

    #[test]
    fn test_deprecated_headers() {
        let headers = h(&[
            ("public-key-pins", "pin-sha256=...; max-age=5184000"),
            ("expect-ct", "max-age=86400, enforce"),
        ]);
        let report = analyze_info_disclosure(&headers);
        assert_eq!(report.findings.len(), 2);
        assert!(report.findings.iter().all(|f| f.severity == Severity::Low));
    }

    #[test]
    fn test_x_runtime() {
        let headers = h(&[("x-runtime", "0.003842")]);
        let report = analyze_info_disclosure(&headers);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_clean_headers() {
        let headers = h(&[("content-type", "text/html; charset=utf-8")]);
        let report = analyze_info_disclosure(&headers);
        assert!(report.findings.is_empty());
        assert_eq!(report.score_modifier, 0);
    }

    #[test]
    fn test_score_modifier() {
        let headers = h(&[
            ("x-powered-by", "Express"),
            ("x-debug-token", "abc"),
            ("server", "Apache/2.4.41"),
        ]);
        let report = analyze_info_disclosure(&headers);
        assert!(report.score_modifier < 0);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p ox-security info_disclosure`
Expected: FAIL (todo!() panics)

**Step 3: Write minimal implementation**

In `crates/security/src/info_disclosure.rs`, replace `todo!()` with:

```rust
pub fn analyze_info_disclosure(headers: &HashMap<String, String>) -> InfoDisclosureReport {
    let mut findings = Vec::new();

    // Headers that should NOT exist at all
    let forbidden: &[(&str, Severity, &str)] = &[
        ("x-powered-by", Severity::Medium, "Technology stack disclosed"),
        ("x-aspnet-version", Severity::Medium, ".NET version disclosed"),
        ("x-aspnetmvc-version", Severity::Medium, "ASP.NET MVC version disclosed"),
        ("x-generator", Severity::Medium, "Generator/CMS disclosed"),
        ("x-backend-server", Severity::High, "Internal hostname disclosed"),
        ("x-debug-token", Severity::High, "Debug profiler token exposed"),
        ("x-debug-token-link", Severity::High, "Debug profiler URL exposed"),
        ("x-chromelogger-data", Severity::High, "PHP debug data in header"),
        ("x-runtime", Severity::Low, "Server processing time disclosed"),
    ];

    for &(name, severity, desc) in forbidden {
        if let Some(val) = headers.get(name) {
            findings.push(InfoDisclosureFinding {
                header: name.to_string(),
                value: val.clone(),
                description: desc.to_string(),
                severity,
            });
        }
    }

    // Server header: only flag if it contains a version number
    if let Some(server) = headers.get("server") {
        let has_version = server.chars().any(|c| c.is_ascii_digit())
            && server.contains('/');
        if has_version {
            findings.push(InfoDisclosureFinding {
                header: "server".to_string(),
                value: server.clone(),
                description: "Server header discloses version information".to_string(),
                severity: Severity::Medium,
            });
        }
    }

    // Deprecated headers (still present = stale config)
    let deprecated: &[(&str, &str)] = &[
        ("public-key-pins", "HPKP is deprecated and no longer supported by browsers"),
        ("expect-ct", "Expect-CT is deprecated since Chrome 107"),
    ];

    for &(name, desc) in deprecated {
        if let Some(val) = headers.get(name) {
            findings.push(InfoDisclosureFinding {
                header: name.to_string(),
                value: val.clone(),
                description: desc.to_string(),
                severity: Severity::Low,
            });
        }
    }

    let score_modifier = findings.iter().fold(0i32, |acc, f| {
        acc + match f.severity {
            Severity::Critical => -15,
            Severity::High => -10,
            Severity::Medium => -5,
            Severity::Low => -2,
            Severity::Info => 0,
        }
    }).max(-30);

    InfoDisclosureReport { findings, score_modifier }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p ox-security info_disclosure`
Expected: 10 tests PASS

**Step 5: Wire into lib.rs and scoring**

In `crates/security/src/lib.rs` add: `pub mod info_disclosure;`

In `crates/security/src/scoring/mod.rs` add field to `SecurityReport`:
```rust
pub info_disclosure: InfoDisclosureReport,
```
(Add `use crate::info_disclosure::InfoDisclosureReport;` at top)

In `crates/security/src/scoring/aggregate.rs`:
- Add `use crate::info_disclosure;`
- After the existing module calls, add: `let info_disc = info_disclosure::analyze_info_disclosure(resp_headers);`
- In `compute_score()`, add: `score += info_disc.score_modifier;`
- In `count_findings()`, iterate `info_disc.findings`
- Set `info_disclosure: info_disc` in SecurityReport construction

**Step 6: Run all security tests**

Run: `cargo test -p ox-security`
Expected: All tests pass (existing 58 + 10 new = 68)

**Step 7: Commit**

```bash
git add crates/security/src/info_disclosure.rs crates/security/src/lib.rs crates/security/src/scoring/
git commit -m "feat(security): add information disclosure detection module

Detect headers leaking internal info: Server version, X-Powered-By,
X-Backend-Server, debug tokens, deprecated HPKP/Expect-CT.
10 new tests."
```

---

### Task 2: Body Scanner Module

Scan HTML body for security-sensitive patterns: private IPs, stack traces, suspicious comments, session IDs in URLs, insecure form posts, directory listings.

**Files:**
- Create: `crates/security/src/body_scan.rs`
- Modify: `crates/security/src/lib.rs`
- Modify: `crates/security/src/scoring/mod.rs`
- Modify: `crates/security/src/scoring/aggregate.rs`

**Step 1: Write the failing test**

Add to `crates/security/src/body_scan.rs`:

```rust
use regex::Regex;
use crate::types::Severity;

#[derive(Debug, Clone, serde::Serialize)]
pub struct BodyScanReport {
    pub findings: Vec<BodyScanFinding>,
    pub score_modifier: i32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BodyScanFinding {
    pub check: String,
    pub detail: String,
    pub severity: Severity,
}

/// Scan HTML body for security-sensitive patterns.
/// `page_url` is needed for session-ID-in-URL checks.
pub fn scan_body(html: &str, page_url: &str) -> BodyScanReport {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ip_in_body() {
        let html = r#"<p>Server: 192.168.1.100</p>"#;
        let report = scan_body(html, "https://example.com");
        assert!(report.findings.iter().any(|f| f.check == "private_ip"));
    }

    #[test]
    fn test_no_false_positive_public_ip() {
        let html = r#"<p>Server: 8.8.8.8</p>"#;
        let report = scan_body(html, "https://example.com");
        assert!(report.findings.iter().all(|f| f.check != "private_ip"));
    }

    #[test]
    fn test_java_stack_trace() {
        let html = r#"<pre>at com.example.App.main(App.java:42)
at org.apache.catalina.core.StandardWrapper.service(StandardWrapper.java:175)</pre>"#;
        let report = scan_body(html, "https://example.com");
        assert!(report.findings.iter().any(|f| f.check == "stack_trace"));
        assert!(report.findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_python_traceback() {
        let html = r#"<pre>Traceback (most recent call last):
  File "app.py", line 42, in handler</pre>"#;
        let report = scan_body(html, "https://example.com");
        assert!(report.findings.iter().any(|f| f.check == "stack_trace"));
    }

    #[test]
    fn test_php_error() {
        let html = r#"<b>Fatal error</b>: Uncaught Error: Call to undefined function foo() in /var/www/html/index.php:10"#;
        let report = scan_body(html, "https://example.com");
        assert!(report.findings.iter().any(|f| f.check == "stack_trace"));
    }

    #[test]
    fn test_suspicious_comment() {
        let html = r#"<!-- TODO: remove hardcoded password=admin123 -->"#;
        let report = scan_body(html, "https://example.com");
        assert!(report.findings.iter().any(|f| f.check == "suspicious_comment"));
    }

    #[test]
    fn test_normal_comment_no_finding() {
        let html = r#"<!-- Navigation section -->"#;
        let report = scan_body(html, "https://example.com");
        assert!(report.findings.iter().all(|f| f.check != "suspicious_comment"));
    }

    #[test]
    fn test_meta_generator_version() {
        let html = r#"<meta name="generator" content="WordPress 6.4.2">"#;
        let report = scan_body(html, "https://example.com");
        assert!(report.findings.iter().any(|f| f.check == "generator_version"));
    }

    #[test]
    fn test_directory_listing() {
        let html = r#"<title>Index of /uploads</title>
<h1>Index of /uploads</h1>"#;
        let report = scan_body(html, "https://example.com");
        assert!(report.findings.iter().any(|f| f.check == "directory_listing"));
    }

    #[test]
    fn test_session_id_in_url() {
        let report = scan_body("<html></html>", "https://example.com/page;jsessionid=ABC123DEF456");
        assert!(report.findings.iter().any(|f| f.check == "session_in_url"));
    }

    #[test]
    fn test_sensitive_param_in_url() {
        let report = scan_body("<html></html>", "https://example.com/reset?token=abc123&password=secret");
        assert!(report.findings.iter().any(|f| f.check == "sensitive_url_param"));
    }

    #[test]
    fn test_insecure_form_action() {
        let html = r#"<form action="http://example.com/login" method="post">"#;
        let report = scan_body(html, "https://example.com/login");
        assert!(report.findings.iter().any(|f| f.check == "insecure_form_action"));
    }

    #[test]
    fn test_clean_page() {
        let html = r#"<html><head><title>Hello</title></head><body><p>World</p></body></html>"#;
        let report = scan_body(html, "https://example.com");
        assert!(report.findings.is_empty());
        assert_eq!(report.score_modifier, 0);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p ox-security body_scan`
Expected: FAIL (todo!() panics)

**Step 3: Write minimal implementation**

Replace `todo!()` in `scan_body`:

```rust
use std::sync::LazyLock;

static RE_PRIVATE_IP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s|>)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:\s|<|$)").unwrap()
});

static RE_STACK_TRACE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:at [a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)*\([A-Za-z0-9_]+\.java:\d+\)|Traceback \(most recent call last\)|Fatal error.*in /[^\s]+:\d+|NullReferenceException|System\.Web\.HttpException|undefined method .* for)").unwrap()
});

static RE_SUSPICIOUS_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<!--[^>]*?(?:todo|fixme|hack|bug|xxx|password\s*=|secret\s*=|api.?key\s*=|token\s*=)[^>]*?-->").unwrap()
});

static RE_GENERATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta\s+name\s*=\s*"generator"\s+content\s*=\s*"([^"]+)""#).unwrap()
});

static RE_DIR_LISTING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:<title>Index of /|<h1>Index of /|Directory listing for /)").unwrap()
});

static RE_SESSION_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[;?&](jsessionid|phpsessid|sid|session_id|sessionid|aspsessionid)=[a-zA-Z0-9]{8,}").unwrap()
});

static RE_SENSITIVE_PARAM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[?&](password|passwd|pwd|secret|token|api_key|apikey|access_token|auth|authorization)=[^&]+").unwrap()
});

static RE_INSECURE_FORM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<form\s[^>]*action\s*=\s*["']http://[^"']+["']"#).unwrap()
});

pub fn scan_body(html: &str, page_url: &str) -> BodyScanReport {
    let mut findings = Vec::new();
    let is_https = page_url.starts_with("https://");

    // Private IP disclosure
    for cap in RE_PRIVATE_IP.captures_iter(html) {
        findings.push(BodyScanFinding {
            check: "private_ip".into(),
            detail: format!("Private IP address disclosed: {}", &cap[1]),
            severity: Severity::Medium,
        });
        break; // one finding per check type
    }

    // Stack traces / error messages
    if RE_STACK_TRACE.is_match(html) {
        findings.push(BodyScanFinding {
            check: "stack_trace".into(),
            detail: "Application error or stack trace detected in response body".into(),
            severity: Severity::High,
        });
    }

    // Suspicious HTML comments
    if RE_SUSPICIOUS_COMMENT.is_match(html) {
        findings.push(BodyScanFinding {
            check: "suspicious_comment".into(),
            detail: "HTML comment contains sensitive keywords (TODO/password/secret/token)".into(),
            severity: Severity::Medium,
        });
    }

    // Meta generator with version
    if let Some(cap) = RE_GENERATOR.captures(html) {
        let gen = &cap[1];
        if gen.chars().any(|c| c.is_ascii_digit()) {
            findings.push(BodyScanFinding {
                check: "generator_version".into(),
                detail: format!("CMS/framework version exposed via meta generator: {}", gen),
                severity: Severity::Medium,
            });
        }
    }

    // Directory listing
    if RE_DIR_LISTING.is_match(html) {
        findings.push(BodyScanFinding {
            check: "directory_listing".into(),
            detail: "Directory listing is enabled on this path".into(),
            severity: Severity::Medium,
        });
    }

    // Session ID in URL
    if RE_SESSION_URL.is_match(page_url) {
        findings.push(BodyScanFinding {
            check: "session_in_url".into(),
            detail: "Session identifier exposed in URL".into(),
            severity: Severity::High,
        });
    }

    // Sensitive parameters in URL
    if RE_SENSITIVE_PARAM.is_match(page_url) {
        findings.push(BodyScanFinding {
            check: "sensitive_url_param".into(),
            detail: "Sensitive parameter (password/token/key) in URL query string".into(),
            severity: Severity::High,
        });
    }

    // Insecure form action (HTTP on HTTPS page)
    if is_https && RE_INSECURE_FORM.is_match(html) {
        findings.push(BodyScanFinding {
            check: "insecure_form_action".into(),
            detail: "Form submits to HTTP URL from HTTPS page".into(),
            severity: Severity::High,
        });
    }

    let score_modifier = findings.iter().fold(0i32, |acc, f| {
        acc + match f.severity {
            Severity::Critical => -15,
            Severity::High => -10,
            Severity::Medium => -5,
            Severity::Low => -2,
            Severity::Info => 0,
        }
    }).max(-30);

    BodyScanReport { findings, score_modifier }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p ox-security body_scan`
Expected: 13 tests PASS

**Step 5: Wire into lib.rs and scoring**

Same pattern as Task 1:
- `lib.rs`: add `pub mod body_scan;`
- `scoring/mod.rs`: add `pub body_scan: BodyScanReport` to SecurityReport
- `scoring/aggregate.rs`: call `body_scan::scan_body(html, url)`, add `score_modifier`, count findings

**Step 6: Run all security tests**

Run: `cargo test -p ox-security`
Expected: All pass (68 + 13 = 81)

**Step 7: Commit**

```bash
git add crates/security/src/body_scan.rs crates/security/src/lib.rs crates/security/src/scoring/
git commit -m "feat(security): add body scanner module

Detect private IPs, stack traces, suspicious comments, generator versions,
directory listings, session IDs in URLs, sensitive URL params, insecure forms.
13 new tests."
```

---

### Task 3: Vulnerable JS Library Detection

Match `<script src>` URLs against a bundled database of known-vulnerable JavaScript libraries. Based on Retire.js patterns.

**Files:**
- Create: `crates/security/src/vuln_js.rs`
- Modify: `crates/security/src/lib.rs`
- Modify: `crates/security/src/scoring/mod.rs`
- Modify: `crates/security/src/scoring/aggregate.rs`

**Step 1: Write the failing test**

Add to `crates/security/src/vuln_js.rs`:

```rust
use regex::Regex;
use std::sync::LazyLock;
use crate::types::Severity;

#[derive(Debug, Clone, serde::Serialize)]
pub struct VulnJsReport {
    pub libraries: Vec<DetectedLibrary>,
    pub findings: Vec<VulnJsFinding>,
    pub score_modifier: i32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectedLibrary {
    pub name: String,
    pub version: String,
    pub source_url: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VulnJsFinding {
    pub library: String,
    pub version: String,
    pub severity: Severity,
    pub description: String,
}

pub fn detect_vulnerable_js(html: &str) -> VulnJsReport {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jquery_old_version() {
        let html = r#"<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>"#;
        let report = detect_vulnerable_js(html);
        assert_eq!(report.libraries.len(), 1);
        assert_eq!(report.libraries[0].name, "jQuery");
        assert_eq!(report.libraries[0].version, "1.12.4");
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn test_jquery_safe_version() {
        let html = r#"<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>"#;
        let report = detect_vulnerable_js(html);
        assert_eq!(report.libraries.len(), 1);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_angularjs_vulnerable() {
        let html = r#"<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>"#;
        let report = detect_vulnerable_js(html);
        assert_eq!(report.libraries.len(), 1);
        assert_eq!(report.libraries[0].name, "AngularJS");
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn test_bootstrap_3() {
        let html = r#"<script src="/assets/js/bootstrap.min.js?v=3.3.7"></script>"#;
        let report = detect_vulnerable_js(html);
        assert_eq!(report.libraries.len(), 1);
        assert_eq!(report.libraries[0].name, "Bootstrap");
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn test_multiple_libraries() {
        let html = r#"
            <script src="https://code.jquery.com/jquery-2.1.4.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/lodash@4.17.10/lodash.min.js"></script>
        "#;
        let report = detect_vulnerable_js(html);
        assert!(report.libraries.len() >= 2);
    }

    #[test]
    fn test_no_scripts() {
        let html = r#"<html><body>Hello</body></html>"#;
        let report = detect_vulnerable_js(html);
        assert!(report.libraries.is_empty());
        assert!(report.findings.is_empty());
        assert_eq!(report.score_modifier, 0);
    }

    #[test]
    fn test_react_no_vuln_detection() {
        // React is detected but modern version = no finding
        let html = r#"<script src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script>"#;
        let report = detect_vulnerable_js(html);
        assert_eq!(report.libraries.len(), 1);
        assert_eq!(report.libraries[0].name, "React");
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_score_modifier_for_vulnerable() {
        let html = r#"<script src="https://code.jquery.com/jquery-1.6.0.min.js"></script>"#;
        let report = detect_vulnerable_js(html);
        assert!(report.score_modifier < 0);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p ox-security vuln_js`
Expected: FAIL (todo!())

**Step 3: Write minimal implementation**

Replace `todo!()`. The approach: a hardcoded database of ~15 most common libraries with version regex patterns and vulnerability thresholds. Not a full Retire.js port — that would be thousands of entries. Focus on the libraries that appear on 90%+ of vulnerable sites.

```rust
struct LibraryDef {
    name: &'static str,
    url_pattern: &'static str,           // regex to match in <script src>
    version_capture: usize,              // capture group index for version
    vuln_below: &'static str,            // versions below this are vulnerable
    severity: Severity,
    description: &'static str,
}

const LIBRARY_DB: &[LibraryDef] = &[
    LibraryDef {
        name: "jQuery",
        url_pattern: r"jquery[.-](\d+\.\d+\.\d+)",
        version_capture: 1,
        vuln_below: "3.5.0",
        severity: Severity::Medium,
        description: "jQuery < 3.5.0 has XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023)",
    },
    LibraryDef {
        name: "AngularJS",
        url_pattern: r"angular(?:js)?[/.-](\d+\.\d+\.\d+)",
        version_capture: 1,
        vuln_below: "1.8.0",
        severity: Severity::High,
        description: "AngularJS < 1.8.0 has multiple XSS and sandbox escape vulnerabilities",
    },
    LibraryDef {
        name: "Bootstrap",
        url_pattern: r"bootstrap(?:\.min)?\.js\??(?:v=)?(\d+\.\d+\.\d+)?",
        version_capture: 1,
        vuln_below: "3.4.0",
        severity: Severity::Medium,
        description: "Bootstrap < 3.4.0 has XSS vulnerabilities (CVE-2018-14041, CVE-2019-8331)",
    },
    LibraryDef {
        name: "Lodash",
        url_pattern: r"lodash[@/.-](\d+\.\d+\.\d+)",
        version_capture: 1,
        vuln_below: "4.17.21",
        severity: Severity::Medium,
        description: "Lodash < 4.17.21 has prototype pollution (CVE-2021-23337)",
    },
    LibraryDef {
        name: "React",
        url_pattern: r"react[@/.-](\d+\.\d+\.\d+)",
        version_capture: 1,
        vuln_below: "16.4.2",
        severity: Severity::Medium,
        description: "React < 16.4.2 has XSS in SSR (CVE-2018-6341)",
    },
    LibraryDef {
        name: "Vue.js",
        url_pattern: r"vue[@/.-](\d+\.\d+\.\d+)",
        version_capture: 1,
        vuln_below: "2.5.17",
        severity: Severity::Medium,
        description: "Vue.js < 2.5.17 has prototype pollution vulnerability",
    },
    LibraryDef {
        name: "Moment.js",
        url_pattern: r"moment(?:\.min)?\.js\??(?:v=)?(\d+\.\d+\.\d+)?",
        version_capture: 1,
        vuln_below: "2.29.4",
        severity: Severity::Low,
        description: "Moment.js < 2.29.4 has path traversal (CVE-2022-24785)",
    },
    LibraryDef {
        name: "Handlebars",
        url_pattern: r"handlebars(?:\.min)?\.js\??(?:v=)?(\d+\.\d+\.\d+)?",
        version_capture: 1,
        vuln_below: "4.7.7",
        severity: Severity::High,
        description: "Handlebars < 4.7.7 has prototype pollution (CVE-2021-23369)",
    },
    LibraryDef {
        name: "DOMPurify",
        url_pattern: r"(?:dompurify|purify)[@/.-](\d+\.\d+\.\d+)",
        version_capture: 1,
        vuln_below: "2.4.0",
        severity: Severity::High,
        description: "DOMPurify < 2.4.0 has mXSS bypass vulnerabilities",
    },
];

static RE_SCRIPT_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<script\s[^>]*src\s*=\s*["']([^"']+)["']"#).unwrap()
});

pub fn detect_vulnerable_js(html: &str) -> VulnJsReport {
    let mut libraries = Vec::new();
    let mut findings = Vec::new();

    let script_urls: Vec<String> = RE_SCRIPT_SRC.captures_iter(html)
        .map(|c| c[1].to_string())
        .collect();

    for lib_def in LIBRARY_DB {
        let re = Regex::new(lib_def.url_pattern).unwrap();
        for url in &script_urls {
            if let Some(cap) = re.captures(url) {
                let version = cap.get(lib_def.version_capture)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                if version.is_empty() {
                    continue;
                }
                libraries.push(DetectedLibrary {
                    name: lib_def.name.to_string(),
                    version: version.clone(),
                    source_url: url.clone(),
                });
                if version_below(&version, lib_def.vuln_below) {
                    findings.push(VulnJsFinding {
                        library: lib_def.name.to_string(),
                        version: version.clone(),
                        severity: lib_def.severity,
                        description: lib_def.description.to_string(),
                    });
                }
                break; // one match per library
            }
        }
    }

    let score_modifier = findings.iter().fold(0i32, |acc, f| {
        acc + match f.severity {
            Severity::Critical => -15,
            Severity::High => -10,
            Severity::Medium => -5,
            Severity::Low => -2,
            Severity::Info => 0,
        }
    }).max(-25);

    VulnJsReport { libraries, findings, score_modifier }
}

/// Compare semver strings: returns true if `version` < `threshold`.
fn version_below(version: &str, threshold: &str) -> bool {
    let parse = |s: &str| -> (u32, u32, u32) {
        let parts: Vec<u32> = s.split('.').filter_map(|p| p.parse().ok()).collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    };
    parse(version) < parse(threshold)
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p ox-security vuln_js`
Expected: 8 tests PASS

**Step 5: Wire into lib.rs and scoring**

Same pattern:
- `lib.rs`: add `pub mod vuln_js;`
- `scoring/mod.rs`: add `pub vuln_js: VulnJsReport` to SecurityReport
- `scoring/aggregate.rs`: call `vuln_js::detect_vulnerable_js(html)`, add `score_modifier`, count findings

**Step 6: Run all security tests**

Run: `cargo test -p ox-security`
Expected: All pass (81 + 8 = 89)

**Step 7: Commit**

```bash
git add crates/security/src/vuln_js.rs crates/security/src/lib.rs crates/security/src/scoring/
git commit -m "feat(security): add vulnerable JS library detection

Detect known-vulnerable versions of jQuery, AngularJS, Bootstrap, Lodash,
React, Vue.js, Moment.js, Handlebars, DOMPurify from script URLs.
8 new tests."
```

---

### Task 4: Enhanced Existing Modules

Improve CORS (origin reflection detection), headers (Clear-Site-Data, Content-Type charset), and HSTS (preload awareness).

**Files:**
- Modify: `crates/security/src/cors.rs`
- Modify: `crates/security/src/headers/checks.rs`
- Modify: `crates/security/src/headers/tests.rs`

**Step 1: Enhance CORS — add origin reflection detection**

In `crates/security/src/cors.rs`, the current code only checks for `ACAO: *`. Add detection of origin reflection pattern. Since we can't send a custom Origin header in passive mode, detect the dangerous pattern: `ACAO` is set to a specific origin AND `ACAC: true`. This combo typically means the server reflects any origin.

Add test:

```rust
#[test]
fn test_cors_reflected_origin_with_credentials() {
    let headers = h(&[
        ("access-control-allow-origin", "https://some-origin.com"),
        ("access-control-allow-credentials", "true"),
    ]);
    let report = analyze_cors(&headers);
    assert!(report.findings.iter().any(|f| f.severity == Severity::High));
    assert!(report.score_modifier <= -20);
}

#[test]
fn test_cors_specific_origin_without_credentials() {
    let headers = h(&[
        ("access-control-allow-origin", "https://trusted.example.com"),
    ]);
    let report = analyze_cors(&headers);
    assert!(report.findings.is_empty() || report.findings.iter().all(|f| f.severity == Severity::Info));
}
```

Implementation: in `analyze_cors()`, after the wildcard check, add:

```rust
// Origin reflection + credentials = dangerous
if let Some(acao) = headers.get("access-control-allow-origin") {
    if acao != "*" && !acao.is_empty() {
        let acac = headers.get("access-control-allow-credentials")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if acac {
            findings.push(CorsFinding {
                description: format!(
                    "CORS allows credentials with specific origin '{}' — if server reflects Origin header, this enables credential theft",
                    acao
                ),
                severity: Severity::High,
            });
            score_modifier = score_modifier.min(-20);
        }
    }
}
```

**Step 2: Add Clear-Site-Data header check**

In `crates/security/src/headers/checks.rs`, add:

```rust
pub fn check_clear_site_data(headers: &HashMap<String, String>) -> HeaderFinding {
    match headers.get("clear-site-data") {
        Some(val) => HeaderFinding {
            header: "clear-site-data".into(),
            status: HeaderStatus::Present,
            value: Some(val.clone()),
            description: "Clear-Site-Data header present — helps with secure logout flows".into(),
            severity: Severity::Info,
            recommendation: None,
        },
        None => HeaderFinding {
            header: "clear-site-data".into(),
            status: HeaderStatus::Missing,
            value: None,
            description: "Clear-Site-Data header not set".into(),
            severity: Severity::Info, // informational, not penalized
            recommendation: Some("Consider adding Clear-Site-Data for logout endpoints".into()),
        },
    }
}
```

In `headers/mod.rs`, add `checks::check_clear_site_data(headers)` to the findings vec.

**Step 3: Add Content-Type charset check**

In `crates/security/src/headers/checks.rs`, add:

```rust
pub fn check_content_type_charset(headers: &HashMap<String, String>) -> Option<HeaderFinding> {
    let ct = headers.get("content-type")?;
    if ct.contains("text/html") && !ct.to_lowercase().contains("charset") {
        Some(HeaderFinding {
            header: "content-type".into(),
            status: HeaderStatus::Present,
            value: Some(ct.clone()),
            description: "Content-Type header missing charset declaration — charset sniffing possible".into(),
            severity: Severity::Low,
            recommendation: Some("Add charset=utf-8 to Content-Type header".into()),
        })
    } else {
        None
    }
}
```

In `headers/mod.rs`, add:
```rust
if let Some(f) = checks::check_content_type_charset(headers) {
    findings.push(f);
}
```

**Step 4: Add tests for new checks**

In `crates/security/src/headers/tests.rs`, add:

```rust
#[test]
fn test_clear_site_data_present() {
    let headers = h(&[("clear-site-data", r#""cache", "cookies""#)]);
    let report = analyze_headers(&headers);
    let f = report.findings.iter().find(|f| f.header == "clear-site-data").unwrap();
    assert_eq!(f.status, HeaderStatus::Present);
}

#[test]
fn test_content_type_missing_charset() {
    let headers = h(&[("content-type", "text/html")]);
    let report = analyze_headers(&headers);
    let f = report.findings.iter().find(|f| f.header == "content-type" && f.description.contains("charset"));
    assert!(f.is_some());
}

#[test]
fn test_content_type_with_charset_ok() {
    let headers = h(&[("content-type", "text/html; charset=utf-8")]);
    let report = analyze_headers(&headers);
    let f = report.findings.iter().find(|f| f.header == "content-type" && f.description.contains("charset"));
    assert!(f.is_none());
}
```

**Step 5: Update total_checked in test_all_missing**

The test `test_all_missing` asserts `total_checked == 15`. After adding `clear-site-data` it becomes 16. Update:
```rust
assert_eq!(report.total_checked, 16);
```

Also update `test_full_secure_headers` to include `clear-site-data`.

**Step 6: Run all security tests**

Run: `cargo test -p ox-security`
Expected: All pass (89 + 5 new = 94)

**Step 7: Commit**

```bash
git add crates/security/src/cors.rs crates/security/src/headers/
git commit -m "feat(security): enhance CORS, add Clear-Site-Data and Content-Type charset checks

CORS: detect origin reflection + credentials combo (High severity).
Headers: add Clear-Site-Data check, Content-Type charset validation.
5 new tests."
```

---

### Task 5: Scoring Update + Integration + Deploy

Update scoring to include all new modules, rebuild Docker, run end-to-end test.

**Files:**
- Modify: `crates/security/src/scoring/aggregate.rs` (verify all wiring complete)
- Modify: `crates/security/src/scoring/mod.rs` (verify SecurityReport fields)

**Step 1: Verify scoring integration**

Ensure `SecurityReport` has all fields:
```rust
pub struct SecurityReport {
    pub url: String,
    pub score: i32,
    pub grade: String,
    pub headers: HeadersReport,
    pub csp: Option<CspReport>,
    pub cookies: CookieReport,
    pub cors: CorsReport,
    pub sri: SriReport,
    pub supply_chain: SupplyChainReport,
    pub mixed_content: MixedContentReport,
    pub info_disclosure: InfoDisclosureReport,    // NEW
    pub body_scan: BodyScanReport,               // NEW
    pub vuln_js: VulnJsReport,                   // NEW
    pub findings_summary: FindingsSummary,
}
```

**Step 2: Add integration test**

In `crates/security/src/scoring/mod.rs`, add:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ... existing tests ...

    #[test]
    fn test_full_scan_with_all_modules() {
        let headers: HashMap<String, String> = [
            ("server", "nginx/1.18.0"),          // info_disclosure finding
            ("x-powered-by", "Express"),          // info_disclosure finding
        ].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();

        let html = r#"
            <html>
            <head>
                <meta name="generator" content="WordPress 6.4.2">
                <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
            </head>
            <body>
                <!-- TODO: fix this password=admin -->
                <p>Debug: 192.168.1.1</p>
            </body>
            </html>
        "#;

        let report = analyze_security(
            "https://example.com",
            &headers,
            &[],
            html,
        );

        // Should have findings from multiple modules
        assert!(report.findings_summary.total > 0);
        assert!(!report.info_disclosure.findings.is_empty());
        assert!(!report.body_scan.findings.is_empty());
        assert!(!report.vuln_js.findings.is_empty());
        // Score should be lower than base 100 due to all findings
        assert!(report.score < 100);
    }
}
```

**Step 3: Run all tests**

Run: `cargo test -p ox-security`
Expected: All pass (~95 tests)

**Step 4: Build and deploy Docker**

```bash
cd ~/deploy/krolik-server
docker compose build --no-cache ox-browser
docker compose up -d --no-deps --force-recreate ox-browser
```

**Step 5: Smoke test via curl**

```bash
curl -s -X POST http://127.0.0.1:8901/security \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}' | jq '{score, grade, info_disclosure: .info_disclosure.findings | length, body_scan: .body_scan.findings | length, vuln_js: .vuln_js.libraries | length}'
```

Expected: JSON with score, grade, and counts from new modules.

**Step 6: Version bump and tag**

In root `Cargo.toml`: bump version `"0.4.0"` → `"0.4.5"`

```bash
git add Cargo.toml
git commit -m "chore: bump version to 0.4.5"
git tag v0.4.5
git push origin main --tags
```

**Step 7: Update ROADMAP**

Mark Phase 4.5a, 4.5b, 4.5c, 4.5d as complete in `docs/ROADMAP.md`.

```bash
git add docs/ROADMAP.md
git commit -m "docs: mark Phase 4.5a-d complete in roadmap"
```
