//! Body scanner — regex-based detection of security issues in HTML body content.

use std::net::Ipv4Addr;
use std::sync::LazyLock;

use ipnet::Ipv4Net;
use regex::Regex;
use serde::Serialize;

use super::types::Severity;

#[derive(Debug, Clone, Serialize)]
pub struct BodyScanReport {
    pub findings: Vec<BodyScanFinding>,
    pub score_modifier: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct BodyScanFinding {
    pub check: String,
    pub detail: String,
    pub severity: Severity,
}

macro_rules! lazy_re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).unwrap());
    };
}

lazy_re!(RE_IPV4, r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b");
lazy_re!(RE_STACK_JAVA, r"at\s+[\w.]+\.\w+\(\w+\.java:\d+\)");
lazy_re!(RE_STACK_PYTHON, r"Traceback \(most recent call last\)");
lazy_re!(RE_STACK_PHP, r"Fatal error.*in /.*:\d+");
lazy_re!(RE_STACK_DOTNET, r"(?:NullReferenceException|System\.Web\.HttpException)");
lazy_re!(RE_STACK_RUBY, r"undefined method");
lazy_re!(RE_COMMENT, r"<!--([\s\S]*?)-->");
lazy_re!(RE_COMMENT_SENSITIVE, r"(?i)\b(TODO|FIXME|HACK|BUG|XXX)\b|(?i)(password|secret|api_key|token)\s*=");
lazy_re!(RE_META_GEN, r#"(?i)<meta\s+name\s*=\s*["']generator["']\s+content\s*=\s*["']([^"']*\d[^"']*)["']"#);
lazy_re!(RE_DIR_LISTING, r"(?i)<(?:title|h1)>Index of /|Directory listing for /");
lazy_re!(RE_SESSION_URL, r"(?i)(?:jsessionid|phpsessid|sid|session_id|sessionid|aspsessionid)[=;][A-Za-z0-9]{8,}");
lazy_re!(RE_SENSITIVE_PARAM, r"(?i)[?&](password|passwd|pwd|secret|token|api_key|apikey|access_token|auth|authorization)=");
lazy_re!(RE_INSECURE_FORM, r#"(?i)<form\s[^>]*action\s*=\s*["']http://[^"']*["']"#);
lazy_re!(RE_EVENT_HANDLER, r#"(?i)\bon\w+\s*=\s*["']"#);
lazy_re!(RE_JS_URL, r#"(?i)javascript\s*:"#);
lazy_re!(RE_SOURCE_MAP, r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)");
lazy_re!(RE_POST_FORM, r#"(?i)<form\b[^>]*method\s*=\s*["']?post["']?[^>]*>([\s\S]*?)</form>"#);

fn severity_penalty(sev: Severity) -> i32 {
    match sev {
        Severity::Critical => -15, Severity::High => -10,
        Severity::Medium => -5, Severity::Low => -2, Severity::Info => 0,
    }
}

/// Scan HTML body and page URL for security-sensitive patterns.
pub fn scan_body(html: &str, page_url: &str) -> BodyScanReport {
    let mut f = Vec::new();
    // 1. Private IP disclosure (CIDR-based via ipnet)
    if let Some(ip_str) = find_private_ip(html) {
        f.push(finding("private_ip", &format!("Private IP found: {ip_str}"), Severity::Medium));
    }
    // 2. Stack trace detection
    let traces: &[(&LazyLock<Regex>, &str)] = &[
        (&RE_STACK_JAVA, "Java"), (&RE_STACK_PYTHON, "Python"), (&RE_STACK_PHP, "PHP"),
        (&RE_STACK_DOTNET, ".NET"), (&RE_STACK_RUBY, "Ruby"),
    ];
    for &(re, lang) in traces {
        if re.is_match(html) {
            f.push(finding("stack_trace", &format!("{lang} stack trace detected"), Severity::High));
            break;
        }
    }
    // 3. Suspicious HTML comments
    for cap in RE_COMMENT.captures_iter(html) {
        if RE_COMMENT_SENSITIVE.is_match(&cap[1]) {
            let snippet: String = cap[1].chars().take(80).collect();
            f.push(finding("suspicious_comment", &format!("Suspicious comment: {snippet}"), Severity::Medium));
            break;
        }
    }
    // 4. Meta generator with version
    if let Some(cap) = RE_META_GEN.captures(html) {
        f.push(finding("generator_version", &format!("Generator with version: {}", &cap[1]), Severity::Medium));
    }
    // 5. Directory listing
    if RE_DIR_LISTING.is_match(html) {
        f.push(finding("directory_listing", "Directory listing detected", Severity::Medium));
    }
    // 6. Session ID in URL
    if RE_SESSION_URL.is_match(page_url) {
        f.push(finding("session_in_url", "Session ID exposed in URL", Severity::High));
    }
    // 7. Sensitive params in URL
    if RE_SENSITIVE_PARAM.is_match(page_url) {
        f.push(finding("sensitive_url_param", "Sensitive parameter in URL", Severity::High));
    }
    // 8. Insecure form action on HTTPS page
    if page_url.starts_with("https://") && RE_INSECURE_FORM.is_match(html) {
        f.push(finding("insecure_form_action", "Form submits to insecure HTTP endpoint", Severity::High));
    }
    // 9. XSS pattern detection via ammonia
    f.extend(check_xss_patterns(html));
    // 10. Exposed source maps
    f.extend(check_source_maps(html));
    // 11. POST forms without CSRF token
    f.extend(check_csrf_in_forms(html));
    let raw: i32 = f.iter().map(|x| severity_penalty(x.severity)).sum();
    BodyScanReport { findings: f, score_modifier: raw.max(-30) }
}

/// Detect XSS patterns by comparing original HTML with ammonia-sanitized output.
fn check_xss_patterns(html: &str) -> Vec<BodyScanFinding> {
    let cleaned = ammonia::clean(html);
    let mut findings = Vec::new();

    let orig_events = RE_EVENT_HANDLER.find_iter(html).count();
    let clean_events = RE_EVENT_HANDLER.find_iter(&cleaned).count();
    if orig_events > clean_events {
        let stripped = orig_events - clean_events;
        findings.push(finding(
            "xss_event_handlers",
            &format!("{stripped} inline event handler(s) detected"),
            Severity::Medium,
        ));
    }

    if RE_JS_URL.is_match(html) && !RE_JS_URL.is_match(&cleaned) {
        findings.push(finding(
            "xss_javascript_url",
            "javascript: URL scheme detected in HTML",
            Severity::High,
        ));
    }

    findings
}

/// Detect POST forms without hidden CSRF token fields.
fn check_csrf_in_forms(html: &str) -> Vec<BodyScanFinding> {
    let mut findings = Vec::new();
    const CSRF_NAMES: &[&str] = &[
        "csrf", "xsrf", "_token", "authenticity_token",
        "__requestverificationtoken", "csrfmiddlewaretoken",
    ];
    let hidden_re = Regex::new(
        r#"(?i)<input\b[^>]*type\s*=\s*["']?hidden["']?[^>]*name\s*=\s*["']([^"']+)["']"#,
    ).unwrap();
    for cap in RE_POST_FORM.captures_iter(html) {
        let form_body = &cap[1];
        let has_csrf = hidden_re.captures_iter(form_body).any(|input_cap| {
            let name = input_cap[1].to_lowercase();
            CSRF_NAMES.iter().any(|p| name.contains(p))
        });
        if !has_csrf {
            findings.push(finding(
                "form_no_csrf_token",
                "POST form without apparent CSRF token field",
                Severity::Medium,
            ));
            break;
        }
    }
    findings
}

/// Detect exposed source map references in inline scripts.
fn check_source_maps(html: &str) -> Vec<BodyScanFinding> {
    let mut findings = Vec::new();
    if let Some(cap) = RE_SOURCE_MAP.captures(html) {
        findings.push(finding(
            "exposed_source_map",
            &format!("Source map reference found: {}", &cap[1]),
            Severity::Medium,
        ));
    }
    findings
}

/// Private/reserved CIDR ranges to detect in HTML bodies.
static PRIVATE_NETS: LazyLock<Vec<Ipv4Net>> = LazyLock::new(|| {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect()
});

/// Find the first private/reserved IPv4 address in the text.
fn find_private_ip(text: &str) -> Option<String> {
    for m in RE_IPV4.find_iter(text) {
        if let Ok(addr) = m.as_str().parse::<Ipv4Addr>() {
            if PRIVATE_NETS.iter().any(|net: &Ipv4Net| net.contains(&addr)) {
                return Some(m.as_str().to_string());
            }
        }
    }
    None
}

fn finding(check: &str, detail: &str, severity: Severity) -> BodyScanFinding {
    BodyScanFinding { check: check.to_string(), detail: detail.to_string(), severity }
}

#[cfg(test)]
mod tests;
