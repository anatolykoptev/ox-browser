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
    let raw: i32 = f.iter().map(|x| severity_penalty(x.severity)).sum();
    BodyScanReport { findings: f, score_modifier: raw.max(-30) }
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
mod tests {
    use super::*;
    const URL: &str = "https://example.com";

    #[test]
    fn test_private_ip_in_body() {
        let r = scan_body("Server at 192.168.1.100 responded", URL);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].check, "private_ip");
    }
    #[test]
    fn test_no_false_positive_public_ip() {
        let r = scan_body("DNS at 8.8.8.8", URL);
        assert!(r.findings.iter().all(|f| f.check != "private_ip"));
    }
    #[test]
    fn test_java_stack_trace() {
        let r = scan_body("at com.example.App.main(App.java:42)", URL);
        assert_eq!(r.findings[0].check, "stack_trace");
        assert_eq!(r.findings[0].severity, Severity::High);
    }
    #[test]
    fn test_python_traceback() {
        let r = scan_body("Traceback (most recent call last)", URL);
        assert_eq!(r.findings[0].check, "stack_trace");
    }
    #[test]
    fn test_php_error() {
        let r = scan_body("Fatal error: something in /var/www/app.php:123", URL);
        assert_eq!(r.findings[0].check, "stack_trace");
    }
    #[test]
    fn test_suspicious_comment() {
        let r = scan_body("<!-- TODO: remove hardcoded password=admin123 -->", URL);
        assert!(r.findings.iter().any(|f| f.check == "suspicious_comment"));
    }
    #[test]
    fn test_normal_comment_no_finding() {
        let r = scan_body("<!-- Navigation section -->", URL);
        assert!(r.findings.iter().all(|f| f.check != "suspicious_comment"));
    }
    #[test]
    fn test_meta_generator_version() {
        let r = scan_body(r#"<meta name="generator" content="WordPress 6.4.2">"#, URL);
        assert!(r.findings.iter().any(|f| f.check == "generator_version"));
    }
    #[test]
    fn test_directory_listing() {
        let r = scan_body("<title>Index of /uploads</title>", URL);
        assert!(r.findings.iter().any(|f| f.check == "directory_listing"));
    }
    #[test]
    fn test_session_id_in_url() {
        let r = scan_body("", "https://example.com/app;jsessionid=ABC123DEF456");
        assert!(r.findings.iter().any(|f| f.check == "session_in_url"));
    }
    #[test]
    fn test_sensitive_param_in_url() {
        let r = scan_body("", "https://example.com/?token=abc123&password=secret");
        assert!(r.findings.iter().any(|f| f.check == "sensitive_url_param"));
    }
    #[test]
    fn test_insecure_form_action() {
        let html = r#"<form action="http://evil.com/login" method="post">"#;
        let r = scan_body(html, URL);
        assert!(r.findings.iter().any(|f| f.check == "insecure_form_action"));
    }
    #[test]
    fn test_loopback_ip_detected() {
        let r = scan_body("Connected to 127.0.0.1 on port 8080", URL);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].check, "private_ip");
        assert!(r.findings[0].detail.contains("127.0.0.1"));
    }
    #[test]
    fn test_no_false_positive_near_private_ip() {
        let r = scan_body("Upstream server 11.0.0.1 responded OK", URL);
        assert!(r.findings.iter().all(|f| f.check != "private_ip"));
    }
    #[test]
    fn test_clean_page() {
        let r = scan_body("<html><body><p>Hello world</p></body></html>", URL);
        assert!(r.findings.is_empty());
        assert_eq!(r.score_modifier, 0);
    }
}
