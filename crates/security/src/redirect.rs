//! Redirect and HTTPS analysis — checks URL transport security properties.

use std::collections::HashMap;

use serde::Serialize;

use super::types::Severity;

#[derive(Debug, Clone, Serialize)]
pub struct RedirectReport {
    pub is_https: bool,
    pub findings: Vec<RedirectFinding>,
    pub score_modifier: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedirectFinding {
    pub description: String,
    pub severity: Severity,
}

/// Analyze URL security properties (HTTPS, mixed signals).
/// `url` is the scanned URL, `resp_headers` can contain Location for redirect detection.
pub fn analyze_redirect(
    url: &str,
    resp_headers: &HashMap<String, String>,
) -> RedirectReport {
    let mut findings = Vec::new();
    let is_https = url.starts_with("https://");

    // 1. HTTP site detection (no HTTPS)
    if !is_https {
        findings.push(RedirectFinding {
            description: "Site served over HTTP — no encryption".into(),
            severity: Severity::Critical,
        });
    }

    // 2. Check if response has Location header (redirect)
    if let Some(location) = resp_headers.get("location") {
        // Redirect from HTTPS to HTTP = downgrade
        if is_https && location.starts_with("http://") {
            findings.push(RedirectFinding {
                description: format!(
                    "HTTPS downgrade: redirects to HTTP URL: {location}"
                ),
                severity: Severity::High,
            });
        }

        // Redirect to different host
        let orig_host = extract_host(url);
        let dest_host = extract_host(location);
        if !orig_host.is_empty()
            && !dest_host.is_empty()
            && orig_host != dest_host
        {
            findings.push(RedirectFinding {
                description: format!(
                    "Cross-host redirect: {orig_host} → {dest_host}"
                ),
                severity: Severity::Info,
            });
        }
    }

    let score_modifier = compute_modifier(is_https, &findings);

    RedirectReport {
        is_https,
        findings,
        score_modifier,
    }
}

fn compute_modifier(is_https: bool, findings: &[RedirectFinding]) -> i32 {
    let base = if is_https { 0 } else { -20 };
    let high_penalty = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count() as i32
        * -10;
    (base + high_penalty).max(-30)
}

fn extract_host(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::types::Severity;

    #[test]
    fn test_https_url_clean() {
        let headers = HashMap::new();
        let r = analyze_redirect("https://example.com", &headers);
        assert!(r.is_https);
        assert!(r.findings.is_empty());
        assert_eq!(r.score_modifier, 0);
    }

    #[test]
    fn test_http_url_critical() {
        let headers = HashMap::new();
        let r = analyze_redirect("http://example.com", &headers);
        assert!(!r.is_https);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Critical));
        assert!(r.score_modifier < 0);
    }

    #[test]
    fn test_https_to_http_downgrade() {
        let mut headers = HashMap::new();
        headers.insert(
            "location".to_string(),
            "http://example.com/page".to_string(),
        );
        let r = analyze_redirect("https://example.com", &headers);
        assert!(r.findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_cross_host_redirect() {
        let mut headers = HashMap::new();
        headers.insert(
            "location".to_string(),
            "https://other.com/page".to_string(),
        );
        let r = analyze_redirect("https://example.com", &headers);
        assert!(r
            .findings
            .iter()
            .any(|f| f.description.contains("Cross-host")));
    }

    #[test]
    fn test_same_host_redirect_ok() {
        let mut headers = HashMap::new();
        headers.insert(
            "location".to_string(),
            "https://example.com/new-page".to_string(),
        );
        let r = analyze_redirect("https://example.com/old", &headers);
        assert!(r
            .findings
            .iter()
            .all(|f| f.severity != Severity::High));
    }
}
