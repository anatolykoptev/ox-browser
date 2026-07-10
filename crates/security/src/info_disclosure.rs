//! Information disclosure detection — flags HTTP headers that leak internal details.

use std::collections::HashMap;

use serde::Serialize;

use super::types::Severity;

#[derive(Debug, Clone, Serialize)]
pub struct InfoDisclosureReport {
    pub findings: Vec<InfoDisclosureFinding>,
    pub score_modifier: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct InfoDisclosureFinding {
    pub header: String,
    pub value: String,
    pub description: String,
    pub severity: Severity,
}

const FORBIDDEN_HEADERS: &[(&str, Severity, &str)] = &[
    (
        "x-powered-by",
        Severity::Medium,
        "Exposes server technology",
    ),
    (
        "x-aspnet-version",
        Severity::Medium,
        "Exposes ASP.NET version",
    ),
    (
        "x-aspnetmvc-version",
        Severity::Medium,
        "Exposes ASP.NET MVC version",
    ),
    ("x-generator", Severity::Medium, "Exposes site generator"),
    (
        "x-backend-server",
        Severity::High,
        "Exposes internal backend hostname",
    ),
    (
        "x-debug-token",
        Severity::High,
        "Debug token exposed in production",
    ),
    (
        "x-debug-token-link",
        Severity::High,
        "Debug profiler link exposed in production",
    ),
    (
        "x-chromelogger-data",
        Severity::High,
        "ChromeLogger debug data exposed",
    ),
    (
        "x-runtime",
        Severity::Low,
        "Exposes server-side timing information",
    ),
];

const DEPRECATED_HEADERS: &[(&str, &str)] = &[
    (
        "public-key-pins",
        "HPKP deprecated, no longer supported by browsers",
    ),
    ("expect-ct", "Expect-CT deprecated since Chrome 107"),
];

fn severity_penalty(sev: Severity) -> i32 {
    match sev {
        Severity::Critical => -15,
        Severity::High => -10,
        Severity::Medium => -5,
        Severity::Low => -2,
        Severity::Info => 0,
    }
}

fn server_has_version(value: &str) -> bool {
    if let Some(pos) = value.find('/') {
        value[pos + 1..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
    } else {
        false
    }
}

/// Analyze response headers for information disclosure.
pub fn analyze_info_disclosure(headers: &HashMap<String, String>) -> InfoDisclosureReport {
    let mut findings = Vec::new();

    // Check forbidden headers.
    for &(name, severity, desc) in FORBIDDEN_HEADERS {
        if let Some(value) = headers.get(name) {
            findings.push(InfoDisclosureFinding {
                header: name.to_string(),
                value: value.clone(),
                description: desc.to_string(),
                severity,
            });
        }
    }

    // Check server header for version disclosure.
    if let Some(value) = headers.get("server")
        && server_has_version(value)
    {
        findings.push(InfoDisclosureFinding {
            header: "server".to_string(),
            value: value.clone(),
            description: "Server header discloses version information".to_string(),
            severity: Severity::Medium,
        });
    }

    // Check deprecated headers.
    for &(name, desc) in DEPRECATED_HEADERS {
        if let Some(value) = headers.get(name) {
            findings.push(InfoDisclosureFinding {
                header: name.to_string(),
                value: value.clone(),
                description: desc.to_string(),
                severity: Severity::Low,
            });
        }
    }

    let raw: i32 = findings.iter().map(|f| severity_penalty(f.severity)).sum();
    let score_modifier = raw.max(-30);

    InfoDisclosureReport {
        findings,
        score_modifier,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_server_with_version() {
        let r = analyze_info_disclosure(&h(&[("server", "nginx/1.18.0")]));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_server_without_version() {
        let r = analyze_info_disclosure(&h(&[("server", "nginx")]));
        assert!(r.findings.is_empty());
    }

    #[test]
    fn test_x_powered_by() {
        let r = analyze_info_disclosure(&h(&[("x-powered-by", "PHP/8.1.2")]));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_debug_headers_high_severity() {
        let r = analyze_info_disclosure(&h(&[
            ("x-debug-token", "abc123"),
            ("x-debug-token-link", "https://example.com/_profiler/abc123"),
        ]));
        assert_eq!(r.findings.len(), 2);
        assert!(r.findings.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_backend_server_disclosure() {
        let r = analyze_info_disclosure(&h(&[("x-backend-server", "web-node-03.internal")]));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].severity, Severity::High);
    }

    #[test]
    fn test_aspnet_version() {
        let r = analyze_info_disclosure(&h(&[
            ("x-aspnet-version", "4.0.30319"),
            ("x-aspnetmvc-version", "5.2"),
        ]));
        assert_eq!(r.findings.len(), 2);
    }

    #[test]
    fn test_deprecated_headers() {
        let r = analyze_info_disclosure(&h(&[
            ("public-key-pins", "pin-sha256=abc; max-age=600"),
            ("expect-ct", "max-age=86400, enforce"),
        ]));
        assert_eq!(r.findings.len(), 2);
        assert!(r.findings.iter().all(|f| f.severity == Severity::Low));
    }

    #[test]
    fn test_x_runtime() {
        let r = analyze_info_disclosure(&h(&[("x-runtime", "0.003821")]));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_clean_headers() {
        let r = analyze_info_disclosure(&h(&[("content-type", "text/html")]));
        assert!(r.findings.is_empty());
        assert_eq!(r.score_modifier, 0);
    }

    #[test]
    fn test_score_modifier() {
        let r = analyze_info_disclosure(&h(&[
            ("x-powered-by", "PHP/8.1"),
            ("x-backend-server", "internal-01"),
            ("x-debug-token", "tok"),
            ("x-debug-token-link", "http://x/_profiler/tok"),
            ("server", "Apache/2.4.41"),
        ]));
        assert!(r.score_modifier < 0);
        // -5 + -10 + -10 + -10 + -5 = -40, capped at -30
        assert_eq!(r.score_modifier, -30);
    }
}
