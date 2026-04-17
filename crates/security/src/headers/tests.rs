use std::collections::HashMap;

use super::*;
use crate::types::Severity;

fn h(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn test_hsts_good() {
    let headers = h(&[(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains; preload",
    )]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "strict-transport-security")
        .unwrap();
    assert_eq!(f.status, HeaderStatus::Present);
    assert_eq!(f.severity, Severity::Info);
    assert!(
        f.description.contains("preload-ready"),
        "desc={}",
        f.description
    );
}

#[test]
fn test_hsts_short() {
    let headers = h(&[("strict-transport-security", "max-age=3600")]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "strict-transport-security")
        .unwrap();
    assert_eq!(f.status, HeaderStatus::Present);
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_hsts_missing() {
    let report = analyze_headers(&HashMap::new(), "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "strict-transport-security")
        .unwrap();
    assert_eq!(f.status, HeaderStatus::Missing);
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_xcto_nosniff() {
    let headers = h(&[("x-content-type-options", "nosniff")]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "x-content-type-options")
        .unwrap();
    assert_eq!(f.status, HeaderStatus::Present);
    assert_eq!(f.severity, Severity::Info);
}

#[test]
fn test_xcto_missing() {
    let report = analyze_headers(&HashMap::new(), "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "x-content-type-options")
        .unwrap();
    assert_eq!(f.status, HeaderStatus::Missing);
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_coop_same_origin() {
    let headers = h(&[("cross-origin-opener-policy", "same-origin")]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "cross-origin-opener-policy")
        .unwrap();
    assert_eq!(f.status, HeaderStatus::Present);
    assert_eq!(f.severity, Severity::Info);
}

#[test]
fn test_permissions_policy_good() {
    let headers = h(&[(
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    )]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "permissions-policy")
        .unwrap();
    assert_eq!(f.status, HeaderStatus::Present);
}

#[test]
fn test_xss_protection_deprecated() {
    let headers = h(&[("x-xss-protection", "1; mode=block")]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "x-xss-protection")
        .unwrap();
    assert_eq!(f.status, HeaderStatus::Deprecated);
    assert_eq!(f.severity, Severity::Low);
}

#[test]
fn test_referrer_policy_good() {
    let headers = h(&[("referrer-policy", "strict-origin-when-cross-origin")]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "referrer-policy")
        .unwrap();
    assert_eq!(f.status, HeaderStatus::Present);
    assert_eq!(f.severity, Severity::Info);
}

#[test]
fn test_all_missing() {
    let report = analyze_headers(&HashMap::new(), "https://example.com");
    assert_eq!(report.total_checked, 16);
    assert!(
        report.missing_count >= 10,
        "missing_count={}",
        report.missing_count
    );
}

#[test]
fn test_full_secure_headers() {
    let headers = h(&[
        (
            "strict-transport-security",
            "max-age=31536000; includeSubDomains; preload",
        ),
        ("content-security-policy", "default-src 'none'"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("permissions-policy", "camera=(), microphone=()"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-resource-policy", "same-origin"),
        ("x-xss-protection", "0"),
        (
            "reporting-endpoints",
            "default=\"https://example.com/report\"",
        ),
        ("nel", "{\"report_to\":\"default\",\"max_age\":86400}"),
        ("x-permitted-cross-domain-policies", "none"),
        ("x-dns-prefetch-control", "off"),
        ("cache-control", "no-store"),
        ("clear-site-data", "\"cache\", \"cookies\""),
    ]);
    let report = analyze_headers(&headers, "https://example.com");
    assert_eq!(
        report.present_count + report.missing_count,
        report.total_checked
    );
    for f in &report.findings {
        assert_eq!(
            f.severity,
            Severity::Info,
            "unexpected severity for {}: {:?}",
            f.header,
            f.severity
        );
    }
}

#[test]
fn test_clear_site_data_present() {
    let headers = h(&[("clear-site-data", "\"cache\"")]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "clear-site-data")
        .unwrap();
    assert_eq!(f.status, HeaderStatus::Present);
    assert_eq!(f.severity, Severity::Info);
}

#[test]
fn test_content_type_missing_charset() {
    let headers = h(&[("content-type", "text/html")]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "content-type")
        .unwrap();
    assert_eq!(f.severity, Severity::Low);
}

#[test]
fn test_content_type_with_charset() {
    let headers = h(&[("content-type", "text/html; charset=utf-8")]);
    let report = analyze_headers(&headers, "https://example.com");
    assert!(
        report
            .findings
            .iter()
            .find(|f| f.header == "content-type")
            .is_none()
    );
}

// --- New tests ---

#[test]
fn test_hsts_preload_ready() {
    let headers = h(&[(
        "strict-transport-security",
        "max-age=63072000; includeSubDomains; preload",
    )]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "strict-transport-security")
        .unwrap();
    assert_eq!(f.severity, Severity::Info);
    assert!(
        f.description.contains("preload-ready"),
        "desc={}",
        f.description
    );
}

#[test]
fn test_hsts_preload_incomplete() {
    // Has preload flag but missing includeSubDomains
    let headers = h(&[("strict-transport-security", "max-age=31536000; preload")]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "strict-transport-security")
        .unwrap();
    assert_eq!(f.severity, Severity::Low);
    assert!(
        f.description.contains("preload flag but doesn't meet"),
        "desc={}",
        f.description
    );
}

#[test]
fn test_cache_control_missing_with_cookies() {
    let headers = h(&[("set-cookie", "session=abc; HttpOnly")]);
    let report = analyze_headers(&headers, "https://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "cache-control")
        .unwrap();
    assert_eq!(f.severity, Severity::Medium);
    assert!(
        f.description.contains("Sensitive page"),
        "desc={}",
        f.description
    );
}

#[test]
fn test_basic_auth_over_http() {
    let headers = h(&[("www-authenticate", "Basic realm=\"test\"")]);
    let report = analyze_headers(&headers, "http://example.com");
    let f = report
        .findings
        .iter()
        .find(|f| f.header == "www-authenticate")
        .unwrap();
    assert_eq!(f.severity, Severity::High);
    assert!(
        f.description.contains("cleartext"),
        "desc={}",
        f.description
    );

    // Over HTTPS — severity Medium
    let report2 = analyze_headers(&headers, "https://example.com");
    let f2 = report2
        .findings
        .iter()
        .find(|f| f.header == "www-authenticate")
        .unwrap();
    assert_eq!(f2.severity, Severity::Medium);
}
