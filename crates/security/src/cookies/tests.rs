use super::*;
use crate::types::Severity;

const PAGE: &str = "https://app.example.com/path";

#[test]
fn test_secure_httponly_samesite() {
    let r = analyze_cookies(
        &["session=abc; Secure; HttpOnly; SameSite=Strict".into()],
        PAGE,
    );
    assert_eq!(r.score_modifier, 5);
}

#[test]
fn test_session_without_httponly() {
    let r = analyze_cookies(&["PHPSESSID=abc; Secure".into()], PAGE);
    assert_eq!(r.score_modifier, -30);
    assert!(r.findings.iter().any(|f| f.severity == Severity::High));
}

#[test]
fn test_session_without_secure() {
    let r = analyze_cookies(&["JSESSIONID=abc; HttpOnly".into()], PAGE);
    assert_eq!(r.score_modifier, -40);
    assert!(r.findings.iter().any(|f| f.severity == Severity::Critical));
}

#[test]
fn test_tracker_cookies_detected() {
    let r = analyze_cookies(&["_ga=GA1.2.xxx; Path=/".into()], PAGE);
    assert!(r.cookies[0].is_tracker);
}

#[test]
fn test_host_prefix() {
    let r = analyze_cookies(&["__Host-session=abc; Secure; Path=/".into()], PAGE);
    assert!(r.cookies[0].host_prefix);
}

#[test]
fn test_no_cookies() {
    let r = analyze_cookies(&[], PAGE);
    assert_eq!(r.score_modifier, 0);
}

#[test]
fn test_public_suffix_domain_critical() {
    let r = analyze_cookies(&["track=1; Domain=.co.uk".into()], "https://example.co.uk/");
    let finding = r.findings.iter().find(|f| f.severity == Severity::Critical);
    assert!(
        finding.is_some(),
        "expected Critical for public suffix domain"
    );
    assert!(finding.unwrap().description.contains("public suffix"));
}

#[test]
fn test_loosely_scoped_domain_medium() {
    let r = analyze_cookies(
        &["id=abc; Domain=.example.com".into()],
        "https://app.example.com/page",
    );
    let finding = r.findings.iter().find(|f| f.severity == Severity::Medium);
    assert!(
        finding.is_some(),
        "expected Medium for loosely scoped cookie"
    );
    assert!(finding.unwrap().description.contains("Loosely scoped"));
}

#[test]
fn test_no_domain_attr_no_finding() {
    let r = analyze_cookies(
        &["id=abc; Secure; HttpOnly".into()],
        "https://app.example.com/",
    );
    let domain_findings: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.description.contains("public suffix") || f.description.contains("Loosely"))
        .collect();
    assert!(domain_findings.is_empty());
}

#[test]
fn test_csrf_cookie_without_samesite() {
    let r = analyze_cookies(&["csrf_token=abc; Secure; HttpOnly".into()], PAGE);
    assert!(
        r.findings
            .iter()
            .any(|f| f.description.contains("CSRF") && f.severity == Severity::Medium)
    );
}

#[test]
fn test_csrf_cookie_with_samesite_ok() {
    let r = analyze_cookies(
        &["csrf_token=abc; Secure; HttpOnly; SameSite=Strict".into()],
        PAGE,
    );
    assert!(r.findings.iter().all(|f| !f.description.contains("CSRF")));
}
