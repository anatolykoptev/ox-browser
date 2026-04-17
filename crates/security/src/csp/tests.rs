//! CSP evaluator tests.

use super::*;
use crate::types::Severity;

#[test]
fn test_parse_simple_csp() {
    let report = evaluate_csp("default-src 'self'");
    assert_eq!(report.directives.len(), 1);
    assert_eq!(report.directives[0].name, "default-src");
    assert_eq!(report.directives[0].values, vec!["'self'"]);
}

#[test]
fn test_parse_complex_csp() {
    let csp = "default-src 'none'; script-src 'self' https://cdn.example.com; \
               style-src 'self' 'unsafe-inline'; img-src *";
    let report = evaluate_csp(csp);
    assert_eq!(report.directives.len(), 4);
}

#[test]
fn test_no_csp() {
    let report = evaluate_csp("");
    assert_eq!(report.grade, 'F');
    assert_eq!(report.score, -25);
}

#[test]
fn test_strict_csp_nonce() {
    let csp = "script-src 'nonce-abc123' 'strict-dynamic'; \
               object-src 'none'; base-uri 'none'";
    let report = evaluate_csp(csp);
    assert!(report.has_nonce);
    assert!(report.has_strict_dynamic);
    assert!(report.grade <= 'B');
}

#[test]
fn test_unsafe_inline() {
    let report = evaluate_csp("script-src 'unsafe-inline' 'self'");
    assert!(report.has_unsafe_inline);
    assert_eq!(report.score, -20);
    assert_eq!(report.grade, 'D');
}

#[test]
fn test_unsafe_eval_detection() {
    // 'unsafe-eval' allows dynamic code execution
    let report = evaluate_csp("script-src 'self' 'unsafe-eval'");
    assert!(report.has_unsafe_eval);
    assert_eq!(report.score, -10);
    assert_eq!(report.grade, 'C');
}

#[test]
fn test_default_src_none_no_unsafe() {
    let csp = "default-src 'none'; script-src 'self'; style-src 'self'; \
               img-src 'self'; object-src 'none'; base-uri 'none'; \
               form-action 'self'; frame-ancestors 'none'";
    let report = evaluate_csp(csp);
    assert_eq!(report.score, 10);
    assert_eq!(report.grade, 'A');
}

#[test]
fn test_missing_object_src() {
    let report = evaluate_csp("default-src 'self'");
    assert!(report.findings.iter().any(|f| f.directive == "object-src"));
}

#[test]
fn test_missing_form_action() {
    let report = evaluate_csp("default-src 'self'");
    assert!(report.findings.iter().any(|f| f.directive == "form-action"));
    assert!(
        report
            .missing_directives
            .contains(&"form-action".to_string())
    );
}

#[test]
fn test_overly_broad_source() {
    let report = evaluate_csp("script-src https:");
    let finding = report
        .findings
        .iter()
        .find(|f| f.directive == "script-src" && f.severity == Severity::High);
    assert!(
        finding.is_some(),
        "expected High severity finding for overly broad source"
    );
}

#[test]
fn test_style_src_unsafe_inline_only() {
    let csp = "default-src 'none'; script-src 'self'; \
               style-src 'self' 'unsafe-inline'; object-src 'none'; \
               base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
    let report = evaluate_csp(csp);
    assert_eq!(report.score, 0);
    assert_eq!(report.grade, 'B');
    // has_unsafe_inline should only be true for script-src
    assert!(!report.has_unsafe_inline);
}

// --- New tests leveraging the content-security-policy crate ---

#[test]
fn test_upgrade_insecure_requests() {
    let csp = "default-src 'self'; upgrade-insecure-requests";
    let report = evaluate_csp(csp);
    assert!(
        report.has_upgrade_insecure_requests,
        "should detect upgrade-insecure-requests directive"
    );

    let report_without = evaluate_csp("default-src 'self'");
    assert!(
        !report_without.has_upgrade_insecure_requests,
        "should not report upgrade-insecure-requests when absent"
    );
}

#[test]
fn test_multiple_policies() {
    // Comma-separated policies — the crate parses these as separate policies
    let csp = "script-src 'self', style-src 'self'";
    let report = evaluate_csp(csp);
    assert_eq!(
        report.policy_count, 2,
        "comma-separated header should yield 2 policies"
    );
    // Our directives extract from the first policy only
    assert_eq!(report.directives.len(), 1);
    assert_eq!(report.directives[0].name, "script-src");
}

#[test]
fn test_report_to_detection() {
    let csp = "default-src 'self'; report-to csp-endpoint";
    let report = evaluate_csp(csp);
    assert!(report.has_reporting, "should detect report-to directive");

    let csp_uri = "default-src 'self'; report-uri /csp-violations";
    let report_uri = evaluate_csp(csp_uri);
    assert!(
        report_uri.has_reporting,
        "should detect report-uri directive"
    );

    let csp_none = "default-src 'self'";
    let report_none = evaluate_csp(csp_none);
    assert!(
        !report_none.has_reporting,
        "should not report reporting when absent"
    );
}

#[test]
fn wildcard_subdomain_detected() {
    let report = evaluate_csp("script-src 'self' *.example.com");
    let has_wildcard = report
        .findings
        .iter()
        .any(|f| f.description.contains("Wildcard subdomain"));
    assert!(has_wildcard, "should detect wildcard subdomain");
}

#[test]
fn no_wildcard_for_exact_domain() {
    let report = evaluate_csp("script-src 'self' cdn.example.com");
    let has_wildcard = report
        .findings
        .iter()
        .any(|f| f.description.contains("Wildcard subdomain"));
    assert!(
        !has_wildcard,
        "exact domain should not trigger wildcard check"
    );
}

#[test]
fn jsonp_bypass_googleapis_detected() {
    let report = evaluate_csp("script-src 'self' ajax.googleapis.com");
    let has_jsonp = report
        .findings
        .iter()
        .any(|f| f.description.contains("JSONP bypass"));
    assert!(has_jsonp, "should detect JSONP bypass via googleapis");
}

#[test]
fn jsonp_bypass_cdnjs_detected() {
    let report = evaluate_csp("script-src 'self' cdnjs.cloudflare.com");
    let has_jsonp = report
        .findings
        .iter()
        .any(|f| f.description.contains("JSONP bypass"));
    assert!(has_jsonp, "should detect JSONP bypass via cdnjs");
}

#[test]
fn no_jsonp_for_safe_domain() {
    let report = evaluate_csp("script-src 'self' cdn.myapp.com");
    let has_jsonp = report
        .findings
        .iter()
        .any(|f| f.description.contains("JSONP bypass"));
    assert!(!has_jsonp, "safe domain should not trigger JSONP check");
}

#[test]
fn deprecated_report_uri_detected() {
    let report = evaluate_csp("default-src 'self'; report-uri /csp-report");
    let has_deprecated = report
        .findings
        .iter()
        .any(|f| f.description.contains("Deprecated report-uri"));
    assert!(has_deprecated, "should detect deprecated report-uri");
}

#[test]
fn no_warning_when_report_to_present() {
    let report = evaluate_csp("default-src 'self'; report-uri /csp-report; report-to csp-endpoint");
    let has_deprecated = report
        .findings
        .iter()
        .any(|f| f.description.contains("Deprecated report-uri"));
    assert!(!has_deprecated, "should not warn when report-to is present");
}
