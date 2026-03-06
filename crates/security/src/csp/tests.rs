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
    assert!(report.missing_directives.contains(&"form-action".to_string()));
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
