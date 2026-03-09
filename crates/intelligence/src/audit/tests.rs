use super::*;
use crate::{accessibility, performance, seo};
use std::collections::HashMap;

#[test]
fn seo_findings_missing_all() {
    let report = seo::analyze("");
    let findings = seo_findings(&report);
    assert!(findings.iter().any(|f| f.message.contains("meta description")));
    assert!(findings.iter().any(|f| f.message.contains("canonical")));
    assert!(findings.iter().any(|f| f.severity == "high"));
}

#[test]
fn seo_findings_perfect() {
    let html = r#"<html><head>
        <meta name="description" content="Desc">
        <meta property="og:title" content="T">
        <meta property="og:image" content="I">
        <meta name="twitter:card" content="summary">
        <link rel="canonical" href="https://example.com/">
        <script type="application/ld+json">{"@type":"WebPage"}</script>
        <link rel="icon" href="/favicon.ico">
    </head></html>"#;
    let report = seo::analyze(html);
    let findings = seo_findings(&report);
    assert!(findings.is_empty(), "expected no findings, got {:?}", findings);
}

#[test]
fn performance_findings_no_compression() {
    let report = performance::analyze(&HashMap::new(), "");
    let findings = performance_findings(&report);
    assert!(findings.iter().any(|f| f.message.contains("compression")));
}

#[test]
fn accessibility_findings_no_lang() {
    let report = accessibility::analyze("<html><body></body></html>");
    let findings = accessibility_findings(&report);
    assert!(findings.iter().any(|f| f.message.contains("lang")));
}

#[test]
fn grade_boundaries() {
    assert_eq!(audit_grade(100), "A+");
    assert_eq!(audit_grade(93), "A");
    assert_eq!(audit_grade(73), "C");
    assert_eq!(audit_grade(50), "F");
}

#[test]
fn overall_score_average() {
    assert_eq!(overall_score(80, 60, 100, 40), 70);
}

#[test]
fn security_findings_from_report() {
    let report = ox_security::analyze_security(
        "http://example.com",
        &HashMap::new(),
        &[],
        "",
    );
    let findings = security_findings(&report);
    assert!(findings.iter().any(|f| f.category == "security"));
}
