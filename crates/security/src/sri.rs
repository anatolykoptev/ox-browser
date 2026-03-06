//! Subresource Integrity (SRI) analyzer.

use regex::Regex;
use serde::Serialize;

use super::types::Severity;

#[derive(Debug, Clone, Serialize)]
pub struct SriReport {
    pub total_external_scripts: usize,
    pub scripts_with_integrity: usize,
    pub total_external_styles: usize,
    pub styles_with_integrity: usize,
    pub coverage_percent: f32,
    pub findings: Vec<SriFinding>,
    pub score_modifier: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SriFinding {
    pub resource: String,
    pub description: String,
    pub severity: Severity,
}

fn is_external(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://") || url.starts_with("//")
}

/// Analyze SRI from HTML body.
pub fn analyze_sri(html: &str) -> SriReport {
    let script_re = Regex::new(r#"<script\b([^>]*)>"#).unwrap();
    let style_re = Regex::new(r#"<link\b([^>]*)>"#).unwrap();
    let src_re = Regex::new(r#"src=["']([^"']+)["']"#).unwrap();
    let href_re = Regex::new(r#"href=["']([^"']+)["']"#).unwrap();
    let integrity_re = Regex::new(r#"integrity=["']"#).unwrap();
    let rel_ss_re = Regex::new(r#"rel=["']stylesheet["']"#).unwrap();

    let mut findings = Vec::new();
    let (mut ext_scripts, mut sri_scripts) = (0usize, 0usize);
    let (mut ext_styles, mut sri_styles) = (0usize, 0usize);

    for cap in script_re.captures_iter(html) {
        let attrs = &cap[1];
        if let Some(src_cap) = src_re.captures(attrs) {
            let url = &src_cap[1];
            if is_external(url) {
                ext_scripts += 1;
                if integrity_re.is_match(attrs) {
                    sri_scripts += 1;
                } else {
                    findings.push(SriFinding {
                        resource: url.to_string(),
                        description: "External script missing integrity attribute".into(),
                        severity: Severity::Medium,
                    });
                }
            }
        }
    }

    for cap in style_re.captures_iter(html) {
        let attrs = &cap[1];
        if !rel_ss_re.is_match(attrs) {
            continue;
        }
        if let Some(href_cap) = href_re.captures(attrs) {
            let url = &href_cap[1];
            if is_external(url) {
                ext_styles += 1;
                if integrity_re.is_match(attrs) {
                    sri_styles += 1;
                } else {
                    findings.push(SriFinding {
                        resource: url.to_string(),
                        description: "External stylesheet missing integrity attribute".into(),
                        severity: Severity::Medium,
                    });
                }
            }
        }
    }

    let total_ext = ext_scripts + ext_styles;
    let total_sri = sri_scripts + sri_styles;
    let coverage_percent = if total_ext == 0 { 0.0 } else { (total_sri as f32 / total_ext as f32) * 100.0 };

    let score_modifier = if total_ext == 0 {
        0
    } else if total_sri == total_ext {
        5
    } else if total_sri == 0 {
        -50
    } else {
        let missing = (total_ext - total_sri) as i32;
        (-5 * missing).max(-25)
    };

    // Upgrade severity to Critical when no SRI at all
    if total_ext > 0 && total_sri == 0 {
        for f in &mut findings {
            f.severity = Severity::Critical;
        }
    }

    SriReport {
        total_external_scripts: ext_scripts,
        scripts_with_integrity: sri_scripts,
        total_external_styles: ext_styles,
        styles_with_integrity: sri_styles,
        coverage_percent,
        findings,
        score_modifier,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_scripts_have_sri() {
        let html = r#"<script src="https://cdn.example.com/app.js" integrity="sha256-abc"></script>"#;
        let r = analyze_sri(html);
        assert_eq!(r.total_external_scripts, 1);
        assert_eq!(r.scripts_with_integrity, 1);
        assert!((r.coverage_percent - 100.0).abs() < f32::EPSILON);
        assert_eq!(r.score_modifier, 5);
    }

    #[test]
    fn test_no_external_scripts() {
        let html = r#"<script>console.log("inline")</script>"#;
        let r = analyze_sri(html);
        assert_eq!(r.total_external_scripts, 0);
        assert_eq!(r.score_modifier, 0);
    }

    #[test]
    fn test_missing_sri_on_cdn() {
        let html = r#"<script src="https://cdn.example.com/app.js"></script>"#;
        let r = analyze_sri(html);
        assert_eq!(r.coverage_percent, 0.0);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_mixed_sri_coverage() {
        let html = concat!(
            r#"<script src="https://cdn.example.com/a.js" integrity="sha256-abc"></script>"#,
            r#"<script src="https://cdn.example.com/b.js"></script>"#,
        );
        let r = analyze_sri(html);
        assert_eq!(r.total_external_scripts, 2);
        assert!((r.coverage_percent - 50.0).abs() < f32::EPSILON);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn test_styles_sri() {
        let html = r#"<link rel="stylesheet" href="https://cdn.example.com/style.css" integrity="sha256-xyz">"#;
        let r = analyze_sri(html);
        assert_eq!(r.total_external_styles, 1);
        assert_eq!(r.styles_with_integrity, 1);
    }
}
