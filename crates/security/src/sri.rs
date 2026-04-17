//! Subresource Integrity (SRI) analyzer.

use std::collections::HashMap;

use psl;
use regex::Regex;
use serde::Serialize;
use url::Url;

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

/// Get the registrable domain for a host string via PSL.
fn registrable_domain(host: &str) -> Option<String> {
    let domain = psl::domain(host.as_bytes())?;
    Some(std::str::from_utf8(domain.as_bytes()).ok()?.to_lowercase())
}

/// Check if a resource URL is cross-origin relative to the page URL
/// using PSL-based registrable domain comparison.
fn is_cross_origin(resource_url: &str, page_url: &str) -> bool {
    // Protocol-relative URLs need a scheme for parsing.
    let resource = if resource_url.starts_with("//") {
        format!("https:{resource_url}")
    } else {
        resource_url.to_string()
    };

    let res_parsed = match Url::parse(&resource) {
        Ok(u) => u,
        Err(_) => return false, // relative URL, not external
    };

    let page_parsed = match Url::parse(page_url) {
        Ok(u) => u,
        Err(_) => return true, // cannot determine, treat as external
    };

    let res_host = match res_parsed.host_str() {
        Some(h) => h.to_lowercase(),
        None => return false,
    };
    let page_host = match page_parsed.host_str() {
        Some(h) => h.to_lowercase(),
        None => return true,
    };

    if res_host == page_host {
        return false;
    }

    match (
        registrable_domain(&res_host),
        registrable_domain(&page_host),
    ) {
        (Some(r), Some(p)) => r != p,
        _ => true,
    }
}

/// Analyze SRI from HTML body.
pub fn analyze_sri(html: &str, page_url: &str) -> SriReport {
    let script_re = Regex::new(r#"<script\b([^>]*)>"#).unwrap();
    let style_re = Regex::new(r#"<link\b([^>]*)>"#).unwrap();
    let src_re = Regex::new(r#"src=["']([^"']+)["']"#).unwrap();
    let href_re = Regex::new(r#"href=["']([^"']+)["']"#).unwrap();
    let integrity_re = Regex::new(r#"integrity=["']"#).unwrap();
    let rel_ss_re = Regex::new(r#"rel=["']stylesheet["']"#).unwrap();

    let mut findings = Vec::new();
    let mut missing_by_domain: HashMap<String, usize> = HashMap::new();
    let (mut ext_scripts, mut sri_scripts) = (0usize, 0usize);
    let (mut ext_styles, mut sri_styles) = (0usize, 0usize);

    for cap in script_re.captures_iter(html) {
        let attrs = &cap[1];
        if let Some(src_cap) = src_re.captures(attrs) {
            let url = &src_cap[1];
            if is_cross_origin(url, page_url) {
                ext_scripts += 1;
                if integrity_re.is_match(attrs) {
                    sri_scripts += 1;
                } else {
                    let domain = Url::parse(url)
                        .or_else(|_| Url::parse(&format!("https:{url}")))
                        .ok()
                        .and_then(|u| {
                            u.host_str()
                                .map(|h| registrable_domain(h).unwrap_or_else(|| h.to_string()))
                        })
                        .unwrap_or_else(|| "unknown".into());
                    *missing_by_domain.entry(domain).or_insert(0) += 1;
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
            if is_cross_origin(url, page_url) {
                ext_styles += 1;
                if integrity_re.is_match(attrs) {
                    sri_styles += 1;
                } else {
                    let domain = Url::parse(url)
                        .or_else(|_| Url::parse(&format!("https:{url}")))
                        .ok()
                        .and_then(|u| {
                            u.host_str()
                                .map(|h| registrable_domain(h).unwrap_or_else(|| h.to_string()))
                        })
                        .unwrap_or_else(|| "unknown".into());
                    *missing_by_domain.entry(domain).or_insert(0) += 1;
                }
            }
        }
    }

    for (domain, count) in &missing_by_domain {
        let desc = if *count == 1 {
            format!("External resource from {domain} missing integrity attribute")
        } else {
            format!("{count} external resources from {domain} missing integrity attribute")
        };
        findings.push(SriFinding {
            resource: domain.clone(),
            description: desc,
            severity: Severity::Medium,
        });
    }

    let total_ext = ext_scripts + ext_styles;
    let total_sri = sri_scripts + sri_styles;
    let coverage_percent = if total_ext == 0 {
        0.0
    } else {
        (total_sri as f32 / total_ext as f32) * 100.0
    };

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

    const PAGE: &str = "https://www.example.com/page";

    #[test]
    fn test_all_scripts_have_sri() {
        let html =
            r#"<script src="https://cdn.otherdomain.com/app.js" integrity="sha256-abc"></script>"#;
        let r = analyze_sri(html, PAGE);
        assert_eq!(r.total_external_scripts, 1);
        assert_eq!(r.scripts_with_integrity, 1);
        assert!((r.coverage_percent - 100.0).abs() < f32::EPSILON);
        assert_eq!(r.score_modifier, 5);
    }

    #[test]
    fn test_no_external_scripts() {
        let html = r#"<script>console.log("inline")</script>"#;
        let r = analyze_sri(html, PAGE);
        assert_eq!(r.total_external_scripts, 0);
        assert_eq!(r.score_modifier, 0);
    }

    #[test]
    fn test_missing_sri_on_cdn() {
        let html = r#"<script src="https://cdn.otherdomain.com/app.js"></script>"#;
        let r = analyze_sri(html, PAGE);
        assert_eq!(r.coverage_percent, 0.0);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_mixed_sri_coverage() {
        let html = concat!(
            r#"<script src="https://cdn.otherdomain.com/a.js" integrity="sha256-abc"></script>"#,
            r#"<script src="https://cdn.otherdomain.com/b.js"></script>"#,
        );
        let r = analyze_sri(html, PAGE);
        assert_eq!(r.total_external_scripts, 2);
        assert!((r.coverage_percent - 50.0).abs() < f32::EPSILON);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn test_styles_sri() {
        let html = r#"<link rel="stylesheet" href="https://cdn.otherdomain.com/style.css" integrity="sha256-xyz">"#;
        let r = analyze_sri(html, PAGE);
        assert_eq!(r.total_external_styles, 1);
        assert_eq!(r.styles_with_integrity, 1);
    }

    #[test]
    fn test_same_registrable_domain_not_external() {
        let html = r#"<script src="https://cdn.example.com/app.js"></script>"#;
        let r = analyze_sri(html, PAGE);
        assert_eq!(
            r.total_external_scripts, 0,
            "same registrable domain should not count as external"
        );
    }

    #[test]
    fn test_different_registrable_domain_is_external() {
        let html = r#"<script src="https://cdn.otherdomain.com/app.js"></script>"#;
        let r = analyze_sri(html, PAGE);
        assert_eq!(
            r.total_external_scripts, 1,
            "different registrable domain should count as external"
        );
    }

    #[test]
    fn test_findings_grouped_by_domain() {
        let html = concat!(
            r#"<script src="https://cdn.other.com/a.js"></script>"#,
            r#"<script src="https://cdn.other.com/b.js"></script>"#,
            r#"<script src="https://cdn.other.com/c.js"></script>"#,
            r#"<script src="https://cdn.third.com/x.js"></script>"#,
        );
        let r = analyze_sri(html, "https://www.example.com/page");
        assert_eq!(r.total_external_scripts, 4);
        // Should be 2 findings (one per domain), not 4
        assert_eq!(r.findings.len(), 2);
        assert!(
            r.findings
                .iter()
                .any(|f| f.description.contains("other.com") && f.description.contains("3"))
        );
        assert!(
            r.findings
                .iter()
                .any(|f| f.description.contains("third.com"))
        );
    }
}
