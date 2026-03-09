//! Third-party script supply chain risk analyzer.

use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde::Serialize;

use super::types::Severity;

/// Known risky/compromised CDN domains.
const RISKY_DOMAINS: &[&str] = &[
    "polyfill.io",
    "cdn.polyfill.io",
    "cdn.bootcss.com",
    "cdn.bootcdn.net",
];

#[derive(Debug, Clone, Serialize)]
pub struct SupplyChainReport {
    pub third_party_scripts: Vec<ThirdPartyScript>,
    pub total_third_party: usize,
    pub risky_domains: Vec<String>,
    pub sri_coverage_third_party: f32,
    pub findings: Vec<SupplyChainFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThirdPartyScript {
    pub url: String,
    pub domain: String,
    pub has_integrity: bool,
    pub is_known_risky: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplyChainFinding {
    pub description: String,
    pub severity: Severity,
}

/// Extract domain from a URL (strips protocol, takes host before `/` or `:`).
fn extract_domain(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("//"))?;
    let host = rest.split('/').next().unwrap_or("");
    let domain = host.split(':').next().unwrap_or("");
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_lowercase())
    }
}

/// Analyze third-party script supply chain risk from HTML.
/// `page_domain` is the domain of the page being analyzed.
pub fn analyze_supply_chain(html: &str, page_domain: &str) -> SupplyChainReport {
    let script_re = Regex::new(r#"<script\b([^>]*)>"#).unwrap();
    let src_re = Regex::new(r#"src=["']([^"']+)["']"#).unwrap();
    let integrity_re = Regex::new(r#"integrity=["']"#).unwrap();

    let page_domain_lower = page_domain.to_lowercase();
    let mut scripts = Vec::new();
    let mut risky = Vec::new();
    let mut findings = Vec::new();
    let mut with_integrity = 0usize;
    let mut seen_urls = HashSet::new();
    let mut missing_sri_by_domain: HashMap<String, usize> = HashMap::new();

    for cap in script_re.captures_iter(html) {
        let attrs = &cap[1];
        let Some(src_cap) = src_re.captures(attrs) else { continue };
        let url = &src_cap[1];
        let Some(domain) = extract_domain(url) else { continue };

        if !seen_urls.insert(url.to_string()) {
            continue; // skip duplicate script URL
        }

        if domain == page_domain_lower || domain.ends_with(&format!(".{page_domain_lower}")) {
            continue; // same origin
        }

        let has_integrity = integrity_re.is_match(attrs);
        let is_known_risky = RISKY_DOMAINS.iter().any(|&r| r == domain);

        if has_integrity {
            with_integrity += 1;
        }

        if is_known_risky {
            risky.push(domain.clone());
            findings.push(SupplyChainFinding {
                description: format!("Script loaded from known compromised domain: {domain}"),
                severity: Severity::Critical,
            });
        }

        if !has_integrity {
            *missing_sri_by_domain.entry(domain.clone()).or_insert(0) += 1;
        }

        scripts.push(ThirdPartyScript {
            url: url.to_string(),
            domain,
            has_integrity,
            is_known_risky,
        });
    }

    for (domain, count) in &missing_sri_by_domain {
        let desc = if *count == 1 {
            format!("Third-party script from {domain} missing SRI integrity attribute")
        } else {
            format!("{count} third-party scripts from {domain} missing SRI integrity attribute")
        };
        findings.push(SupplyChainFinding {
            description: desc,
            severity: Severity::Medium,
        });
    }

    let total = scripts.len();
    let coverage = if total == 0 {
        0.0
    } else {
        (with_integrity as f32 / total as f32) * 100.0
    };

    SupplyChainReport {
        third_party_scripts: scripts,
        total_third_party: total,
        risky_domains: risky,
        sri_coverage_third_party: coverage,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_third_party() {
        let html = r#"<script src="/app.js"></script>"#;
        let r = analyze_supply_chain(html, "example.com");
        assert_eq!(r.total_third_party, 0);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn test_third_party_with_sri() {
        let html = r#"<script src="https://cdn.jsdelivr.net/app.js" integrity="sha256-abc"></script>"#;
        let r = analyze_supply_chain(html, "example.com");
        assert_eq!(r.total_third_party, 1);
        assert!(r.third_party_scripts[0].has_integrity);
        assert!((r.sri_coverage_third_party - 100.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_risky_domain_polyfill() {
        let html =
            r#"<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>"#;
        let r = analyze_supply_chain(html, "example.com");
        assert!(r.third_party_scripts[0].is_known_risky);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_third_party_without_sri() {
        let html = r#"<script src="https://cdn.example.com/lib.js"></script>"#;
        let r = analyze_supply_chain(html, "other.com");
        assert_eq!(r.total_third_party, 1);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn test_findings_grouped_by_domain() {
        let html = concat!(
            r#"<script src="https://cdn.other.com/a.js"></script>"#,
            r#"<script src="https://cdn.other.com/b.js"></script>"#,
            r#"<script src="https://cdn.other.com/c.js"></script>"#,
            r#"<script src="https://cdn.third.com/x.js"></script>"#,
        );
        let r = analyze_supply_chain(html, "example.com");
        assert_eq!(r.total_third_party, 4);
        // Findings grouped by domain, not per-script
        assert_eq!(r.findings.len(), 2);
        assert!(r.findings.iter().any(|f| f.description.contains("cdn.other.com") && f.description.contains("3")));
    }

    #[test]
    fn test_duplicate_script_url_deduped() {
        let html = concat!(
            r#"<script src="https://cdn.other.com/app.js"></script>"#,
            r#"<script src="https://cdn.other.com/app.js"></script>"#,
        );
        let r = analyze_supply_chain(html, "example.com");
        assert_eq!(r.total_third_party, 1, "duplicate URL should be counted once");
        assert_eq!(r.third_party_scripts.len(), 1);
    }
}
