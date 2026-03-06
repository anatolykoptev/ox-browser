//! Security scoring and aggregate report (Observatory-compatible).

mod aggregate;

use serde::Serialize;

use super::body_scan::BodyScanReport;
use super::cookies::CookieReport;
use super::cors::CorsReport;
use super::csp::CspReport;
use super::headers::HeadersReport;
use super::info_disclosure::InfoDisclosureReport;
use super::mixed_content::MixedContentReport;
use super::sri::SriReport;
use super::supply_chain::SupplyChainReport;
use super::vuln_js::VulnJsReport;

pub use aggregate::analyze_security;

#[derive(Debug, Clone, Serialize)]
pub struct SecurityReport {
    pub url: String,
    pub score: i32,
    pub grade: String,
    pub headers: HeadersReport,
    pub csp: Option<CspReport>,
    pub cookies: CookieReport,
    pub cors: CorsReport,
    pub sri: SriReport,
    pub supply_chain: SupplyChainReport,
    pub mixed_content: MixedContentReport,
    pub info_disclosure: InfoDisclosureReport,
    pub body_scan: BodyScanReport,
    pub vuln_js: VulnJsReport,
    pub findings_summary: FindingsSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingsSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

/// Mozilla Observatory grade chart.
pub fn score_to_grade(score: i32) -> String {
    match score {
        s if s >= 100 => "A+".into(),
        90..=99 => "A".into(),
        85..=89 => "A-".into(),
        80..=84 => "B+".into(),
        70..=79 => "B".into(),
        65..=69 => "B-".into(),
        60..=64 => "C+".into(),
        50..=59 => "C".into(),
        45..=49 => "C-".into(),
        40..=44 => "D+".into(),
        30..=39 => "D".into(),
        25..=29 => "D-".into(),
        _ => "F".into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn test_grade_chart() {
        assert_eq!(score_to_grade(100), "A+");
        assert_eq!(score_to_grade(115), "A+");
        assert_eq!(score_to_grade(95), "A");
        assert_eq!(score_to_grade(87), "A-");
        assert_eq!(score_to_grade(82), "B+");
        assert_eq!(score_to_grade(75), "B");
        assert_eq!(score_to_grade(67), "B-");
        assert_eq!(score_to_grade(62), "C+");
        assert_eq!(score_to_grade(55), "C");
        assert_eq!(score_to_grade(47), "C-");
        assert_eq!(score_to_grade(42), "D+");
        assert_eq!(score_to_grade(35), "D");
        assert_eq!(score_to_grade(27), "D-");
        assert_eq!(score_to_grade(10), "F");
    }

    #[test]
    fn test_perfect_score() {
        let hdrs = h(&[
            ("strict-transport-security", "max-age=63072000; includeSubDomains; preload"),
            ("content-security-policy", "default-src 'none'; script-src 'self'"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
        ]);
        let cookies = vec!["session=abc; Secure; HttpOnly; SameSite=Strict".to_string()];
        let r = analyze_security("https://example.com", &hdrs, &cookies, "");
        assert!(r.grade.starts_with('A'), "grade={} score={}", r.grade, r.score);
    }

    #[test]
    fn test_no_security() {
        // 100 - 25(CSP) - 20(HSTS) - 5(XCTO) - 20(XFO) - 5(referrer) = 25 → D-
        let r = analyze_security("https://example.com", &HashMap::new(), &[], "");
        assert_eq!(r.grade, "D-", "score={}", r.score);
        assert_eq!(r.score, 25);
    }

    #[test]
    fn test_findings_summary_counts() {
        let html = r#"<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>"#;
        let r = analyze_security("https://example.com", &HashMap::new(), &[], html);
        assert!(r.findings_summary.critical > 0);
        assert!(r.findings_summary.total > 0);
    }

    #[test]
    fn test_full_scan_with_all_modules() {
        let hdrs = h(&[
            ("server", "Apache/2.4.41"),
            ("x-powered-by", "PHP/7.4"),
            ("access-control-allow-origin", "https://evil.com"),
            ("access-control-allow-credentials", "true"),
            ("content-type", "text/html"),
        ]);
        let html = r#"
            <script src="https://cdn.example.com/jquery-1.12.4.min.js"></script>
            <form action="http://insecure.example.com/login"></form>
            <!-- TODO: remove debug endpoint -->
        "#;
        let cookies = vec!["session=abc".to_string()];
        let r = analyze_security("https://example.com", &hdrs, &cookies, html);

        // Info disclosure: server version + x-powered-by
        assert!(!r.info_disclosure.findings.is_empty(), "info_disclosure should have findings");
        // Vuln JS: jQuery 1.12.4
        assert!(!r.vuln_js.findings.is_empty(), "vuln_js should have findings");
        assert_eq!(r.vuln_js.libraries[0].name, "jQuery");
        // Body scan: insecure form + suspicious comment
        assert!(!r.body_scan.findings.is_empty(), "body_scan should have findings");
        // CORS: reflected origin with credentials
        assert!(!r.cors.findings.is_empty(), "cors should have findings");
        // All modules populated
        assert!(r.findings_summary.total > 5);
        assert!(r.score < 50, "score={} should be low with many issues", r.score);
    }

    #[test]
    fn test_moderate_security() {
        let hdrs = h(&[
            ("strict-transport-security", "max-age=63072000"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "SAMEORIGIN"),
        ]);
        let r = analyze_security("https://example.com", &hdrs, &[], "");
        assert!(r.score >= 30 && r.score <= 85, "score={}", r.score);
        assert!(r.grade != "F" && r.grade != "A+", "grade={}", r.grade);
    }
}
