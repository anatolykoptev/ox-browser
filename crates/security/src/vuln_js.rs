//! Detect known-vulnerable JavaScript libraries from `<script src>` URLs.

use std::sync::LazyLock;

use regex::Regex;
use semver::Version;
use serde::Serialize;

use crate::types::Severity;

#[derive(Debug, Clone, Serialize)]
pub struct VulnJsReport {
    pub libraries: Vec<DetectedLibrary>,
    pub findings: Vec<VulnJsFinding>,
    pub score_modifier: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectedLibrary {
    pub name: String,
    pub version: String,
    pub source_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnJsFinding {
    pub library: String,
    pub version: String,
    pub severity: Severity,
    pub description: String,
}

struct LibraryDef {
    name: &'static str,
    pattern: &'static str,
    vuln_below: &'static str,
    severity: Severity,
    description: &'static str,
}

static SCRIPT_SRC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<script[^>]+src=["']([^"']+)["']"#).unwrap());

const LIBRARY_DEFS: &[LibraryDef] = &[
    LibraryDef {
        name: "jQuery",
        pattern: r"jquery[.-](\d+\.\d+\.\d+)",
        vuln_below: "3.5.0",
        severity: Severity::Medium,
        description: "CVE-2020-11022, CVE-2020-11023 XSS",
    },
    LibraryDef {
        name: "AngularJS",
        pattern: r"angular(?:js)?[/.-](\d+\.\d+\.\d+)",
        vuln_below: "1.8.0",
        severity: Severity::High,
        description: "multiple XSS and sandbox escapes",
    },
    LibraryDef {
        name: "Bootstrap",
        pattern: r"bootstrap(?:\.min)?\.js\??(?:v=)?(\d+\.\d+\.\d+)",
        vuln_below: "3.4.0",
        severity: Severity::Medium,
        description: "CVE-2018-14041, CVE-2019-8331 XSS",
    },
    LibraryDef {
        name: "Lodash",
        pattern: r"lodash[@/.-](\d+\.\d+\.\d+)",
        vuln_below: "4.17.21",
        severity: Severity::Medium,
        description: "CVE-2021-23337 prototype pollution",
    },
    LibraryDef {
        name: "React",
        pattern: r"react[@/.-](\d+\.\d+\.\d+)",
        vuln_below: "16.4.2",
        severity: Severity::Medium,
        description: "CVE-2018-6341 XSS in SSR",
    },
    LibraryDef {
        name: "Vue.js",
        pattern: r"vue[@/.-](\d+\.\d+\.\d+)",
        vuln_below: "2.5.17",
        severity: Severity::Medium,
        description: "prototype pollution",
    },
    LibraryDef {
        name: "Moment.js",
        pattern: r"moment(?:\.min)?\.js\??(?:v=)?(\d+\.\d+\.\d+)",
        vuln_below: "2.29.4",
        severity: Severity::Low,
        description: "CVE-2022-24785 path traversal",
    },
    LibraryDef {
        name: "Handlebars",
        pattern: r"handlebars(?:\.min)?\.js\??(?:v=)?(\d+\.\d+\.\d+)",
        vuln_below: "4.7.7",
        severity: Severity::High,
        description: "CVE-2021-23369 prototype pollution",
    },
    LibraryDef {
        name: "DOMPurify",
        pattern: r"(?:dompurify|purify)[@/.-](\d+\.\d+\.\d+)",
        vuln_below: "2.4.0",
        severity: Severity::High,
        description: "mXSS bypass",
    },
];

fn version_below(version: &str, threshold: &str) -> bool {
    match (Version::parse(version), Version::parse(threshold)) {
        (Ok(v), Ok(t)) => v < t,
        _ => false, // if parsing fails, don't flag as vulnerable
    }
}

pub fn detect_vulnerable_js(html: &str) -> VulnJsReport {
    let mut libraries = Vec::new();
    let mut findings = Vec::new();

    for cap in SCRIPT_SRC_RE.captures_iter(html) {
        let src = &cap[1];
        for def in LIBRARY_DEFS {
            let re = Regex::new(def.pattern).unwrap();
            if let Some(m) = re.captures(src) {
                let version = m[1].to_string();
                libraries.push(DetectedLibrary {
                    name: def.name.to_string(),
                    version: version.clone(),
                    source_url: src.to_string(),
                });
                if version_below(&version, def.vuln_below) {
                    findings.push(VulnJsFinding {
                        library: def.name.to_string(),
                        version: version.clone(),
                        severity: def.severity,
                        description: def.description.to_string(),
                    });
                }
            }
        }
    }

    let score_modifier = findings
        .iter()
        .map(|f| match f.severity {
            Severity::Critical => -15,
            Severity::High => -10,
            Severity::Medium => -5,
            Severity::Low => -2,
            Severity::Info => 0,
        })
        .sum::<i32>()
        .max(-25);

    VulnJsReport { libraries, findings, score_modifier }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html_with_scripts(srcs: &[&str]) -> String {
        srcs.iter()
            .map(|s| format!(r#"<script src="{s}"></script>"#))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn test_jquery_old_version() {
        let html = html_with_scripts(&["https://cdn.example.com/jquery-1.12.4.min.js"]);
        let r = detect_vulnerable_js(&html);
        assert_eq!(r.libraries.len(), 1);
        assert_eq!(r.libraries[0].version, "1.12.4");
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn test_jquery_safe_version() {
        let html = html_with_scripts(&["https://cdn.example.com/jquery-3.7.1.min.js"]);
        let r = detect_vulnerable_js(&html);
        assert_eq!(r.libraries.len(), 1);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn test_angularjs_vulnerable() {
        let html = html_with_scripts(&["https://cdn.example.com/angularjs/1.6.0/angular.min.js"]);
        let r = detect_vulnerable_js(&html);
        assert_eq!(r.libraries.len(), 1);
        assert_eq!(r.libraries[0].name, "AngularJS");
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn test_bootstrap_3() {
        let html = html_with_scripts(&["https://cdn.example.com/bootstrap.min.js?v=3.3.7"]);
        let r = detect_vulnerable_js(&html);
        assert_eq!(r.libraries.len(), 1);
        assert_eq!(r.libraries[0].name, "Bootstrap");
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn test_multiple_libraries() {
        let html = html_with_scripts(&[
            "https://cdn.example.com/jquery-2.1.4.min.js",
            "https://cdn.example.com/lodash@4.17.10/lodash.min.js",
        ]);
        let r = detect_vulnerable_js(&html);
        assert!(r.libraries.len() >= 2);
    }

    #[test]
    fn test_no_scripts() {
        let r = detect_vulnerable_js("<html><body>Hello</body></html>");
        assert!(r.libraries.is_empty());
        assert!(r.findings.is_empty());
        assert_eq!(r.score_modifier, 0);
    }

    #[test]
    fn test_react_safe() {
        let html = html_with_scripts(&["https://cdn.example.com/react@18.2.0/react.min.js"]);
        let r = detect_vulnerable_js(&html);
        assert_eq!(r.libraries.len(), 1);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn test_score_modifier_for_vulnerable() {
        let html = html_with_scripts(&["https://cdn.example.com/jquery-1.6.0.min.js"]);
        let r = detect_vulnerable_js(&html);
        assert!(r.score_modifier < 0);
    }
}
