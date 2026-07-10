//! Mixed content detector (HTTP resources on HTTPS pages).

use regex::Regex;
use serde::Serialize;

use super::types::Severity;

#[derive(Debug, Clone, Serialize)]
pub struct MixedContentReport {
    pub is_https: bool,
    pub mixed_scripts: Vec<String>,
    pub mixed_styles: Vec<String>,
    pub mixed_iframes: Vec<String>,
    pub mixed_forms: Vec<String>,
    pub mixed_media: Vec<String>,
    pub findings: Vec<MixedContentFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MixedContentFinding {
    pub resource: String,
    pub resource_type: String,
    pub description: String,
    pub severity: Severity,
}

impl MixedContentReport {
    fn empty(is_https: bool) -> Self {
        Self {
            is_https,
            mixed_scripts: vec![],
            mixed_styles: vec![],
            mixed_iframes: vec![],
            mixed_forms: vec![],
            mixed_media: vec![],
            findings: vec![],
        }
    }
}

/// Detect mixed content from HTML.
/// `page_url` determines if the page is HTTPS.
pub fn analyze_mixed_content(html: &str, page_url: &str) -> MixedContentReport {
    let is_https = page_url.starts_with("https://");
    if !is_https {
        return MixedContentReport::empty(false);
    }

    let mut report = MixedContentReport::empty(true);

    // Active mixed content (Critical)
    find_mixed(
        html,
        r#"<script[^>]+src=["'](http://[^"']+)["']"#,
        "script",
        Severity::Critical,
        &mut report.mixed_scripts,
        &mut report.findings,
    );

    // Stylesheets — only <link> with rel="stylesheet" (Critical)
    find_stylesheet_mixed(html, &mut report.mixed_styles, &mut report.findings);

    // Iframes (High)
    find_mixed(
        html,
        r#"<iframe[^>]+src=["'](http://[^"']+)["']"#,
        "iframe",
        Severity::High,
        &mut report.mixed_iframes,
        &mut report.findings,
    );

    // Forms (High)
    find_mixed(
        html,
        r#"<form[^>]+action=["'](http://[^"']+)["']"#,
        "form",
        Severity::High,
        &mut report.mixed_forms,
        &mut report.findings,
    );

    // Passive mixed content — images, video, audio (Low)
    let media_patterns = [
        r#"<img[^>]+src=["'](http://[^"']+)["']"#,
        r#"<video[^>]+src=["'](http://[^"']+)["']"#,
        r#"<audio[^>]+src=["'](http://[^"']+)["']"#,
    ];
    for pat in &media_patterns {
        find_mixed(
            html,
            pat,
            "media",
            Severity::Low,
            &mut report.mixed_media,
            &mut report.findings,
        );
    }

    report
}

#[allow(clippy::too_many_arguments)] // one resource-type scan; params are scan inputs, not shared state
fn find_mixed(
    html: &str,
    pattern: &str,
    resource_type: &str,
    severity: Severity,
    urls: &mut Vec<String>,
    findings: &mut Vec<MixedContentFinding>,
) {
    let re = Regex::new(pattern).unwrap();
    for cap in re.captures_iter(html) {
        let url = cap[1].to_string();
        findings.push(MixedContentFinding {
            resource: url.clone(),
            resource_type: resource_type.to_string(),
            description: format!("Mixed content: HTTP {resource_type} on HTTPS page"),
            severity,
        });
        urls.push(url);
    }
}

fn find_stylesheet_mixed(
    html: &str,
    urls: &mut Vec<String>,
    findings: &mut Vec<MixedContentFinding>,
) {
    let re = Regex::new(r#"<link\b([^>]*)>"#).unwrap();
    let href_re = Regex::new(r#"href=["'](http://[^"']+)["']"#).unwrap();
    let rel_re = Regex::new(r#"rel=["']stylesheet["']"#).unwrap();

    for cap in re.captures_iter(html) {
        let attrs = &cap[1];
        if !rel_re.is_match(attrs) {
            continue;
        }
        if let Some(href_cap) = href_re.captures(attrs) {
            let url = href_cap[1].to_string();
            findings.push(MixedContentFinding {
                resource: url.clone(),
                resource_type: "stylesheet".to_string(),
                description: "Mixed content: HTTP stylesheet on HTTPS page".into(),
                severity: Severity::Critical,
            });
            urls.push(url);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_page_clean() {
        let html = r#"<script src="https://cdn.example.com/app.js"></script>"#;
        let r = analyze_mixed_content(html, "https://example.com");
        assert!(r.is_https);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn test_http_script_on_https() {
        let html = r#"<script src="http://evil.com/malware.js"></script>"#;
        let r = analyze_mixed_content(html, "https://example.com");
        assert_eq!(r.mixed_scripts.len(), 1);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_http_image_on_https() {
        let html = r#"<img src="http://example.com/photo.jpg">"#;
        let r = analyze_mixed_content(html, "https://example.com");
        assert_eq!(r.mixed_media.len(), 1);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Low));
    }

    #[test]
    fn test_http_page_no_mixed() {
        let html = r#"<script src="http://cdn.example.com/app.js"></script>"#;
        let r = analyze_mixed_content(html, "http://example.com");
        assert!(!r.is_https);
        assert!(r.findings.is_empty());
    }
}
