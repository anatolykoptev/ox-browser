//! Finding generators for each audit category.

use super::AuditFinding;
use crate::{
    accessibility::AccessibilityReport, performance::PerformanceReport, seo::SeoReport,
};

/// Generate audit findings from an SEO report.
pub fn seo_findings(report: &SeoReport) -> Vec<AuditFinding> {
    let mut out = Vec::new();
    if report.description.is_empty() {
        out.push(AuditFinding {
            severity: "high", category: "seo",
            message: "Missing meta description".into(),
            fix: "Add <meta name=\"description\" content=\"...\"> to <head>".into(),
        });
    }
    if report.og.title.is_empty() {
        out.push(AuditFinding {
            severity: "medium", category: "seo",
            message: "Missing Open Graph title".into(),
            fix: "Add <meta property=\"og:title\" content=\"...\">".into(),
        });
    }
    if report.og.image.is_empty() {
        out.push(AuditFinding {
            severity: "medium", category: "seo",
            message: "Missing OG image".into(),
            fix: "Add <meta property=\"og:image\" content=\"...\">".into(),
        });
    }
    if report.canonical.is_none() {
        out.push(AuditFinding {
            severity: "medium", category: "seo",
            message: "No canonical URL".into(),
            fix: "Add <link rel=\"canonical\" href=\"...\">".into(),
        });
    }
    if report.json_ld.is_empty() {
        out.push(AuditFinding {
            severity: "low", category: "seo",
            message: "No structured data (JSON-LD)".into(),
            fix: "Add a <script type=\"application/ld+json\"> block".into(),
        });
    }
    if report.favicon.is_none() {
        out.push(AuditFinding {
            severity: "low", category: "seo",
            message: "No favicon".into(),
            fix: "Add <link rel=\"icon\" href=\"/favicon.ico\">".into(),
        });
    }
    if report.twitter.card.is_empty() {
        out.push(AuditFinding {
            severity: "low", category: "seo",
            message: "Missing Twitter Card".into(),
            fix: "Add <meta name=\"twitter:card\" content=\"summary\">".into(),
        });
    }
    if report.robots.contains("noindex") {
        out.push(AuditFinding {
            severity: "info", category: "seo",
            message: "Page set to noindex".into(),
            fix: "Remove noindex from robots meta if indexing is desired".into(),
        });
    }
    out
}

/// Generate audit findings from a performance report.
pub fn performance_findings(report: &PerformanceReport) -> Vec<AuditFinding> {
    let mut out = Vec::new();
    if report.compression.is_empty() {
        out.push(AuditFinding {
            severity: "high", category: "performance",
            message: "No compression enabled".into(),
            fix: "Enable gzip or Brotli compression on the server".into(),
        });
    }
    if report.cache_control.is_empty() {
        out.push(AuditFinding {
            severity: "high", category: "performance",
            message: "No Cache-Control header".into(),
            fix: "Set Cache-Control header with appropriate max-age".into(),
        });
    }
    if report.images_total > 0 && report.images_lazy == 0 {
        out.push(AuditFinding {
            severity: "medium", category: "performance",
            message: format!("{} images without lazy loading", report.images_total),
            fix: "Add loading=\"lazy\" to below-the-fold images".into(),
        });
    }
    if report.preconnect.is_empty() && report.preload.is_empty() && report.prefetch.is_empty() {
        out.push(AuditFinding {
            severity: "medium", category: "performance",
            message: "No resource hints".into(),
            fix: "Add preconnect/preload/prefetch for critical resources".into(),
        });
    }
    if report.inline_styles_bytes > 10_000 {
        out.push(AuditFinding {
            severity: "medium", category: "performance",
            message: format!("Large inline CSS ({} bytes)", report.inline_styles_bytes),
            fix: "Move large CSS to external stylesheets".into(),
        });
    }
    if !report.http3_supported {
        out.push(AuditFinding {
            severity: "low", category: "performance",
            message: "HTTP/3 not available".into(),
            fix: "Enable HTTP/3 (QUIC) support on the server".into(),
        });
    }
    if report.images_total > 0 && report.images_lazy > 0 {
        let lazy_pct = report.images_lazy * 100 / report.images_total;
        if lazy_pct > 0 && lazy_pct < 50 {
            out.push(AuditFinding {
                severity: "low", category: "performance",
                message: format!("Only {}% images lazy-loaded", lazy_pct),
                fix: "Add loading=\"lazy\" to more below-the-fold images".into(),
            });
        }
    }
    out
}

/// Generate audit findings from an accessibility report.
pub fn accessibility_findings(report: &AccessibilityReport) -> Vec<AuditFinding> {
    let mut out = Vec::new();
    if report.lang.is_empty() {
        out.push(AuditFinding {
            severity: "high", category: "accessibility",
            message: "Missing html lang attribute".into(),
            fix: "Add lang=\"en\" (or appropriate language) to <html>".into(),
        });
    }
    if report.images_no_alt > 0 {
        out.push(AuditFinding {
            severity: "high", category: "accessibility",
            message: format!("{} images missing alt text", report.images_no_alt),
            fix: "Add descriptive alt attributes to all images".into(),
        });
    }
    if report.h1_count == 0 {
        out.push(AuditFinding {
            severity: "high", category: "accessibility",
            message: "No H1 heading on page".into(),
            fix: "Add exactly one <h1> element to the page".into(),
        });
    }
    if report.h1_count > 1 {
        out.push(AuditFinding {
            severity: "medium", category: "accessibility",
            message: format!("Multiple H1 headings ({})", report.h1_count),
            fix: "Use only one <h1> per page".into(),
        });
    }
    if report.heading_skip {
        out.push(AuditFinding {
            severity: "medium", category: "accessibility",
            message: "Heading levels are skipped".into(),
            fix: "Use sequential heading levels (h1 → h2 → h3)".into(),
        });
    }
    if report.landmarks == 0 {
        out.push(AuditFinding {
            severity: "medium", category: "accessibility",
            message: "No landmark elements found".into(),
            fix: "Add semantic elements: <main>, <nav>, <header>, <footer>".into(),
        });
    }
    if report.inputs_total > 0 && report.inputs_with_label < report.inputs_total {
        let unlabeled = report.inputs_total - report.inputs_with_label;
        out.push(AuditFinding {
            severity: "medium", category: "accessibility",
            message: format!("{} form inputs without labels", unlabeled),
            fix: "Associate <label> elements with all form inputs".into(),
        });
    }
    out
}

/// Convert ox_security findings into audit findings.
pub fn security_findings(report: &ox_security::SecurityReport) -> Vec<AuditFinding> {
    let mut f = Vec::new();
    for hf in &report.headers.findings {
        f.push(AuditFinding {
            severity: severity_str(&hf.severity),
            category: "security",
            message: hf.description.clone(),
            fix: hf.recommendation.clone().unwrap_or_default(),
        });
    }
    for cf in &report.cors.findings {
        f.push(AuditFinding {
            severity: severity_str(&cf.severity),
            category: "security",
            message: cf.description.clone(),
            fix: "Review CORS configuration".into(),
        });
    }
    for cf in &report.cookies.findings {
        f.push(AuditFinding {
            severity: severity_str(&cf.severity),
            category: "security",
            message: format!("{}: {}", cf.cookie, cf.description),
            fix: "Set Secure, HttpOnly, SameSite flags on cookies".into(),
        });
    }
    for rf in &report.redirect.findings {
        f.push(AuditFinding {
            severity: severity_str(&rf.severity),
            category: "security",
            message: rf.description.clone(),
            fix: "Enforce HTTPS redirects".into(),
        });
    }
    f
}

fn severity_str(s: &ox_security::types::Severity) -> &'static str {
    match s {
        ox_security::types::Severity::Critical => "critical",
        ox_security::types::Severity::High => "high",
        ox_security::types::Severity::Medium => "medium",
        ox_security::types::Severity::Low => "low",
        ox_security::types::Severity::Info => "info",
    }
}
