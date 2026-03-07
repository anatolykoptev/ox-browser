//! Aggregate security analysis — runs all checks and computes score.

use std::collections::HashMap;

use super::super::body_scan;
use super::super::cookies::{self, CookieReport};
use super::super::cors::{self, CorsReport};
use super::super::csp::{self, CspReport};
use super::super::headers::{self, HeaderStatus, HeadersReport};
use super::super::info_disclosure;
use super::super::mixed_content;
use super::super::redirect;
use super::super::dangerous_js;
use super::super::vuln_js;
use super::super::sri::{self, SriReport};
use super::super::supply_chain;
use super::super::types::Severity;
use super::{score_to_grade, FindingsSummary, SecurityReport};

/// Run all security checks and produce aggregate report.
pub fn analyze_security(
    url: &str,
    resp_headers: &HashMap<String, String>,
    set_cookie_headers: &[String],
    html: &str,
) -> SecurityReport {
    let headers_report = headers::analyze_headers(resp_headers, url);
    let csp_header = resp_headers
        .get("content-security-policy")
        .cloned()
        .unwrap_or_default();
    let csp_report = if csp_header.is_empty() {
        None
    } else {
        Some(csp::evaluate_csp(&csp_header))
    };
    let cookies_report = cookies::analyze_cookies(set_cookie_headers, url);
    let cors_report = cors::analyze_cors(resp_headers);
    let sri_report = sri::analyze_sri(html, url);

    let page_domain = extract_domain(url);
    let supply_chain_report = supply_chain::analyze_supply_chain(html, &page_domain);
    let mixed_content_report = mixed_content::analyze_mixed_content(html, url);
    let info_disc = info_disclosure::analyze_info_disclosure(resp_headers);
    let body = body_scan::scan_body(html, url);
    let vuln = vuln_js::detect_vulnerable_js(html);
    let dangerous = dangerous_js::analyze_dangerous_js(html);
    let redirect_report = redirect::analyze_redirect(url, resp_headers);

    let score = compute_score(
        resp_headers,
        &headers_report,
        &csp_report,
        &cookies_report,
        &cors_report,
        &sri_report,
        &info_disc,
        &body,
        &vuln,
        &dangerous,
        &redirect_report,
    );
    let grade = score_to_grade(score);
    let findings_summary = count_findings(
        &headers_report,
        &csp_report,
        &cookies_report,
        &cors_report,
        &sri_report,
        &supply_chain_report,
        &mixed_content_report,
        &info_disc,
        &body,
        &vuln,
        &dangerous,
        &redirect_report,
    );

    SecurityReport {
        url: url.to_string(),
        score,
        grade,
        headers: headers_report,
        csp: csp_report,
        cookies: cookies_report,
        cors: cors_report,
        sri: sri_report,
        supply_chain: supply_chain_report,
        mixed_content: mixed_content_report,
        info_disclosure: info_disc,
        body_scan: body,
        vuln_js: vuln,
        dangerous_js: dangerous,
        redirect: redirect_report,
        findings_summary,
    }
}

fn extract_domain(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

fn compute_score(
    resp_headers: &HashMap<String, String>,
    headers_report: &HeadersReport,
    csp_report: &Option<CspReport>,
    cookies_report: &CookieReport,
    cors_report: &CorsReport,
    sri_report: &SriReport,
    info_disc: &info_disclosure::InfoDisclosureReport,
    body: &body_scan::BodyScanReport,
    vuln: &vuln_js::VulnJsReport,
    dangerous: &dangerous_js::DangerousJsReport,
    redirect: &redirect::RedirectReport,
) -> i32 {
    let mut score: i32 = 100;

    match csp_report {
        Some(csp) => score += csp.score,
        None => score -= 25,
    }

    score += cookies_report.score_modifier;
    score += cors_report.score_modifier;
    score += sri_report.score_modifier;
    score += info_disc.score_modifier;
    score += body.score_modifier;
    score += vuln.score_modifier;
    score += dangerous.score_modifier;
    score += redirect.score_modifier;

    for f in &headers_report.findings {
        match f.header.as_str() {
            "strict-transport-security" if f.status == HeaderStatus::Missing => score -= 20,
            "strict-transport-security"
                if f.status == HeaderStatus::Present && f.severity == Severity::Medium =>
            {
                score -= 10;
            }
            "x-content-type-options" if f.status == HeaderStatus::Missing => score -= 5,
            "x-frame-options" if f.status == HeaderStatus::Missing => score -= 20,
            "referrer-policy" if f.status == HeaderStatus::Missing => score -= 5,
            _ => {}
        }
    }

    let score = super::bonuses::apply_bonuses(score, resp_headers);

    score.max(0)
}

fn count_findings(
    headers_report: &HeadersReport,
    csp_report: &Option<CspReport>,
    cookies_report: &CookieReport,
    cors_report: &CorsReport,
    sri_report: &SriReport,
    supply_chain_report: &supply_chain::SupplyChainReport,
    mixed_content_report: &mixed_content::MixedContentReport,
    info_disc: &info_disclosure::InfoDisclosureReport,
    body: &body_scan::BodyScanReport,
    vuln: &vuln_js::VulnJsReport,
    dangerous: &dangerous_js::DangerousJsReport,
    redirect: &redirect::RedirectReport,
) -> FindingsSummary {
    let mut sevs: Vec<Severity> = Vec::new();

    sevs.extend(headers_report.findings.iter().map(|f| f.severity));
    if let Some(csp) = csp_report {
        sevs.extend(csp.findings.iter().map(|f| f.severity));
    }
    sevs.extend(cookies_report.findings.iter().map(|f| f.severity));
    sevs.extend(cors_report.findings.iter().map(|f| f.severity));
    sevs.extend(sri_report.findings.iter().map(|f| f.severity));
    sevs.extend(supply_chain_report.findings.iter().map(|f| f.severity));
    sevs.extend(mixed_content_report.findings.iter().map(|f| f.severity));
    sevs.extend(info_disc.findings.iter().map(|f| f.severity));
    sevs.extend(body.findings.iter().map(|f| f.severity));
    sevs.extend(vuln.findings.iter().map(|f| f.severity));
    sevs.extend(dangerous.findings.iter().map(|f| f.severity));
    sevs.extend(redirect.findings.iter().map(|f| f.severity));

    let total = sevs.len();
    FindingsSummary {
        critical: sevs.iter().filter(|&&s| s == Severity::Critical).count(),
        high: sevs.iter().filter(|&&s| s == Severity::High).count(),
        medium: sevs.iter().filter(|&&s| s == Severity::Medium).count(),
        low: sevs.iter().filter(|&&s| s == Severity::Low).count(),
        info: sevs.iter().filter(|&&s| s == Severity::Info).count(),
        total,
    }
}
