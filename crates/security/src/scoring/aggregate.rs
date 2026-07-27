//! Aggregate security analysis — runs all checks and computes score.

use std::collections::HashMap;

use super::super::cookies::CookieReport;
use super::super::cors::CorsReport;
use super::super::csp::CspReport;
use super::super::headers::{HeaderStatus, HeadersReport};
use super::super::sri::SriReport;
use super::super::types::ScanMode;
use super::super::types::Severity;
use super::super::{body_scan, cookies, cors, csp, dangerous_js, headers, info_disclosure};
use super::super::{mixed_content, protection, redirect, sri, supply_chain, vuln_js};
use super::{FindingsSummary, SecurityReport, score_to_grade};

/// Run all security checks and produce aggregate report.
pub fn analyze_security(
    url: &str,
    resp_headers: &HashMap<String, String>,
    set_cookie_headers: &[String],
    html: &str,
    mode: ScanMode,
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

    let cookie_names: Vec<String> = set_cookie_headers
        .iter()
        .filter_map(|h| h.split('=').next().map(|n| n.trim().to_string()))
        .collect();
    let protection_report =
        protection::detect_protection(resp_headers, &cookie_names, html, url, mode);

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
        &protection_report,
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
        protection: protection_report,
        findings_summary,
    }
}

fn extract_domain(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)] // aggregates every security signal report; struct-refactor tracked (PR notes)
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
    // Split: 50 points for headers presence, 50 for policy quality.
    // Ensures sites with all headers score >=50 even with weak policies.
    let mut headers_score: i32 = 50;
    let mut quality_score: i32 = 50;

    // === Headers presence (0-50) ===
    for f in &headers_report.findings {
        let missing = f.status == HeaderStatus::Missing;
        match f.header.as_str() {
            "strict-transport-security" if missing => headers_score -= 15,
            "strict-transport-security"
                if f.status == HeaderStatus::Present && f.severity == Severity::Medium =>
            {
                headers_score -= 5;
            }
            "x-content-type-options" if missing => headers_score -= 3,
            "x-frame-options" if missing => headers_score -= 10,
            "referrer-policy" if missing => headers_score -= 3,
            "content-security-policy" if missing => headers_score -= 15,
            _ => {}
        }
    }

    // === Policy quality (0-50) ===
    // CSP quality: raw score ranges from -25 (absent) to +10 (perfect).
    // Map to 0-30 contribution.
    match csp_report {
        Some(csp) => {
            let csp_contribution = ((csp.score + 25) * 30 / 35).clamp(0, 30);
            quality_score = quality_score - 30 + csp_contribution;
        }
        None => quality_score -= 30,
    }

    // Other quality modifiers (capped impact)
    quality_score += cookies_report.score_modifier.clamp(-10, 0);
    quality_score += cors_report.score_modifier.clamp(-10, 0);
    quality_score += sri_report.score_modifier.clamp(-5, 0);
    quality_score += info_disc.score_modifier.clamp(-5, 0);
    quality_score += body.score_modifier.clamp(-5, 0);
    quality_score += vuln.score_modifier.clamp(-10, 0);
    quality_score += dangerous.score_modifier.clamp(-10, 0);
    quality_score += redirect.score_modifier.clamp(-5, 0);

    let score = headers_score.max(0) + quality_score.max(0);
    let score = super::bonuses::apply_bonuses(score, resp_headers);
    score.max(0)
}

#[allow(clippy::too_many_arguments)] // tallies findings across every report kind; struct-refactor tracked (PR notes)
fn count_findings(
    headers: &HeadersReport,
    csp: &Option<CspReport>,
    cookies: &CookieReport,
    cors: &CorsReport,
    sri: &SriReport,
    supply: &supply_chain::SupplyChainReport,
    mixed: &mixed_content::MixedContentReport,
    info: &info_disclosure::InfoDisclosureReport,
    body: &body_scan::BodyScanReport,
    vuln: &vuln_js::VulnJsReport,
    dangerous: &dangerous_js::DangerousJsReport,
    redirect: &redirect::RedirectReport,
    protection: &protection::ProtectionReport,
) -> FindingsSummary {
    let mut sevs: Vec<Severity> = Vec::new();
    sevs.extend(headers.findings.iter().map(|f| f.severity));
    if let Some(c) = csp {
        sevs.extend(c.findings.iter().map(|f| f.severity));
    }
    sevs.extend(cookies.findings.iter().map(|f| f.severity));
    sevs.extend(cors.findings.iter().map(|f| f.severity));
    sevs.extend(sri.findings.iter().map(|f| f.severity));
    sevs.extend(supply.findings.iter().map(|f| f.severity));
    sevs.extend(mixed.findings.iter().map(|f| f.severity));
    sevs.extend(info.findings.iter().map(|f| f.severity));
    sevs.extend(body.findings.iter().map(|f| f.severity));
    sevs.extend(vuln.findings.iter().map(|f| f.severity));
    sevs.extend(dangerous.findings.iter().map(|f| f.severity));
    sevs.extend(redirect.findings.iter().map(|f| f.severity));
    sevs.extend(protection.findings.iter().map(|f| f.severity));
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
