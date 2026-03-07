//! Extended header checks (CORP, XSS, reporting, cache, basic auth).

use std::collections::HashMap;

use crate::types::Severity;

use super::{get, missing, present, HeaderFinding, HeaderStatus};

pub(super) fn check_corp(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "cross-origin-resource-policy";
    match get(h, name) {
        None => out.push(missing(name, Severity::Low, "CORP header missing", "Add Cross-Origin-Resource-Policy: same-origin")),
        Some(v) => out.push(present(name, &v, Severity::Info, "CORP header present")),
    }
}

pub(super) fn check_xss_protection(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "x-xss-protection";
    match get(h, name) {
        None => out.push(present(name, "", Severity::Info, "X-XSS-Protection absent (correct, header is deprecated)")),
        Some(v) if v.trim() == "0" => out.push(present(name, &v, Severity::Info, "X-XSS-Protection disabled (correct)")),
        Some(v) => out.push(HeaderFinding {
            header: name.into(), status: HeaderStatus::Deprecated, value: Some(v),
            description: "X-XSS-Protection is deprecated and can introduce vulnerabilities".into(),
            severity: Severity::Low, recommendation: Some("Remove header or set to 0".into()),
        }),
    }
}

pub(super) fn check_reporting_endpoints(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "reporting-endpoints";
    match get(h, name) {
        None => out.push(present(name, "", Severity::Info, "Reporting-Endpoints absent (optional)")),
        Some(v) => out.push(present(name, &v, Severity::Info, "Reporting-Endpoints configured")),
    }
}

pub(super) fn check_nel(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "nel";
    match get(h, name) {
        None => out.push(present(name, "", Severity::Info, "NEL absent (optional)")),
        Some(v) => out.push(present(name, &v, Severity::Info, "Network Error Logging configured")),
    }
}

pub(super) fn check_cross_domain_policies(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "x-permitted-cross-domain-policies";
    match get(h, name) {
        None => out.push(missing(name, Severity::Low, "X-Permitted-Cross-Domain-Policies missing", "Add X-Permitted-Cross-Domain-Policies: none")),
        Some(v) => {
            let lower = v.to_lowercase();
            if lower == "none" || lower == "master-only" {
                out.push(present(name, &v, Severity::Info, "Cross-domain policies restricted"));
            } else {
                out.push(present(name, &v, Severity::Low, "Cross-domain policies may be too permissive"));
            }
        }
    }
}

pub(super) fn check_dns_prefetch(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "x-dns-prefetch-control";
    match get(h, name) {
        None => out.push(present(name, "", Severity::Info, "X-DNS-Prefetch-Control absent (acceptable)")),
        Some(v) if v.eq_ignore_ascii_case("off") => {
            out.push(present(name, &v, Severity::Info, "DNS prefetch disabled"));
        }
        Some(v) => out.push(present(name, &v, Severity::Low, "DNS prefetch enabled — minor privacy concern")),
    }
}

pub(super) fn check_cache_control(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "cache-control";
    let has_cookies = get(h, "set-cookie").is_some();
    match get(h, name) {
        None => {
            if has_cookies {
                out.push(HeaderFinding {
                    header: name.into(),
                    status: HeaderStatus::Missing,
                    value: None,
                    description: "Sensitive page (sets cookies) without Cache-Control: no-store".into(),
                    severity: Severity::Medium,
                    recommendation: Some("Add Cache-Control: no-store for pages that set cookies".into()),
                });
            } else {
                out.push(present(name, "", Severity::Info, "Cache-Control absent (informational)"));
            }
        }
        Some(v) => {
            let lower = v.to_lowercase();
            if has_cookies && !lower.contains("no-store") && !lower.contains("private") {
                out.push(HeaderFinding {
                    header: name.into(),
                    status: HeaderStatus::Present,
                    value: Some(v),
                    description: "Sensitive page (sets cookies) without Cache-Control: no-store".into(),
                    severity: Severity::Medium,
                    recommendation: Some("Add no-store or private to Cache-Control".into()),
                });
            } else {
                out.push(present(name, &v, Severity::Info, &format!("Cache-Control: {v}")));
            }
        }
    }
}

pub(super) fn check_clear_site_data(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "clear-site-data";
    match get(h, name) {
        None => out.push(present(name, "", Severity::Info, "Clear-Site-Data absent (optional)")),
        Some(v) => out.push(present(name, &v, Severity::Info, "Clear-Site-Data header present")),
    }
}

pub(super) fn check_content_type_charset(
    h: &HashMap<String, String>,
) -> Option<HeaderFinding> {
    let ct = get(h, "content-type")?;
    let lower = ct.to_lowercase();
    if lower.contains("text/html") && !lower.contains("charset") {
        Some(HeaderFinding {
            header: "content-type".to_string(),
            status: HeaderStatus::Present,
            value: Some(ct),
            description: "Content-Type text/html without charset declaration".into(),
            severity: Severity::Low,
            recommendation: Some("Add charset=utf-8 to Content-Type".into()),
        })
    } else {
        None
    }
}

pub(super) fn check_basic_auth(
    h: &HashMap<String, String>,
    page_url: &str,
    out: &mut Vec<HeaderFinding>,
) {
    let name = "www-authenticate";
    if let Some(v) = get(h, name) {
        if v.to_lowercase().contains("basic") {
            let is_https = page_url.starts_with("https://") || page_url.starts_with("https%");
            let severity = if is_https { Severity::Medium } else { Severity::High };
            let desc = if is_https {
                "Basic authentication detected (credentials sent as base64)"
            } else {
                "Basic authentication over HTTP (credentials sent in cleartext)"
            };
            out.push(HeaderFinding {
                header: name.to_string(),
                status: HeaderStatus::Present,
                value: Some(v),
                description: desc.into(),
                severity,
                recommendation: Some("Use token-based authentication instead of Basic auth".into()),
            });
        }
    }
}
