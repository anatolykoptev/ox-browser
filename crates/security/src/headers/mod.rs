//! Security headers analyzer — checks 16+ HTTP security headers.

mod checks;

use std::collections::HashMap;

use serde::Serialize;

use super::types::Severity;

/// Status of a security header check.
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HeaderStatus {
    Present,
    Missing,
    Invalid,
    Deprecated,
}

/// A single finding from checking one header.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderFinding {
    pub header: String,
    pub status: HeaderStatus,
    pub value: Option<String>,
    pub description: String,
    pub severity: Severity,
    pub recommendation: Option<String>,
}

/// Aggregated report from analyzing all security headers.
#[derive(Debug, Clone, Serialize)]
pub struct HeadersReport {
    pub findings: Vec<HeaderFinding>,
    pub present_count: usize,
    pub missing_count: usize,
    pub total_checked: usize,
}

/// Analyze HTTP response headers for security issues.
pub fn analyze_headers(headers: &HashMap<String, String>) -> HeadersReport {
    let mut findings = Vec::new();

    checks::check_hsts(headers, &mut findings);
    checks::check_csp(headers, &mut findings);
    checks::check_xcto(headers, &mut findings);
    checks::check_xfo(headers, &mut findings);
    checks::check_referrer_policy(headers, &mut findings);
    checks::check_permissions_policy(headers, &mut findings);
    checks::check_coop(headers, &mut findings);
    checks::check_coep(headers, &mut findings);
    checks::check_corp(headers, &mut findings);
    checks::check_xss_protection(headers, &mut findings);
    checks::check_reporting_endpoints(headers, &mut findings);
    checks::check_nel(headers, &mut findings);
    checks::check_cross_domain_policies(headers, &mut findings);
    checks::check_dns_prefetch(headers, &mut findings);
    checks::check_cache_control(headers, &mut findings);
    checks::check_clear_site_data(headers, &mut findings);
    if let Some(f) = checks::check_content_type_charset(headers) {
        findings.push(f);
    }

    let present_count = findings
        .iter()
        .filter(|f| f.status == HeaderStatus::Present || f.status == HeaderStatus::Deprecated)
        .count();
    let missing_count = findings
        .iter()
        .filter(|f| f.status == HeaderStatus::Missing)
        .count();

    HeadersReport {
        total_checked: findings.len(),
        present_count,
        missing_count,
        findings,
    }
}

fn get(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    headers.get(name).cloned()
}

fn missing(name: &str, severity: Severity, desc: &str, rec: &str) -> HeaderFinding {
    HeaderFinding {
        header: name.to_string(),
        status: HeaderStatus::Missing,
        value: None,
        description: desc.to_string(),
        severity,
        recommendation: Some(rec.to_string()),
    }
}

fn present(name: &str, value: &str, severity: Severity, desc: &str) -> HeaderFinding {
    HeaderFinding {
        header: name.to_string(),
        status: HeaderStatus::Present,
        value: Some(value.to_string()),
        description: desc.to_string(),
        severity,
        recommendation: None,
    }
}

#[cfg(test)]
mod tests;
