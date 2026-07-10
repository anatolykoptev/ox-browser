//! CSP bypass detection and scoring checks.

use crate::types::Severity;

use super::parser::{get_directive_values, get_script_src_values, has_nonce_or_hash, has_value};
use super::{CspDirective, CspFinding};

/// Check all CSP bypass patterns and return findings + missing directives.
pub fn run_checks(directives: &[CspDirective]) -> (Vec<CspFinding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut missing = Vec::new();

    check_unsafe_inline(directives, &mut findings);
    check_unsafe_eval_directive(directives, &mut findings);
    check_broad_sources(directives, &mut findings);
    check_strict_dynamic(directives, &mut findings);
    check_insecure_scheme(directives, &mut findings);
    check_missing_directives(directives, &mut findings, &mut missing);
    check_wildcard_domains(directives, &mut findings);
    check_jsonp_bypass(directives, &mut findings);
    check_deprecated_reporting(directives, &mut findings);

    (findings, missing)
}

/// Detect `http:` scheme in any directive (not just script-src).
pub fn check_insecure_scheme(directives: &[CspDirective], findings: &mut Vec<CspFinding>) {
    for d in directives {
        if d.values.iter().any(|v| v == "http:") {
            findings.push(CspFinding {
                directive: d.name.clone(),
                description: format!(
                    "Insecure http: scheme in {} allows downgrade attacks",
                    d.name
                ),
                severity: Severity::Medium,
            });
        }
    }
}

/// Check if `report-uri` or `report-to` is configured (informational).
pub fn has_reporting(directives: &[CspDirective]) -> bool {
    directives
        .iter()
        .any(|d| d.name == "report-uri" || d.name == "report-to")
}

fn check_unsafe_inline(directives: &[CspDirective], findings: &mut Vec<CspFinding>) {
    let script_vals = get_script_src_values(directives);
    if let Some(vals) = script_vals
        && has_value(vals, "'unsafe-inline'")
        && !has_nonce_or_hash(vals)
    {
        findings.push(CspFinding {
            directive: "script-src".into(),
            description: "XSS bypass possible: unsafe-inline without nonce/hash".into(),
            severity: Severity::High,
        });
    }
}

fn check_unsafe_eval_directive(directives: &[CspDirective], findings: &mut Vec<CspFinding>) {
    let script_vals = get_script_src_values(directives);
    if let Some(vals) = script_vals {
        // Detect 'unsafe-eval' which allows dynamic code execution
        if has_value(vals, "'unsafe-eval'") {
            findings.push(CspFinding {
                directive: "script-src".into(),
                description: "Allows dynamic code execution, injection risk".into(),
                severity: Severity::Medium,
            });
        }
    }
}

fn check_broad_sources(directives: &[CspDirective], findings: &mut Vec<CspFinding>) {
    let script_vals = get_script_src_values(directives);
    if let Some(vals) = script_vals {
        let broad = ["https:", "data:", "http:", "*"];
        if vals.iter().any(|v| broad.contains(&v.as_str())) {
            findings.push(CspFinding {
                directive: "script-src".into(),
                description: "Overly broad source allows script injection".into(),
                severity: Severity::High,
            });
        }
    }
}

fn check_strict_dynamic(directives: &[CspDirective], findings: &mut Vec<CspFinding>) {
    let script_vals = get_script_src_values(directives);
    if let Some(vals) = script_vals
        && has_value(vals, "'strict-dynamic'")
        && !has_nonce_or_hash(vals)
    {
        findings.push(CspFinding {
            directive: "script-src".into(),
            description: "strict-dynamic without nonce/hash is misconfigured".into(),
            severity: Severity::High,
        });
    }
}

fn check_missing_directives(
    directives: &[CspDirective],
    findings: &mut Vec<CspFinding>,
    missing: &mut Vec<String>,
) {
    // object-src should be 'none'
    match get_directive_values(directives, "object-src") {
        Some(vals) if has_value(vals, "'none'") => {}
        _ => {
            missing.push("object-src".into());
            findings.push(CspFinding {
                directive: "object-src".into(),
                description: "Missing or permissive object-src allows plugin-based bypasses".into(),
                severity: Severity::Medium,
            });
        }
    }

    if get_directive_values(directives, "base-uri").is_none() {
        missing.push("base-uri".into());
        findings.push(CspFinding {
            directive: "base-uri".into(),
            description: "Missing base-uri allows base tag injection".into(),
            severity: Severity::Medium,
        });
    }

    if get_directive_values(directives, "form-action").is_none() {
        missing.push("form-action".into());
        findings.push(CspFinding {
            directive: "form-action".into(),
            description: "Missing form-action allows form hijacking".into(),
            severity: Severity::Medium,
        });
    }

    if get_directive_values(directives, "frame-ancestors").is_none() {
        missing.push("frame-ancestors".into());
        findings.push(CspFinding {
            directive: "frame-ancestors".into(),
            description: "Missing frame-ancestors, relies on X-Frame-Options".into(),
            severity: Severity::Low,
        });
    }
}

/// Detect wildcard subdomain sources (*.example.com) in script-src or default-src.
fn check_wildcard_domains(directives: &[CspDirective], findings: &mut Vec<CspFinding>) {
    for d in directives {
        if d.name != "script-src" && d.name != "default-src" {
            continue;
        }
        for v in &d.values {
            if v.starts_with("*.") {
                findings.push(CspFinding {
                    directive: d.name.clone(),
                    description: format!(
                        "Wildcard subdomain {} allows any subdomain to inject scripts",
                        v
                    ),
                    severity: Severity::Medium,
                });
                break;
            }
        }
    }
}

/// Detect known JSONP-capable endpoints in script-src allowlist.
fn check_jsonp_bypass(directives: &[CspDirective], findings: &mut Vec<CspFinding>) {
    const JSONP_DOMAINS: &[&str] = &[
        "ajax.googleapis.com",
        "cdn.google.com",
        "apis.google.com",
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "rawgit.com",
        "raw.githubusercontent.com",
        "accounts.google.com",
        "docs.google.com",
        "translate.googleapis.com",
        "maps.googleapis.com",
        "www.googleadservices.com",
    ];

    let script_vals = get_script_src_values(directives);
    let vals = match script_vals {
        Some(v) => v,
        None => return,
    };

    for val in vals {
        let lower = val.to_ascii_lowercase();
        for &domain in JSONP_DOMAINS {
            if lower.contains(domain) {
                findings.push(CspFinding {
                    directive: "script-src".into(),
                    description: format!(
                        "JSONP bypass: {} serves JSONP callbacks that bypass CSP",
                        val
                    ),
                    severity: Severity::High,
                });
                break;
            }
        }
    }
}

/// Detect deprecated report-uri without report-to.
fn check_deprecated_reporting(directives: &[CspDirective], findings: &mut Vec<CspFinding>) {
    let has_report_uri = directives.iter().any(|d| d.name == "report-uri");
    let has_report_to = directives.iter().any(|d| d.name == "report-to");

    if has_report_uri && !has_report_to {
        findings.push(CspFinding {
            directive: "report-uri".into(),
            description: "Deprecated report-uri without report-to — browsers dropping support"
                .into(),
            severity: Severity::Low,
        });
    }
}
