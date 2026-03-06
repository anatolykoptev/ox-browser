//! CSP bypass detection and scoring checks.

use crate::types::Severity;

use super::parser::{get_directive_values, get_script_src_values, has_nonce_or_hash, has_value};
use super::{CspDirective, CspFinding};

/// Check all CSP bypass patterns and return findings + missing directives.
pub fn run_checks(directives: &[CspDirective]) -> (Vec<CspFinding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut missing = Vec::new();

    check_unsafe_inline(directives, &mut findings);
    check_unsafe_eval(directives, &mut findings);
    check_broad_sources(directives, &mut findings);
    check_strict_dynamic(directives, &mut findings);
    check_missing_directives(directives, &mut findings, &mut missing);

    (findings, missing)
}

fn check_unsafe_inline(directives: &[CspDirective], findings: &mut Vec<CspFinding>) {
    let script_vals = get_script_src_values(directives);
    if let Some(vals) = script_vals {
        if has_value(vals, "'unsafe-inline'") && !has_nonce_or_hash(vals) {
            findings.push(CspFinding {
                directive: "script-src".into(),
                description: "XSS bypass possible: unsafe-inline without nonce/hash".into(),
                severity: Severity::High,
            });
        }
    }
}

fn check_unsafe_eval(directives: &[CspDirective], findings: &mut Vec<CspFinding>) {
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
    if let Some(vals) = script_vals {
        if has_value(vals, "'strict-dynamic'") && !has_nonce_or_hash(vals) {
            findings.push(CspFinding {
                directive: "script-src".into(),
                description: "strict-dynamic without nonce/hash is misconfigured".into(),
                severity: Severity::High,
            });
        }
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
