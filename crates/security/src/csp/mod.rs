//! Content Security Policy parser, evaluator, and bypass detector.
//!
//! Provides Observatory-compatible scoring and A-F grading.

mod checks;
mod parser;

use serde::Serialize;

use super::types::Severity;
use parser::{get_directive_values, get_script_src_values, has_nonce_or_hash, has_value};

#[derive(Debug, Clone, Serialize)]
pub struct CspReport {
    pub raw: String,
    pub directives: Vec<CspDirective>,
    pub findings: Vec<CspFinding>,
    pub grade: char,
    pub score: i32,
    pub has_unsafe_inline: bool,
    pub has_unsafe_eval: bool,
    pub has_nonce: bool,
    pub has_hash: bool,
    pub has_strict_dynamic: bool,
    pub missing_directives: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CspDirective {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CspFinding {
    pub directive: String,
    pub description: String,
    pub severity: Severity,
}

/// Parse and evaluate a Content-Security-Policy header value.
/// Returns `CspReport` with findings, grade, and score.
pub fn evaluate_csp(csp_header: &str) -> CspReport {
    if csp_header.trim().is_empty() {
        return CspReport {
            raw: String::new(),
            directives: vec![],
            findings: vec![CspFinding {
                directive: "content-security-policy".into(),
                description: "Content Security Policy not implemented".into(),
                severity: Severity::High,
            }],
            grade: 'F',
            score: -25,
            has_unsafe_inline: false,
            has_unsafe_eval: false,
            has_nonce: false,
            has_hash: false,
            has_strict_dynamic: false,
            missing_directives: vec![],
        };
    }

    let directives = parser::parse_csp(csp_header);
    let (findings, missing_directives) = checks::run_checks(&directives);

    let script_vals = get_script_src_values(&directives);
    let has_unsafe_inline = script_vals
        .map(|v| has_value(v, "'unsafe-inline'"))
        .unwrap_or(false);
    let has_unsafe_eval = script_vals
        .map(|v| has_value(v, "'unsafe-eval'"))
        .unwrap_or(false);
    let has_nonce = script_vals.map(|v| has_nonce_or_hash(v)).unwrap_or(false);
    let has_hash = has_nonce; // nonce_or_hash covers both
    let has_strict_dynamic = script_vals
        .map(|v| has_value(v, "'strict-dynamic'"))
        .unwrap_or(false);

    let score = compute_score(&directives, has_unsafe_inline, has_unsafe_eval);
    let grade = score_to_grade(score);

    CspReport {
        raw: csp_header.to_string(),
        directives,
        findings,
        grade,
        score,
        has_unsafe_inline,
        has_unsafe_eval,
        has_nonce,
        has_hash,
        has_strict_dynamic,
        missing_directives,
    }
}

/// Compute Observatory-compatible score.
fn compute_score(
    directives: &[CspDirective],
    has_unsafe_inline: bool,
    has_unsafe_eval: bool,
) -> i32 {
    // Check for insecure schemes or broad sources in script-src
    let script_vals = get_script_src_values(directives);
    if let Some(vals) = script_vals {
        let broad = ["https:", "data:", "http:", "*"];
        if vals.iter().any(|v| broad.contains(&v.as_str())) {
            return -20;
        }
    }

    // unsafe-inline in script-src (without nonce/hash) → -20
    if has_unsafe_inline {
        if let Some(vals) = script_vals {
            if !has_nonce_or_hash(vals) {
                return -20;
            }
        }
    }

    // unsafe-eval → -10
    if has_unsafe_eval {
        return -10;
    }

    // Check unsafe-inline in style-src only (not script-src) → 0
    let style_vals = get_directive_values(directives, "style-src");
    let style_has_unsafe = style_vals
        .map(|v| has_value(v, "'unsafe-inline'"))
        .unwrap_or(false);
    if style_has_unsafe {
        return 0;
    }

    // default-src 'none' with no unsafe → +10
    let default_vals = get_directive_values(directives, "default-src");
    let default_none = default_vals
        .map(|v| has_value(v, "'none'"))
        .unwrap_or(false);
    if default_none {
        return 10;
    }

    // No unsafe-inline, no unsafe-eval → +5
    5
}

fn score_to_grade(score: i32) -> char {
    match score {
        5..=i32::MAX => 'A',
        0..=4 => 'B',
        -10..=-1 => 'C',
        -24..=-11 => 'D',
        _ => 'F',
    }
}

#[cfg(test)]
mod tests;
