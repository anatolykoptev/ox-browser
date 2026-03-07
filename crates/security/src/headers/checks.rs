//! Core header check functions (HSTS, CSP, XCTO, XFO, Referrer, Permissions, COOP, COEP).

use std::collections::HashMap;

use crate::types::Severity;

use super::{get, missing, present, HeaderFinding, HeaderStatus};

const HSTS: &str = "strict-transport-security";
const MIN_MAX_AGE: u64 = 15_768_000;
const PRELOAD_MIN_AGE: u64 = 31_536_000;

pub(super) fn check_hsts(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    match get(h, HSTS) {
        None => out.push(missing(
            HSTS, Severity::High, "HSTS header missing",
            "Add Strict-Transport-Security with max-age >= 15768000",
        )),
        Some(v) => {
            let age = extract_max_age(&v);
            let lower = v.to_lowercase();
            let has_preload = lower.contains("preload");
            let has_sub = lower.contains("includesubdomains");

            if age < MIN_MAX_AGE {
                out.push(HeaderFinding {
                    header: HSTS.to_string(),
                    status: HeaderStatus::Present,
                    value: Some(v),
                    description: format!("HSTS max-age too short ({age} < {MIN_MAX_AGE})"),
                    severity: Severity::Medium,
                    recommendation: Some("Increase max-age to at least 15768000".into()),
                });
            } else if has_preload && has_sub && age >= PRELOAD_MIN_AGE {
                out.push(present(HSTS, &v, Severity::Info, "HSTS preload-ready"));
            } else if has_preload && (!has_sub || age < PRELOAD_MIN_AGE) {
                out.push(HeaderFinding {
                    header: HSTS.to_string(),
                    status: HeaderStatus::Present,
                    value: Some(v),
                    description: "HSTS has preload flag but doesn't meet preload requirements".into(),
                    severity: Severity::Low,
                    recommendation: Some(
                        "Add includeSubDomains and set max-age >= 31536000 for preload".into(),
                    ),
                });
            } else {
                out.push(present(HSTS, &v, Severity::Info, "HSTS configured correctly"));
            }
        }
    }
}

fn extract_max_age(val: &str) -> u64 {
    val.split(';')
        .map(str::trim)
        .find(|p| p.to_lowercase().starts_with("max-age"))
        .and_then(|p| p.split('=').nth(1))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0)
}

pub(super) fn check_csp(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "content-security-policy";
    match get(h, name) {
        None => out.push(missing(name, Severity::High, "CSP header missing", "Add a Content-Security-Policy header")),
        Some(v) => out.push(present(name, &v, Severity::Info, "CSP header present")),
    }
}

pub(super) fn check_xcto(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "x-content-type-options";
    match get(h, name) {
        None => out.push(missing(name, Severity::Medium, "X-Content-Type-Options missing", "Add X-Content-Type-Options: nosniff")),
        Some(v) if v.eq_ignore_ascii_case("nosniff") => {
            out.push(present(name, &v, Severity::Info, "X-Content-Type-Options set to nosniff"));
        }
        Some(v) => out.push(HeaderFinding {
            header: name.into(), status: HeaderStatus::Invalid, value: Some(v),
            description: "X-Content-Type-Options has invalid value".into(),
            severity: Severity::Medium, recommendation: Some("Set to nosniff".into()),
        }),
    }
}

pub(super) fn check_xfo(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "x-frame-options";
    match get(h, name) {
        None => out.push(missing(name, Severity::Medium, "X-Frame-Options missing", "Add X-Frame-Options: DENY or SAMEORIGIN")),
        Some(v) => {
            let up = v.to_uppercase();
            if up == "DENY" || up == "SAMEORIGIN" {
                out.push(present(name, &v, Severity::Info, "X-Frame-Options configured correctly"));
            } else {
                out.push(HeaderFinding {
                    header: name.into(), status: HeaderStatus::Invalid, value: Some(v),
                    description: "X-Frame-Options has unrecognized value".into(),
                    severity: Severity::Low, recommendation: Some("Use DENY or SAMEORIGIN".into()),
                });
            }
        }
    }
}

pub(super) fn check_referrer_policy(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "referrer-policy";
    let good = ["strict-origin-when-cross-origin", "no-referrer", "same-origin", "strict-origin"];
    match get(h, name) {
        None => out.push(missing(name, Severity::Low, "Referrer-Policy missing", "Add Referrer-Policy: strict-origin-when-cross-origin")),
        Some(v) => {
            let sev = if good.contains(&v.to_lowercase().as_str()) { Severity::Info } else { Severity::Low };
            out.push(present(name, &v, sev, "Referrer-Policy header present"));
        }
    }
}

pub(super) fn check_permissions_policy(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "permissions-policy";
    match get(h, name) {
        None => out.push(missing(name, Severity::Medium, "Permissions-Policy missing", "Add Permissions-Policy to restrict browser features")),
        Some(v) => out.push(present(name, &v, Severity::Info, "Permissions-Policy header present")),
    }
}

pub(super) fn check_coop(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "cross-origin-opener-policy";
    match get(h, name) {
        None => out.push(missing(name, Severity::Low, "COOP header missing", "Add Cross-Origin-Opener-Policy: same-origin")),
        Some(v) => out.push(present(name, &v, Severity::Info, "COOP header present")),
    }
}

pub(super) fn check_coep(h: &HashMap<String, String>, out: &mut Vec<HeaderFinding>) {
    let name = "cross-origin-embedder-policy";
    match get(h, name) {
        None => out.push(missing(name, Severity::Low, "COEP header missing", "Add Cross-Origin-Embedder-Policy: require-corp")),
        Some(v) => out.push(present(name, &v, Severity::Info, "COEP header present")),
    }
}
