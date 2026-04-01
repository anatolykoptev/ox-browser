//! Protection detection engine.
//!
//! Detects WAFs, bot-detection systems, CAPTCHAs, fingerprinting
//! services, and auth-security providers from HTTP response signals.

mod rules;

use std::collections::HashMap;

use serde::Serialize;

use crate::types::{ScanMode, Severity};
use rules::{DB, COMPILED};

#[cfg(test)]
mod tests;

// ── Public types ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ProtectionReport {
    pub detections: Vec<ProtectionDetection>,
    pub findings: Vec<ProtectionFinding>,
    pub summary: ProtectionSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtectionDetection {
    pub name: String,
    pub category: String,
    pub category_label: String,
    pub confidence: u8,
    pub matched_signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtectionFinding {
    pub check: String,
    pub detail: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtectionSummary {
    pub has_waf: bool,
    pub has_bot_detection: bool,
    pub has_captcha: bool,
    pub has_fingerprinting: bool,
    pub has_auth_security: bool,
    pub total_systems: usize,
}

// ── Entry point ───────────────────────────────────────────────

pub fn detect_protection(
    headers: &HashMap<String, String>,
    cookie_names: &[String],
    html: &str,
    page_url: &str,
    mode: ScanMode,
) -> ProtectionReport {
    let db = &*DB;

    let lower_cookies: Vec<String> =
        cookie_names.iter().map(|c| c.to_ascii_lowercase()).collect();

    let lower_headers: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();

    let mut detections: Vec<ProtectionDetection> = Vec::new();

    let compiled = &*COMPILED;

    for (idx, rule) in db.rules.iter().enumerate() {
        let (confidence, matched) =
            evaluate_rule(rule, &compiled[idx], &lower_headers, &lower_cookies, cookie_names, html, page_url);

        if confidence == 0 {
            continue;
        }

        let category_label = db
            .categories
            .get(&rule.category)
            .cloned()
            .unwrap_or_default();

        detections.push(ProtectionDetection {
            name: rule.name.clone(),
            category: rule.category.clone(),
            category_label,
            confidence,
            matched_signals: matched,
        });
    }

    detections.sort_by(|a, b| b.confidence.cmp(&a.confidence));

    let summary = build_summary(&detections);
    let findings = build_findings(mode, &summary, db);

    ProtectionReport {
        detections,
        findings,
        summary,
    }
}

// ── Rule evaluation ───────────────────────────────────────────

fn evaluate_rule(
    rule: &rules::Rule,
    compiled: &rules::CompiledRule,
    headers: &HashMap<String, String>,
    lower_cookies: &[String],
    original_cookies: &[String],
    html: &str,
    page_url: &str,
) -> (u8, Vec<String>) {
    let sig = &rule.signals;
    let boost = &rule.confidence_boost;
    let mut confidence: u16 = 0;
    let mut matched = Vec::new();

    // 1. Exact cookie match (case-insensitive via pre-lowered names)
    if let Some(&pts) = boost.get("cookies") {
        for pattern in &sig.cookies {
            let pat_lower = pattern.to_ascii_lowercase();
            if lower_cookies.iter().any(|c| *c == pat_lower) {
                confidence += u16::from(pts);
                matched.push(format!("cookie:{pattern}"));
                break;
            }
        }
    }

    // 2. Cookie prefix match (case-insensitive via pre-lowered names)
    if let Some(&pts) = boost.get("cookies") {
        for prefix in &sig.cookies_prefix {
            let pfx_lower = prefix.to_ascii_lowercase();
            if lower_cookies.iter().any(|c| c.starts_with(&pfx_lower)) {
                confidence += u16::from(pts);
                matched.push(format!("cookie_prefix:{prefix}"));
                break;
            }
        }
    }

    // 3. Cookie regex match (original case — regex controls sensitivity)
    if let Some(&pts) = boost.get("cookies") {
        for (i, re) in compiled.cookies_regex.iter().enumerate() {
            if original_cookies.iter().any(|c| re.is_match(c)) {
                confidence += u16::from(pts);
                let pat = &sig.cookies_regex[i];
                matched.push(format!("cookie_regex:{pat}"));
                break;
            }
        }
    }

    // 4. Header exact match
    if let Some(&pts) = boost.get("headers") {
        for (name, value) in &sig.headers {
            let name_lower = name.to_ascii_lowercase();
            if let Some(hdr_val) = headers.get(&name_lower) {
                if value.is_empty() || hdr_val.to_ascii_lowercase().contains(&value.to_ascii_lowercase()) {
                    confidence += u16::from(pts);
                    matched.push(format!("header:{name}"));
                    break;
                }
            }
        }
    }

    // 5. Header regex match (matches header NAME)
    if let Some(&pts) = boost.get("headers") {
        for (i, re) in compiled.headers_regex.iter().enumerate() {
            if headers.keys().any(|k| re.is_match(k)) {
                confidence += u16::from(pts);
                let pat = &sig.headers_regex[i];
                matched.push(format!("header_regex:{pat}"));
                break;
            }
        }
    }

    // 6. Script patterns
    if let Some(&pts) = boost.get("scripts") {
        for (i, re) in compiled.scripts.iter().enumerate() {
            if re.is_match(html) {
                confidence += u16::from(pts);
                let pat = &sig.scripts[i];
                matched.push(format!("script:{pat}"));
                break;
            }
        }
    }

    // 7. HTML patterns
    if let Some(&pts) = boost.get("html_patterns") {
        for (i, re) in compiled.html_patterns.iter().enumerate() {
            if re.is_match(html) {
                confidence += u16::from(pts);
                let pat = &sig.html_patterns[i];
                matched.push(format!("html:{pat}"));
                break;
            }
        }
    }

    // 8. URL patterns
    if let Some(&pts) = boost.get("url_patterns") {
        for (i, re) in compiled.url_patterns.iter().enumerate() {
            if re.is_match(page_url) {
                confidence += u16::from(pts);
                let pat = &sig.url_patterns[i];
                matched.push(format!("url:{pat}"));
                break;
            }
        }
    }

    let capped = confidence.min(100) as u8;
    (capped, matched)
}

// ── Summary builder ───────────────────────────────────────────

fn build_summary(detections: &[ProtectionDetection]) -> ProtectionSummary {
    ProtectionSummary {
        has_waf: detections.iter().any(|d| d.category == "waf"),
        has_bot_detection: detections.iter().any(|d| d.category == "bot_detection"),
        has_captcha: detections.iter().any(|d| d.category == "captcha"),
        has_fingerprinting: detections.iter().any(|d| d.category == "fingerprinting"),
        has_auth_security: detections.iter().any(|d| d.category == "auth_security"),
        total_systems: detections.len(),
    }
}

// ── Mode-specific findings ────────────────────────────────────

fn build_findings(
    mode: ScanMode,
    summary: &ProtectionSummary,
    db: &rules::RulesDB,
) -> Vec<ProtectionFinding> {
    let mut findings = Vec::new();

    if mode != ScanMode::Login {
        return findings;
    }

    let Some(login_findings) = db.mode_findings.get("login") else {
        return findings;
    };

    // PoW challenge (bot_detection) is functionally equivalent to CAPTCHA.
    if !summary.has_captcha && !summary.has_bot_detection {
        if let Some(f) = login_findings.get("no_captcha") {
            findings.push(ProtectionFinding {
                check: "no_captcha".to_owned(),
                detail: f.message.clone(),
                severity: parse_severity(&f.severity),
            });
        }
    }

    if !summary.has_bot_detection && !summary.has_waf {
        if let Some(f) = login_findings.get("no_bot_detection") {
            findings.push(ProtectionFinding {
                check: "no_bot_detection".to_owned(),
                detail: f.message.clone(),
                severity: parse_severity(&f.severity),
            });
        }
    }

    if !summary.has_fingerprinting {
        if let Some(f) = login_findings.get("no_fingerprinting") {
            findings.push(ProtectionFinding {
                check: "no_fingerprinting".to_owned(),
                detail: f.message.clone(),
                severity: parse_severity(&f.severity),
            });
        }
    }

    findings
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}
