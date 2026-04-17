//! Site audit: scores, findings, and recommendations across categories.

mod findings;
#[cfg(test)]
mod tests;

pub use findings::{accessibility_findings, performance_findings, security_findings, seo_findings};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub severity: &'static str,
    pub category: &'static str,
    pub message: String,
    pub fix: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryAudit {
    pub score: u8,
    pub grade: String,
    pub findings: Vec<AuditFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiteAuditReport {
    pub url: String,
    pub overall_score: u8,
    pub overall_grade: String,
    pub categories: AuditCategories,
    pub top_issues: Vec<AuditFinding>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditCategories {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seo: Option<CategoryAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub performance: Option<CategoryAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessibility: Option<CategoryAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<CategoryAudit>,
}

/// Convert a numeric score (0-100) to a letter grade.
pub fn audit_grade(score: u8) -> String {
    match score {
        97..=100 => "A+",
        93..=96 => "A",
        90..=92 => "A-",
        87..=89 => "B+",
        83..=86 => "B",
        80..=82 => "B-",
        77..=79 => "C+",
        73..=76 => "C",
        70..=72 => "C-",
        67..=69 => "D+",
        63..=66 => "D",
        60..=62 => "D-",
        _ => "F",
    }
    .to_string()
}

/// Compute an overall score as the average of four category scores.
pub fn overall_score(seo: u8, perf: u8, a11y: u8, security: u8) -> u8 {
    let total = seo as u32 + perf as u32 + a11y as u32 + security as u32;
    (total / 4) as u8
}

/// Collect top issues from all categories, sorted by severity.
pub fn top_issues(categories: &AuditCategories, max: usize) -> Vec<AuditFinding> {
    let mut all: Vec<AuditFinding> = Vec::new();
    for cat in [
        &categories.seo,
        &categories.performance,
        &categories.accessibility,
        &categories.security,
    ] {
        if let Some(c) = cat {
            all.extend(c.findings.iter().cloned());
        }
    }
    all.sort_by_key(|f| match f.severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    });
    all.truncate(max);
    all
}
