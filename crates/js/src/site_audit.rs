//! POST /site-audit — comprehensive site audit with scores and recommendations.

use std::collections::HashMap;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use ox_intelligence::{accessibility, audit, performance, seo};
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
pub struct SiteAuditRequest {
    pub url: String,
    #[serde(default)]
    pub focus: Option<String>,
}

pub async fn site_audit(
    State(state): State<AppState>,
    Json(req): Json<SiteAuditRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let start = Instant::now();
    let focus = req.focus.as_deref().unwrap_or("all");

    let resp = match state.http_client.get(&req.url).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": e.to_string()})),
            );
        }
    };

    let headers: HashMap<String, String> = resp
        .headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.to_string().to_lowercase(), val.to_owned()))
        })
        .collect();

    let set_cookie_headers: Vec<String> = resp
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_owned()))
        .collect();

    let seo_report = seo::analyze(&resp.body);
    let perf_report = performance::analyze(&headers, &resp.body);
    let a11y_report = accessibility::analyze(&resp.body);
    let sec_report = ox_security::analyze_security(
        &req.url,
        &headers,
        &set_cookie_headers,
        &resp.body,
        ox_security::ScanMode::Public,
    );

    let sec_score = sec_report.score.clamp(0, 100) as u8;
    let include = |cat: &str| focus == "all" || focus == cat;

    let categories = audit::AuditCategories {
        seo: include("seo").then(|| audit::CategoryAudit {
            score: seo_report.score,
            grade: audit::audit_grade(seo_report.score),
            findings: audit::seo_findings(&seo_report),
        }),
        performance: include("performance").then(|| audit::CategoryAudit {
            score: perf_report.score,
            grade: audit::audit_grade(perf_report.score),
            findings: audit::performance_findings(&perf_report),
        }),
        accessibility: include("accessibility").then(|| audit::CategoryAudit {
            score: a11y_report.score,
            grade: audit::audit_grade(a11y_report.score),
            findings: audit::accessibility_findings(&a11y_report),
        }),
        security: include("security").then(|| audit::CategoryAudit {
            score: sec_score,
            grade: audit::audit_grade(sec_score),
            findings: audit::security_findings(&sec_report),
        }),
    };

    let overall = audit::overall_score(
        seo_report.score,
        perf_report.score,
        a11y_report.score,
        sec_score,
    );
    let top_issues = audit::top_issues(&categories, 10);

    let result = audit::SiteAuditReport {
        url: req.url,
        overall_score: overall,
        overall_grade: audit::audit_grade(overall),
        categories,
        top_issues,
        elapsed_ms: start.elapsed().as_millis() as u64,
    };

    let json = serde_json::to_value(&result).unwrap_or_default();
    (StatusCode::OK, Json(json))
}
