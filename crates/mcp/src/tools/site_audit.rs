//! MCP tool: site_audit — comprehensive site audit with scores and recommendations.

use std::collections::HashMap;
use std::time::Instant;

use ox_intelligence::{accessibility, audit, performance, seo};
use rmcp::model::*;
use rmcp::ErrorData as McpError;
use serde::Deserialize;

use rmcp::schemars;
use schemars::JsonSchema;

use super::OxMcpServer;

/// Input parameters for the `site_audit` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SiteAuditInput {
    /// The URL to audit.
    pub url: String,
    /// Focus area: "all" (default), "seo", "performance", "accessibility", "security".
    #[serde(default)]
    pub focus: Option<String>,
}

impl OxMcpServer {
    pub(crate) async fn do_site_audit(
        &self,
        input: SiteAuditInput,
    ) -> Result<CallToolResult, McpError> {
        let start = Instant::now();
        let focus = input.focus.as_deref().unwrap_or("all");

        let resp = match self.http_client.get(&input.url).await {
            Ok(r) => r,
            Err(e) => {
                let json = serde_json::json!({
                    "url": input.url,
                    "error": e.to_string(),
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                });
                return Ok(CallToolResult::error(vec![Content::text(json.to_string())]));
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

        // Run all analyzers
        let seo_report = seo::analyze(&resp.body);
        let perf_report = performance::analyze(&headers, &resp.body);
        let a11y_report = accessibility::analyze(&resp.body);
        let sec_report = ox_security::analyze_security(
            &input.url,
            &headers,
            &set_cookie_headers,
            &resp.body,
        );

        // Security score: cap Observatory score to 0-100 range
        let sec_score = sec_report.score.clamp(0, 100) as u8;

        // Build categories based on focus
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
            url: input.url,
            overall_score: overall,
            overall_grade: audit::audit_grade(overall),
            categories,
            top_issues,
            elapsed_ms: start.elapsed().as_millis() as u64,
        };

        let json = serde_json::to_string(&result).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
