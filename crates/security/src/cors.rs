//! CORS security analyzer.

use std::collections::HashMap;

use serde::Serialize;

use super::types::Severity;

#[derive(Debug, Clone, Serialize)]
pub struct CorsReport {
    pub acao: Option<String>,
    pub acac: bool,
    pub findings: Vec<CorsFinding>,
    pub score_modifier: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorsFinding {
    pub description: String,
    pub severity: Severity,
}

/// Analyze CORS from response headers (lowercase keys).
pub fn analyze_cors(headers: &HashMap<String, String>) -> CorsReport {
    let acao = headers.get("access-control-allow-origin").cloned();
    let acac = headers
        .get("access-control-allow-credentials")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut findings = Vec::new();
    let mut score_modifier = 0;

    if let Some(ref origin) = acao {
        if origin == "*" {
            score_modifier = -50;
            findings.push(CorsFinding {
                description: "Access-Control-Allow-Origin set to wildcard (*)".into(),
                severity: Severity::Critical,
            });
            if acac {
                findings.push(CorsFinding {
                    description: "Wildcard ACAO with credentials — dangerous misconfiguration"
                        .into(),
                    severity: Severity::Critical,
                });
            }
        }
    }

    CorsReport { acao, acac, findings, score_modifier }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn test_cors_wildcard() {
        let r = analyze_cors(&headers(&[("access-control-allow-origin", "*")]));
        assert_eq!(r.score_modifier, -50);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_cors_restricted() {
        let r = analyze_cors(&headers(&[(
            "access-control-allow-origin",
            "https://example.com",
        )]));
        assert_eq!(r.score_modifier, 0);
    }

    #[test]
    fn test_cors_not_present() {
        let r = analyze_cors(&HashMap::new());
        assert_eq!(r.score_modifier, 0);
    }

    #[test]
    fn test_cors_wildcard_with_credentials() {
        let r = analyze_cors(&headers(&[
            ("access-control-allow-origin", "*"),
            ("access-control-allow-credentials", "true"),
        ]));
        assert_eq!(r.findings.len(), 2);
        assert!(r.findings.iter().all(|f| f.severity == Severity::Critical));
    }
}
