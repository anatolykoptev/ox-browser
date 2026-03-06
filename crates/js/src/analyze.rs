//! POST /analyze — fetch page, detect technologies, discover assets.

use std::collections::HashMap;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_core::Page;
use ox_http::detect_cloudflare;
use ox_intelligence::fingerprint::Fingerprinter;
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Deserialize)]
pub struct AnalyzeRequest {
    pub url: String,
}

#[derive(Serialize)]
pub struct AnalyzeResponse {
    pub url: String,
    pub status: u16,
    pub technologies: Vec<TechInfo>,
    pub meta: MetaInfo,
    pub assets: AssetInfo,
    pub method: String,
    pub cf_detected: bool,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct TechInfo {
    pub name: String,
    pub category: String,
    pub confidence: u8,
}

#[derive(Serialize)]
pub struct MetaInfo {
    pub generator: String,
    pub server: String,
    pub powered_by: String,
    pub title: String,
}

#[derive(Serialize)]
pub struct AssetInfo {
    pub scripts: Vec<String>,
    pub stylesheets: Vec<String>,
}

pub async fn analyze(
    State(state): State<AppState>,
    Json(req): Json<AnalyzeRequest>,
) -> (StatusCode, Json<AnalyzeResponse>) {
    let start = Instant::now();

    let resp = match state.http_client.get(&req.url).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(AnalyzeResponse {
                    url: req.url,
                    status: 0,
                    technologies: vec![],
                    assets: AssetInfo {
                        scripts: vec![],
                        stylesheets: vec![],
                    },
                    meta: MetaInfo {
                        generator: String::new(),
                        server: String::new(),
                        powered_by: String::new(),
                        title: String::new(),
                    },
                    method: "direct".into(),
                    cf_detected: false,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: Some(e.to_string()),
                }),
            );
        }
    };

    let cf_detected = detect_cloudflare(&resp).is_some();
    let page = Page::new(resp.url.clone(), resp.status, &resp.body);

    // Build lowercase headers map.
    let headers: HashMap<String, String> = resp
        .headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.to_string().to_lowercase(), val.to_owned()))
        })
        .collect();

    // Extract meta tags as name→content map.
    let meta_tags: HashMap<String, String> = page
        .meta_tags()
        .into_iter()
        .filter(|m| !m.name.is_empty())
        .map(|m| (m.name.to_lowercase(), m.content))
        .collect();

    // Extract script src URLs.
    let script_srcs: Vec<String> = page
        .select("script[src]")
        .iter()
        .filter_map(|s| s.attr("src").map(|v| v.to_string()))
        .collect();

    // Extract stylesheet hrefs.
    let stylesheets: Vec<String> = page
        .select("link[rel='stylesheet'][href]")
        .iter()
        .filter_map(|s| s.attr("href").map(|v| v.to_string()))
        .collect();

    // Run fingerprinting.
    let fingerprinter = Fingerprinter::new();
    let detections = fingerprinter.detect(&headers, &resp.body, &meta_tags, &script_srcs);

    let technologies: Vec<TechInfo> = detections
        .into_iter()
        .map(|d| TechInfo {
            name: d.name,
            category: d.category,
            confidence: d.confidence,
        })
        .collect();

    // Extract meta info.
    let meta = MetaInfo {
        generator: meta_tags.get("generator").cloned().unwrap_or_default(),
        server: headers.get("server").cloned().unwrap_or_default(),
        powered_by: headers.get("x-powered-by").cloned().unwrap_or_default(),
        title: page.title(),
    };

    (
        StatusCode::OK,
        Json(AnalyzeResponse {
            url: req.url,
            status: resp.status,
            technologies,
            meta,
            assets: AssetInfo {
                scripts: script_srcs,
                stylesheets,
            },
            method: "direct".into(),
            cf_detected,
            elapsed_ms: start.elapsed().as_millis() as u64,
            error: None,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_request_deserializes() {
        let json = r#"{"url": "https://example.com"}"#;
        let req: AnalyzeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.url, "https://example.com");
    }

    #[test]
    fn analyze_response_serializes() {
        let resp = AnalyzeResponse {
            url: "https://example.com".into(),
            status: 200,
            technologies: vec![TechInfo {
                name: "React".into(),
                category: "JS Framework".into(),
                confidence: 100,
            }],
            meta: MetaInfo {
                generator: String::new(),
                server: "nginx".into(),
                powered_by: String::new(),
                title: "Test".into(),
            },
            assets: AssetInfo {
                scripts: vec!["app.js".into()],
                stylesheets: vec!["style.css".into()],
            },
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 500,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["technologies"][0]["name"], "React");
        assert!(!json.as_object().unwrap().contains_key("error"));
    }
}
