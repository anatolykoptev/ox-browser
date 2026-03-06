//! POST /analyze — fetch page, detect technologies, run intelligence modules.

use std::collections::HashMap;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_core::Page;
use ox_http::detect_cloudflare;
use ox_intelligence::{
    accessibility, api_discovery, content, fingerprint, fonts, media, performance, pwa, seo,
};

use crate::analyze_types::*;
use crate::AppState;

pub async fn analyze(
    State(state): State<AppState>,
    Json(req): Json<AnalyzeRequest>,
) -> (StatusCode, Json<AnalyzeResponse>) {
    let start = Instant::now();

    let resp = match state.http_client.get(&req.url).await {
        Ok(r) => r,
        Err(e) => {
            let elapsed = start.elapsed().as_millis() as u64;
            return (
                StatusCode::BAD_GATEWAY,
                Json(AnalyzeResponse::error(req.url, elapsed, e.to_string())),
            );
        }
    };

    let cf_detected = detect_cloudflare(&resp).is_some();
    let page = Page::new(resp.url.clone(), resp.status, &resp.body);

    let headers: HashMap<String, String> = resp
        .headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.to_string().to_lowercase(), val.to_owned()))
        })
        .collect();

    let meta_tags: HashMap<String, String> = page
        .meta_tags()
        .into_iter()
        .filter(|m| !m.name.is_empty())
        .map(|m| (m.name.to_lowercase(), m.content))
        .collect();

    let script_srcs: Vec<String> = page
        .select("script[src]")
        .iter()
        .filter_map(|s| s.attr("src").map(|v| v.to_string()))
        .collect();

    let stylesheets: Vec<String> = page
        .select("link[rel='stylesheet'][href]")
        .iter()
        .filter_map(|s| s.attr("href").map(|v| v.to_string()))
        .collect();

    let cookies: HashMap<String, String> = headers
        .get("set-cookie")
        .map(|v| {
            v.split(';')
                .filter_map(|pair| {
                    let mut kv = pair.trim().splitn(2, '=');
                    let k = kv.next()?.trim().to_owned();
                    let val = kv.next().unwrap_or("").trim().to_owned();
                    if k.is_empty() {
                        None
                    } else {
                        Some((k, val))
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let detections =
        fingerprint::detect(&req.url, &headers, &resp.body, &meta_tags, &script_srcs, &cookies);

    let technologies: Vec<TechInfo> = detections
        .into_iter()
        .map(|d| TechInfo {
            name: d.name,
            categories: d.categories,
            confidence: d.confidence,
            version: d.version,
        })
        .collect();

    let meta = MetaInfo {
        generator: meta_tags.get("generator").cloned().unwrap_or_default(),
        server: headers.get("server").cloned().unwrap_or_default(),
        powered_by: headers.get("x-powered-by").cloned().unwrap_or_default(),
        title: page.title(),
    };

    let seo_report = seo::analyze(&resp.body);
    let perf_report = performance::analyze(&headers, &resp.body);
    let a11y_report = accessibility::analyze(&resp.body);
    let content_report = content::analyze(&resp.body, &req.url);
    let media_report = media::analyze(&resp.body);
    let fonts_report = fonts::analyze(&resp.body);
    let pwa_report = pwa::analyze(&resp.body);
    let api_report = api_discovery::analyze(&resp.body);

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
            seo: seo_report,
            performance: perf_report,
            accessibility: a11y_report,
            content: content_report,
            media: media_report,
            fonts: fonts_report,
            pwa: pwa_report,
            api: api_report,
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
    fn analyze_response_serializes_with_intelligence() {
        let resp = AnalyzeResponse {
            url: "https://example.com".into(),
            status: 200,
            technologies: vec![TechInfo {
                name: "React".into(),
                categories: vec!["JavaScript frameworks".into()],
                confidence: 100,
                version: None,
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
            seo: Default::default(),
            performance: Default::default(),
            accessibility: Default::default(),
            content: Default::default(),
            media: Default::default(),
            fonts: Default::default(),
            pwa: Default::default(),
            api: Default::default(),
            method: "direct".into(),
            cf_detected: false,
            elapsed_ms: 500,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["technologies"][0]["name"], "React");
        assert!(json["seo"].is_object());
        assert!(json["performance"].is_object());
        assert!(!json.as_object().unwrap().contains_key("error"));
    }

    #[test]
    fn error_response_has_default_reports() {
        let resp = AnalyzeResponse::error("https://x.com".into(), 100, "timeout".into());
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["error"], "timeout");
        assert_eq!(json["seo"]["score"], 0);
    }
}
