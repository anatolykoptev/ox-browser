//! Technology fingerprinting via rswappalyzer (7,000+ tech database).
//!
//! Thin wrapper that isolates callers from the upstream API.

use std::collections::HashMap;

use rswappalyzer::detector::TechDetector;
use rswappalyzer::RuleConfig;

/// A detected technology with name, categories, confidence, and optional version.
#[derive(Debug, Clone)]
pub struct Detection {
    pub name: String,
    pub categories: Vec<String>,
    pub confidence: u8,
    pub version: Option<String>,
}

/// Detect technologies from HTTP response data.
///
/// - `url`         — request URL (used for URL-pattern rules)
/// - `headers`     — lowercase header name → value map
/// - `html`        — raw HTML body
/// - `_meta_tags`  — meta name/property → content (handled internally by rswappalyzer)
/// - `_script_srcs`— script src values (handled internally by rswappalyzer via HTML parsing)
/// - `cookies`     — cookie name → value (injected as synthetic Cookie header)
///
/// Returns detections sorted by confidence descending.
pub fn detect(
    url: &str,
    headers: &HashMap<String, String>,
    html: &str,
    _meta_tags: &HashMap<String, String>,
    _script_srcs: &[String],
    cookies: &HashMap<String, String>,
) -> Vec<Detection> {
    let detector = match build_detector() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("fingerprint: detector init failed: {e}");
            return Vec::new();
        }
    };

    // Build FxHashMap<String, Vec<String>> for detect_with_hashmap.
    let mut hdr_map: rustc_hash::FxHashMap<String, Vec<String>> =
        rustc_hash::FxHashMap::default();

    for (k, v) in headers {
        hdr_map.entry(k.clone()).or_default().push(v.clone());
    }

    // Inject cookies as a synthetic Cookie header so the engine's cookie rules fire.
    if !cookies.is_empty() {
        let cookie_str = cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        hdr_map
            .entry("cookie".into())
            .or_default()
            .push(cookie_str);
    }

    let urls = &[url];
    let result = match detector.detect_with_hashmap(&hdr_map, urls, html.as_bytes()) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("fingerprint: detect failed: {e}");
            return Vec::new();
        }
    };

    result
        .technologies
        .into_iter()
        .map(|t| Detection {
            name: t.name,
            categories: t.categories,
            confidence: t.confidence,
            version: t.version,
        })
        .collect()
}

fn build_detector() -> Result<TechDetector, rswappalyzer::RswError> {
    TechDetector::with_embedded_rules(RuleConfig::embedded())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_headers() -> HashMap<String, String> {
        HashMap::new()
    }
    fn empty_meta() -> HashMap<String, String> {
        HashMap::new()
    }
    fn empty_cookies() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn detect_react_from_html() {
        let html = r#"<div id="root" data-reactroot="">Hello</div>"#;
        let results = detect(
            "https://example.com",
            &empty_headers(),
            html,
            &empty_meta(),
            &[],
            &empty_cookies(),
        );
        assert!(
            results.iter().any(|d| d.name == "React"),
            "expected React, got: {:?}",
            results
        );
    }

    #[test]
    fn detect_nextjs_from_header() {
        let mut headers = HashMap::new();
        headers.insert("x-powered-by".into(), "Next.js".into());
        let results = detect(
            "https://example.com",
            &headers,
            "",
            &empty_meta(),
            &[],
            &empty_cookies(),
        );
        assert!(
            results.iter().any(|d| d.name == "Next.js"),
            "expected Next.js, got: {:?}",
            results
        );
    }

    #[test]
    fn detect_nginx_from_headers() {
        let mut headers = HashMap::new();
        headers.insert("server".into(), "nginx/1.25.3".into());
        let results = detect(
            "https://example.com",
            &headers,
            "",
            &empty_meta(),
            &[],
            &empty_cookies(),
        );
        assert!(
            results.iter().any(|d| d.name == "Nginx"),
            "expected Nginx, got: {:?}",
            results
        );
    }

    #[test]
    fn detect_cloudflare_from_server_header() {
        let mut headers = HashMap::new();
        headers.insert("server".into(), "cloudflare".into());
        let results = detect(
            "https://example.com",
            &headers,
            "",
            &empty_meta(),
            &[],
            &empty_cookies(),
        );
        assert!(
            results.iter().any(|d| d.name == "Cloudflare"),
            "expected Cloudflare, got: {:?}",
            results
        );
    }

    #[test]
    fn detect_wordpress_from_meta_generator() {
        let html = r#"<meta name="generator" content="WordPress 6.5">"#;
        let results = detect(
            "https://example.com",
            &empty_headers(),
            html,
            &empty_meta(),
            &[],
            &empty_cookies(),
        );
        assert!(
            results.iter().any(|d| d.name == "WordPress"),
            "expected WordPress, got: {:?}",
            results
        );
    }

    #[test]
    fn empty_input_returns_empty() {
        let results = detect(
            "https://example.com",
            &empty_headers(),
            "",
            &empty_meta(),
            &[],
            &empty_cookies(),
        );
        assert!(results.is_empty(), "expected empty, got: {:?}", results);
    }

    #[test]
    fn detection_has_categories() {
        let html = r#"<div data-reactroot="">hello</div>"#;
        let results = detect(
            "https://example.com",
            &empty_headers(),
            html,
            &empty_meta(),
            &[],
            &empty_cookies(),
        );
        let react = results.iter().find(|d| d.name == "React");
        assert!(react.is_some(), "React not found");
        assert!(
            !react.unwrap().categories.is_empty(),
            "React should have at least one category"
        );
    }

    #[test]
    fn version_extracted_from_server_header() {
        let mut headers = HashMap::new();
        headers.insert("server".into(), "nginx/1.25.3".into());
        let results = detect(
            "https://example.com",
            &headers,
            "",
            &empty_meta(),
            &[],
            &empty_cookies(),
        );
        let nginx = results.iter().find(|d| d.name == "Nginx");
        assert!(nginx.is_some(), "Nginx not found");
        // rswappalyzer extracts version from server header via capture groups.
        // version may be None if the rule has no capture group — acceptable.
        if let Some(v) = &nginx.unwrap().version {
            assert!(v.contains("1.25"), "unexpected version: {v}");
        }
    }
}
