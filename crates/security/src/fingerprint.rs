//! Wappalyzer-compatible technology fingerprinting.

use regex::RegexBuilder;
use serde::Deserialize;
use std::collections::HashMap;

const DB_JSON: &str = include_str!("fingerprints.json");

#[derive(Debug, Clone)]
pub struct Detection {
    pub name: String,
    pub category: String,
    pub confidence: u8,
}

#[derive(Deserialize)]
struct FingerprintDB {
    categories: HashMap<String, String>,
    technologies: HashMap<String, TechDef>,
}

#[derive(Deserialize)]
struct TechDef {
    cats: Vec<u32>,
    #[serde(default)]
    html: Vec<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    meta: HashMap<String, String>,
    #[serde(default)]
    scripts: Vec<String>,
}

/// Fingerprinter matches HTML + headers against the embedded Wappalyzer DB.
pub struct Fingerprinter {
    db: FingerprintDB,
}

impl Fingerprinter {
    /// Load the embedded fingerprint database.
    pub fn new() -> Self {
        let db: FingerprintDB =
            serde_json::from_str(DB_JSON).expect("embedded fingerprints.json is valid");
        Self { db }
    }

    /// Detect technologies from HTTP headers and HTML body.
    /// `headers` should be lowercase key → value.
    /// `meta_tags` should be name/property → content.
    pub fn detect(
        &self,
        headers: &HashMap<String, String>,
        html: &str,
        meta_tags: &HashMap<String, String>,
        script_srcs: &[String],
    ) -> Vec<Detection> {
        let mut results = Vec::new();
        let html_lower = html.to_lowercase();

        for (name, def) in &self.db.technologies {
            let mut confidence: u8 = 0;

            // Match HTML patterns.
            for pattern in &def.html {
                if let Ok(re) = RegexBuilder::new(pattern).case_insensitive(true).build() {
                    if re.is_match(&html_lower) {
                        confidence = confidence.saturating_add(50);
                        break;
                    }
                } else if html_lower.contains(&pattern.to_lowercase()) {
                    confidence = confidence.saturating_add(50);
                    break;
                }
            }

            // Match headers.
            for (hdr_name, hdr_pattern) in &def.headers {
                let hdr_lower = hdr_name.to_lowercase();
                if let Some(val) = headers.get(&hdr_lower)
                    && (hdr_pattern.is_empty()
                        || val.to_lowercase().contains(&hdr_pattern.to_lowercase()))
                {
                    confidence = confidence.saturating_add(50);
                    break;
                }
            }

            // Match meta tags.
            for (meta_name, meta_pattern) in &def.meta {
                if let Some(content) = meta_tags.get(&meta_name.to_lowercase())
                    && content
                        .to_lowercase()
                        .contains(&meta_pattern.to_lowercase())
                {
                    confidence = confidence.saturating_add(25);
                    break;
                }
            }

            // Match script sources.
            for pattern in &def.scripts {
                if let Ok(re) = RegexBuilder::new(pattern).case_insensitive(true).build() {
                    for src in script_srcs {
                        if re.is_match(src) {
                            confidence = confidence.saturating_add(25);
                            break;
                        }
                    }
                }
                if confidence > 0 {
                    break;
                }
            }

            if confidence > 0 {
                let cat_id = def.cats.first().copied().unwrap_or(0).to_string();
                let category = self
                    .db
                    .categories
                    .get(&cat_id)
                    .cloned()
                    .unwrap_or_else(|| "Other".into());
                results.push(Detection {
                    name: name.clone(),
                    category,
                    confidence: confidence.min(100),
                });
            }
        }

        results.sort_by_key(|d| std::cmp::Reverse(d.confidence));
        results
    }
}

impl Default for Fingerprinter {
    fn default() -> Self {
        Self::new()
    }
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

    #[test]
    fn detect_react_from_html() {
        let fp = Fingerprinter::new();
        let html = r#"<div id="root" data-reactroot="">Hello</div>"#;
        let results = fp.detect(&empty_headers(), html, &empty_meta(), &[]);
        assert!(
            results.iter().any(|d| d.name == "React"),
            "expected React, got: {:?}",
            results
        );
    }

    #[test]
    fn detect_nextjs_from_html() {
        let fp = Fingerprinter::new();
        let html = r#"<script id="__NEXT_DATA__" type="application/json">{}</script>"#;
        let results = fp.detect(&empty_headers(), html, &empty_meta(), &[]);
        assert!(
            results.iter().any(|d| d.name == "Next.js"),
            "expected Next.js, got: {:?}",
            results
        );
    }

    #[test]
    fn detect_nginx_from_headers() {
        let fp = Fingerprinter::new();
        let mut headers = HashMap::new();
        headers.insert("server".into(), "nginx/1.25.3".into());
        let results = fp.detect(&headers, "", &empty_meta(), &[]);
        assert!(
            results.iter().any(|d| d.name == "nginx"),
            "expected nginx, got: {:?}",
            results
        );
    }

    #[test]
    fn detect_cloudflare_from_headers() {
        let fp = Fingerprinter::new();
        let mut headers = HashMap::new();
        headers.insert("cf-ray".into(), "abc123".into());
        let results = fp.detect(&headers, "", &empty_meta(), &[]);
        assert!(
            results.iter().any(|d| d.name == "Cloudflare"),
            "expected Cloudflare, got: {:?}",
            results
        );
    }

    #[test]
    fn detect_wordpress_from_meta() {
        let fp = Fingerprinter::new();
        let mut meta = HashMap::new();
        meta.insert("generator".into(), "WordPress 6.5".into());
        let results = fp.detect(&empty_headers(), "", &meta, &[]);
        assert!(
            results.iter().any(|d| d.name == "WordPress"),
            "expected WordPress, got: {:?}",
            results
        );
    }

    #[test]
    fn detect_jquery_from_scripts() {
        let fp = Fingerprinter::new();
        let scripts = vec!["https://cdn.example.com/jquery-3.7.1.min.js".into()];
        let results = fp.detect(&empty_headers(), "", &empty_meta(), &scripts);
        assert!(
            results.iter().any(|d| d.name == "jQuery"),
            "expected jQuery, got: {:?}",
            results
        );
    }

    #[test]
    fn empty_input_returns_empty() {
        let fp = Fingerprinter::new();
        let results = fp.detect(&empty_headers(), "", &empty_meta(), &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn multiple_techs_detected() {
        let fp = Fingerprinter::new();
        let html =
            r#"<div data-reactroot=""><script src="/_next/static/chunks/main.js"></script></div>"#;
        let mut headers = HashMap::new();
        headers.insert("server".into(), "nginx".into());
        let results = fp.detect(&headers, html, &empty_meta(), &[]);
        let names: Vec<&str> = results.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"React"), "missing React in {:?}", names);
        assert!(names.contains(&"Next.js"), "missing Next.js in {:?}", names);
        assert!(names.contains(&"nginx"), "missing nginx in {:?}", names);
    }
}
