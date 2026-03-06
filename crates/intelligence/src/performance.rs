//! Performance analysis: cache, compression, resource hints, lazy images.

use std::collections::HashMap;

use dom_query::Document;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceHint {
    pub href: String,
    pub as_type: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PerformanceReport {
    pub compression: String,
    pub cache_control: String,
    pub etag: String,
    pub expires: String,
    pub age: String,
    pub http3_supported: bool,
    pub preload: Vec<ResourceHint>,
    pub prefetch: Vec<ResourceHint>,
    pub preconnect: Vec<String>,
    pub images_total: u32,
    pub images_lazy: u32,
    pub inline_styles_count: u32,
    pub inline_styles_bytes: u32,
}

/// Analyze HTTP headers and HTML body for performance characteristics.
///
/// `headers` keys must be lowercase.
pub fn analyze(headers: &HashMap<String, String>, html: &str) -> PerformanceReport {
    let mut report = PerformanceReport {
        compression: header(headers, "content-encoding"),
        cache_control: header(headers, "cache-control"),
        etag: header(headers, "etag"),
        expires: header(headers, "expires"),
        age: header(headers, "age"),
        http3_supported: detect_http3(headers),
        ..Default::default()
    };

    parse_html(html, &mut report);
    report
}

fn header(headers: &HashMap<String, String>, key: &str) -> String {
    headers.get(key).cloned().unwrap_or_default()
}

fn detect_http3(headers: &HashMap<String, String>) -> bool {
    headers
        .get("alt-svc")
        .map(|v| v.contains("h3"))
        .unwrap_or(false)
}

fn parse_html(html: &str, report: &mut PerformanceReport) {
    let doc = Document::from(html);

    // Resource hints from <link> tags.
    for node in doc.select("link").iter() {
        let rel = node.attr("rel").map(|v| v.to_string()).unwrap_or_default().to_lowercase();
        let href = node.attr("href").map(|v| v.to_string()).unwrap_or_default();

        match rel.as_str() {
            "preload" => report.preload.push(ResourceHint {
                href,
                as_type: node.attr("as").map(|v| v.to_string()).unwrap_or_default(),
            }),
            "prefetch" => report.prefetch.push(ResourceHint {
                href,
                as_type: node.attr("as").map(|v| v.to_string()).unwrap_or_default(),
            }),
            "preconnect" => report.preconnect.push(href),
            _ => {}
        }
    }

    // Images: total and lazy-loaded.
    for node in doc.select("img").iter() {
        report.images_total += 1;
        if node
            .attr("loading")
            .map(|v| v.to_string().eq_ignore_ascii_case("lazy"))
            .unwrap_or(false)
        {
            report.images_lazy += 1;
        }
    }

    // Inline <style> tags.
    for node in doc.select("style").iter() {
        report.inline_styles_count += 1;
        report.inline_styles_bytes += node.text().len() as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn detect_compression() {
        let h = headers(&[("content-encoding", "gzip")]);
        let r = analyze(&h, "");
        assert_eq!(r.compression, "gzip");
    }

    #[test]
    fn detect_cache_headers() {
        let h = headers(&[
            ("cache-control", "max-age=3600, public"),
            ("etag", "\"abc123\""),
            ("expires", "Thu, 01 Jan 2026 00:00:00 GMT"),
            ("age", "120"),
        ]);
        let r = analyze(&h, "");
        assert_eq!(r.cache_control, "max-age=3600, public");
        assert_eq!(r.etag, "\"abc123\"");
        assert_eq!(r.expires, "Thu, 01 Jan 2026 00:00:00 GMT");
        assert_eq!(r.age, "120");
    }

    #[test]
    fn detect_http3() {
        let h = headers(&[("alt-svc", "h3=\":443\"; ma=86400")]);
        let r = analyze(&h, "");
        assert!(r.http3_supported);
    }

    #[test]
    fn detect_http3_absent() {
        let h = headers(&[("alt-svc", "h2=\":443\"")]);
        let r = analyze(&h, "");
        assert!(!r.http3_supported);
    }

    #[test]
    fn detect_preload_hints() {
        let html = r#"
            <link rel="preload" href="/font.woff2" as="font">
            <link rel="prefetch" href="/next-page.js" as="script">
            <link rel="preconnect" href="https://cdn.example.com">
        "#;
        let r = analyze(&HashMap::new(), html);
        assert_eq!(r.preload.len(), 1);
        assert_eq!(r.preload[0].href, "/font.woff2");
        assert_eq!(r.preload[0].as_type, "font");
        assert_eq!(r.prefetch.len(), 1);
        assert_eq!(r.prefetch[0].href, "/next-page.js");
        assert_eq!(r.preconnect, vec!["https://cdn.example.com".to_string()]);
    }

    #[test]
    fn detect_lazy_images() {
        let html = r#"
            <img src="a.jpg">
            <img src="b.jpg" loading="lazy">
            <img src="c.jpg" loading="lazy">
            <img src="d.jpg" loading="eager">
        "#;
        let r = analyze(&HashMap::new(), html);
        assert_eq!(r.images_total, 4);
        assert_eq!(r.images_lazy, 2);
    }

    #[test]
    fn detect_inline_css() {
        let html = r#"
            <style>body { color: red; }</style>
            <style>.foo { display: none; }</style>
        "#;
        let r = analyze(&HashMap::new(), html);
        assert_eq!(r.inline_styles_count, 2);
        assert!(r.inline_styles_bytes > 0);
    }
}
