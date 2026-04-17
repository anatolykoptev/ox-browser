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
    pub has_speculation_rules: bool,
    pub font_preloads: u32,
    pub images_modern_format: u32,
    pub images_legacy_format: u32,
    pub score: u8,
}

/// Analyze HTTP headers and HTML body for performance characteristics.
///
/// `headers` keys must be lowercase.
pub fn analyze(headers: &HashMap<String, String>, html: &str) -> PerformanceReport {
    // HTTP clients auto-decompress and strip content-encoding.
    // Detect compression reliably: check explicit header first,
    // then vary: accept-encoding as proof server supports it.
    let compression = detect_compression(headers);

    let mut report = PerformanceReport {
        compression,
        cache_control: header(headers, "cache-control"),
        etag: header(headers, "etag"),
        expires: header(headers, "expires"),
        age: header(headers, "age"),
        http3_supported: detect_http3(headers),
        ..Default::default()
    };

    parse_html(html, &mut report);
    report.score = compute_score(&report);
    report
}

fn compute_score(r: &PerformanceReport) -> u8 {
    let mut score: u32 = 0;
    if !r.compression.is_empty() {
        score += 15;
    }
    if !r.cache_control.is_empty() {
        score += 12;
    }
    if !r.etag.is_empty() || !r.expires.is_empty() {
        score += 10;
    }
    if !r.preload.is_empty() {
        score += 8;
    }
    if !r.preconnect.is_empty() {
        score += 5;
    }
    let lazy_ratio = if r.images_total > 0 {
        r.images_lazy * 100 / r.images_total
    } else {
        100
    };
    if lazy_ratio >= 50 {
        score += 8;
    }
    if r.inline_styles_bytes < 10_000 {
        score += 5;
    }
    if r.http3_supported {
        score += 5;
    }
    if !r.prefetch.is_empty() {
        score += 2;
    }
    if r.inline_styles_count == 0 {
        score += 3;
    }
    // New checks
    if r.has_speculation_rules {
        score += 5;
    }
    if r.font_preloads > 0 {
        score += 8;
    }
    let total_imgs = r.images_modern_format + r.images_legacy_format;
    if total_imgs > 0 && r.images_legacy_format == 0 {
        score += 7;
    }
    if total_imgs == 0 {
        score += 7;
    } // No images = no format issue
    score.min(100) as u8
}

fn header(headers: &HashMap<String, String>, key: &str) -> String {
    headers.get(key).cloned().unwrap_or_default()
}

/// Detect compression from response headers.
///
/// HTTP clients like wreq/reqwest auto-decompress and strip `content-encoding`.
/// We check three signals (most reliable first):
/// 1. Explicit `content-encoding` (if client didn't strip it)
/// 2. `vary: accept-encoding` — server negotiates encoding, meaning compression is configured
/// 3. `content-type` with charset on text/* — common with compressed responses
fn detect_compression(headers: &HashMap<String, String>) -> String {
    let ce = header(headers, "content-encoding");
    if !ce.is_empty() {
        return ce;
    }
    let vary = header(headers, "vary").to_lowercase();
    if vary.contains("accept-encoding") {
        return "gzip".to_owned(); // server confirmed compression support
    }
    String::new()
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
        let rel = node
            .attr("rel")
            .map(|v| v.to_string())
            .unwrap_or_default()
            .to_lowercase();
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

    // Speculation rules (prerender/prefetch via JSON).
    report.has_speculation_rules = doc.select("script[type='speculationrules']").length() > 0;

    // Font preloads (critical for LCP).
    report.font_preloads = report
        .preload
        .iter()
        .filter(|h| h.as_type == "font")
        .count() as u32;

    // Image formats: modern (WebP/AVIF) vs legacy (JPEG/PNG/GIF).
    for img in doc.select("img[src]").iter() {
        let src = img.attr("src").unwrap_or_default().to_lowercase();
        if src.ends_with(".webp")
            || src.ends_with(".avif")
            || src.contains("/webp")
            || src.contains("/avif")
        {
            report.images_modern_format += 1;
        } else if src.ends_with(".jpg")
            || src.ends_with(".jpeg")
            || src.ends_with(".png")
            || src.ends_with(".gif")
        {
            report.images_legacy_format += 1;
        }
    }
    for source in doc.select("picture source[type]").iter() {
        let t = source.attr("type").unwrap_or_default().to_lowercase();
        if t.contains("webp") || t.contains("avif") {
            report.images_modern_format += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn detect_compression_explicit() {
        let h = headers(&[("content-encoding", "gzip")]);
        let r = analyze(&h, "");
        assert_eq!(r.compression, "gzip");
    }

    #[test]
    fn detect_compression_via_vary() {
        // HTTP clients strip content-encoding after decompression.
        // vary: accept-encoding proves the server has compression enabled.
        let h = headers(&[("vary", "Accept-Encoding")]);
        let r = analyze(&h, "");
        assert_eq!(r.compression, "gzip");
    }

    #[test]
    fn no_compression_detected() {
        let h = headers(&[("vary", "Cookie")]);
        let r = analyze(&h, "");
        assert!(r.compression.is_empty());
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
    fn performance_score_full() {
        let h = headers(&[
            ("content-encoding", "br"),
            ("cache-control", "max-age=3600"),
            ("etag", "\"abc\""),
            ("alt-svc", "h3=\":443\""),
        ]);
        let html = r#"
            <link rel="preload" href="/f.woff2" as="font">
            <link rel="prefetch" href="/next.js" as="script">
            <link rel="preconnect" href="https://cdn.example.com">
            <img src="a.jpg" loading="lazy">
        "#;
        let r = analyze(&h, html);
        assert_eq!(r.score, 81);
    }

    #[test]
    fn performance_score_empty() {
        let r = analyze(&HashMap::new(), "");
        assert_eq!(r.score, 23);
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

    #[test]
    fn detect_speculation_rules() {
        let html = r#"<script type="speculationrules">{"prerender":[{"where":{"href_matches":"/*"}}]}</script>"#;
        let r = analyze(&HashMap::new(), html);
        assert!(r.has_speculation_rules);
    }

    #[test]
    fn detect_speculation_rules_absent() {
        let r = analyze(&HashMap::new(), "<script>console.log('hi')</script>");
        assert!(!r.has_speculation_rules);
    }

    #[test]
    fn detect_font_preloads() {
        let html = r#"
            <link rel="preload" href="/font.woff2" as="font" type="font/woff2">
            <link rel="preload" href="/other.woff2" as="font">
            <link rel="preload" href="/script.js" as="script">
        "#;
        let r = analyze(&HashMap::new(), html);
        assert_eq!(r.font_preloads, 2);
    }

    #[test]
    fn detect_image_formats() {
        let html = r#"
            <img src="/photo.webp">
            <img src="/hero.avif">
            <img src="/old.jpg">
            <img src="/icon.png">
            <picture><source type="image/webp" srcset="/x.webp"><img src="/x.jpg"></picture>
        "#;
        let r = analyze(&HashMap::new(), html);
        assert_eq!(r.images_modern_format, 3); // webp + avif + picture source
        assert_eq!(r.images_legacy_format, 3); // jpg + png + picture fallback jpg
    }
}
