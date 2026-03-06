//! PWA detection: manifest, service worker, theme color, apple touch icon.

use dom_query::Document;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct PwaReport {
    pub manifest_url: String,
    pub has_service_worker: bool,
    pub theme_color: String,
    pub apple_touch_icon: String,
    pub is_pwa: bool,
}

/// Analyze HTML and return a `PwaReport`.
pub fn analyze(html: &str) -> PwaReport {
    let doc = Document::from(html);

    // Manifest from <link rel="manifest">
    let manifest_url = doc
        .select("link[rel=\"manifest\"]")
        .iter()
        .next()
        .and_then(|n| n.attr("href"))
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Service worker from inline scripts containing registration calls
    let has_service_worker = doc
        .select("script:not([src])")
        .iter()
        .any(|n| {
            let text = n.text().to_string();
            text.contains("serviceWorker.register") || text.contains("navigator.serviceWorker")
        });

    // Theme color from <meta name="theme-color">
    let theme_color = doc
        .select("meta[name=\"theme-color\"]")
        .iter()
        .next()
        .and_then(|n| n.attr("content"))
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Apple touch icon from <link rel="apple-touch-icon">
    let apple_touch_icon = doc
        .select("link[rel=\"apple-touch-icon\"]")
        .iter()
        .next()
        .and_then(|n| n.attr("href"))
        .map(|s| s.to_string())
        .unwrap_or_default();

    let is_pwa = !manifest_url.is_empty() && has_service_worker;

    PwaReport {
        manifest_url,
        has_service_worker,
        theme_color,
        apple_touch_icon,
        is_pwa,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_pwa() {
        let html = r##"<html><head>
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#317EFB">
            <link rel="apple-touch-icon" href="/icons/apple-touch.png">
            <script>
                if ('serviceWorker' in navigator) {
                    navigator.serviceWorker.register('/sw.js');
                }
            </script>
        </head></html>"##;
        let r = analyze(html);
        assert_eq!(r.manifest_url, "/manifest.json");
        assert!(r.has_service_worker);
        assert_eq!(r.theme_color, "#317EFB");
        assert_eq!(r.apple_touch_icon, "/icons/apple-touch.png");
        assert!(r.is_pwa);
    }

    #[test]
    fn not_pwa_without_sw() {
        let html = r##"<html><head>
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#000">
        </head></html>"##;
        let r = analyze(html);
        assert_eq!(r.manifest_url, "/manifest.json");
        assert!(!r.has_service_worker);
        assert!(!r.is_pwa, "should not be PWA without service worker");
    }

    #[test]
    fn not_pwa_without_manifest() {
        let html = r#"<html><head>
            <script>navigator.serviceWorker.register('/sw.js');</script>
        </head></html>"#;
        let r = analyze(html);
        assert!(r.has_service_worker);
        assert!(r.manifest_url.is_empty());
        assert!(!r.is_pwa, "should not be PWA without manifest");
    }

    #[test]
    fn empty_html_returns_defaults() {
        let r = analyze("");
        assert!(r.manifest_url.is_empty());
        assert!(!r.has_service_worker);
        assert!(!r.is_pwa);
    }
}
