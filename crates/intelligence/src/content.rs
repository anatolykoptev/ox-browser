//! Content analysis: links, word count, iframes.

use std::collections::HashSet;

use dom_query::Document;
use serde::Serialize;
use url::Url;

#[derive(Debug, Clone, Serialize, Default)]
pub struct ContentReport {
    pub internal_links: u32,
    pub external_links: u32,
    pub external_domains: Vec<String>,
    pub word_count: u32,
    pub iframes: Vec<IframeInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IframeInfo {
    pub src: String,
    pub platform: String,
}

/// Classify an iframe src URL into a named platform.
fn classify_iframe(src: &str) -> &'static str {
    let s = src.to_lowercase();
    if s.contains("youtube.com") || s.contains("youtu.be") {
        "YouTube"
    } else if s.contains("vimeo.com") {
        "Vimeo"
    } else if s.contains("google.com/maps") || s.contains("maps.google") {
        "Google Maps"
    } else if s.contains("spotify.com") {
        "Spotify"
    } else if s.contains("soundcloud.com") {
        "SoundCloud"
    } else {
        "Other"
    }
}

/// Parse the host from a URL string (returns None for relative/fragment URLs).
fn extract_host(href: &str) -> Option<String> {
    Url::parse(href)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
}

/// Analyze HTML for links, word count, and iframes relative to `page_url`.
pub fn analyze(html: &str, page_url: &str) -> ContentReport {
    let doc = Document::from(html);

    let page_host = Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()));

    let mut internal_links: u32 = 0;
    let mut external_links: u32 = 0;
    let mut external_domains: HashSet<String> = HashSet::new();

    doc.select("a[href]").iter().for_each(|node| {
        let href = node.attr("href").unwrap_or_default();
        let href = href.as_ref();

        // Relative URLs are internal.
        if href.starts_with('/') || href.starts_with('#') || href.starts_with("./") {
            internal_links += 1;
            return;
        }

        match extract_host(href) {
            None => {
                // Unparseable — treat as internal.
                internal_links += 1;
            }
            Some(host) => {
                let is_internal = page_host
                    .as_deref()
                    .map(|ph| host == ph || host.ends_with(&format!(".{ph}")))
                    .unwrap_or(false);

                if is_internal {
                    internal_links += 1;
                } else {
                    external_links += 1;
                    external_domains.insert(host);
                }
            }
        }
    });

    // Word count from body text.
    let body_text = doc.select("body").text();
    let word_count = body_text.split_whitespace().count() as u32;

    // Iframes.
    let iframes: Vec<IframeInfo> = doc
        .select("iframe[src]")
        .iter()
        .map(|node| {
            let src = node.attr("src").unwrap_or_default().to_string();
            let platform = classify_iframe(&src).to_string();
            IframeInfo { src, platform }
        })
        .collect();

    let mut external_domains: Vec<String> = external_domains.into_iter().collect();
    external_domains.sort();

    ContentReport {
        internal_links,
        external_links,
        external_domains,
        word_count,
        iframes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_links() {
        let html = r##"<html><body>
            <a href="/about">Internal</a>
            <a href="#section">Fragment</a>
            <a href="https://example.com/page">Same host</a>
            <a href="https://other.com">External</a>
            <a href="https://cdn.other.com">External subdomain</a>
        </body></html>"##;

        let report = analyze(html, "https://example.com");
        // /about, #section, https://example.com/page are internal
        assert_eq!(report.internal_links, 3, "internal: {:?}", report);
        assert_eq!(report.external_links, 2, "external: {:?}", report);
        assert!(report.external_domains.contains(&"other.com".to_string()));
        assert!(
            report
                .external_domains
                .contains(&"cdn.other.com".to_string())
        );
    }

    #[test]
    fn word_count() {
        let html = r#"<html><body><p>Hello world this is a test</p></body></html>"#;
        let report = analyze(html, "https://example.com");
        assert_eq!(report.word_count, 6);
    }

    #[test]
    fn detect_iframes() {
        let html = r#"<html><body>
            <iframe src="https://www.youtube.com/embed/abc123"></iframe>
            <iframe src="https://player.vimeo.com/video/456"></iframe>
            <iframe src="https://www.google.com/maps/embed?q=city"></iframe>
            <iframe src="https://unknown.example.com/widget"></iframe>
        </body></html>"#;

        let report = analyze(html, "https://mysite.com");
        assert_eq!(report.iframes.len(), 4);

        let platforms: Vec<&str> = report.iframes.iter().map(|i| i.platform.as_str()).collect();
        assert!(platforms.contains(&"YouTube"), "{:?}", platforms);
        assert!(platforms.contains(&"Vimeo"), "{:?}", platforms);
        assert!(platforms.contains(&"Google Maps"), "{:?}", platforms);
        assert!(platforms.contains(&"Other"), "{:?}", platforms);
    }

    #[test]
    fn empty_page() {
        let report = analyze("<html><body></body></html>", "https://example.com");
        assert_eq!(report.internal_links, 0);
        assert_eq!(report.external_links, 0);
        assert_eq!(report.word_count, 0);
        assert!(report.iframes.is_empty());
    }
}
