// Google Lens reverse image search engine (URL mode).

use async_trait::async_trait;
use regex::Regex;
use std::sync::LazyLock;

use crate::{Result, ReverseEngine, ReverseMatch};
use ox_http::HttpClient;
use wreq::header::HeaderMap;

const LENS_URL: &str = "https://lens.google.com/uploadbyurl";

/// Google Lens reverse image search via URL upload.
pub struct GoogleLens;

#[async_trait]
impl ReverseEngine for GoogleLens {
    async fn search(
        &self,
        client: &HttpClient,
        image_url: &str,
        max: usize,
    ) -> Result<Vec<ReverseMatch>> {
        let url = format!(
            "{}?url={}&hl=en&gl=us",
            LENS_URL,
            urlencoding::encode(image_url),
        );
        let resp = client.get(&url).await?;
        // Google Lens returns 303 → google.com/search?...&udm=26
        // Follow the redirect to get actual results.
        let html = if resp.status == 303 || resp.status == 302 {
            if let Some(location) = extract_redirect_url(&resp.body, &resp.headers) {
                tracing::debug!(redirect = %location, "google_lens: following redirect");
                match client.get(&location).await {
                    Ok(r) => r.body,
                    Err(e) => {
                        tracing::warn!(error = %e, "google_lens: redirect fetch failed");
                        return Ok(Vec::new());
                    }
                }
            } else {
                tracing::warn!("google_lens: redirect with no location");
                return Ok(Vec::new());
            }
        } else if resp.status == 200 {
            resp.body
        } else {
            tracing::warn!(status = resp.status, "google_lens: unexpected status");
            return Ok(Vec::new());
        };
        let mut results = parse_lens_html(&html);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "google_lens"
    }
}

/// Extract redirect URL from response headers (Location header).
fn extract_redirect_url(
    _body: &str,
    headers: &wreq::header::HeaderMap,
) -> Option<String> {
    headers
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
}

/// Matches `AF_initDataCallback({...data:[...]...})` blocks.
static AF_DATA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"AF_initDataCallback\(\{[^}]*data:(\[[\s\S]*?\])\s*,\s*sideChannel",
    )
    .expect("af_data regex")
});

/// Matches HTTP(S) URLs inside quoted strings.
static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(https?://[^"]{10,})""#).expect("url regex")
});

/// Extracts domain from a URL, stripping `www.` prefix.
fn extract_domain(page_url: &str) -> String {
    url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .map(|h| h.strip_prefix("www.").unwrap_or(&h).to_owned())
        .unwrap_or_default()
}

/// Checks if a URL belongs to Google itself (not a result).
fn is_google_url(u: &str) -> bool {
    let dominated = |h: &str| {
        h == "google.com"
            || h.ends_with(".google.com")
            || h == "gstatic.com"
            || h.ends_with(".gstatic.com")
            || h == "googleapis.com"
            || h.ends_with(".googleapis.com")
            || h == "googleusercontent.com"
            || h.ends_with(".googleusercontent.com")
    };
    url::Url::parse(u)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|h| dominated(h)))
        .unwrap_or(false)
}

/// Parse Google Lens HTML response into reverse matches.
fn parse_lens_html(html: &str) -> Vec<ReverseMatch> {
    // Strategy 1: extract AF_initDataCallback data blocks.
    let matches = parse_af_callbacks(html);
    if !matches.is_empty() {
        return matches;
    }
    // Strategy 2: fallback to DOM anchor tags.
    parse_dom_links(html)
}

/// Primary parser: extract URLs from AF_initDataCallback data.
fn parse_af_callbacks(html: &str) -> Vec<ReverseMatch> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for cap in AF_DATA_RE.captures_iter(html) {
        let data_str = &cap[1];
        // Collect all non-Google URLs from this data block.
        let urls: Vec<String> = URL_RE
            .captures_iter(data_str)
            .map(|c| c[1].to_owned())
            .filter(|u| !is_google_url(u))
            .collect();

        // Collect candidate title strings: short quoted
        // strings near URLs.
        let titles: Vec<String> = extract_title_candidates(data_str);

        for (i, page_url) in urls.iter().enumerate() {
            if !seen.insert(page_url.clone()) {
                continue;
            }
            let title = titles
                .get(i)
                .cloned()
                .unwrap_or_default();
            let domain = extract_domain(page_url);
            results.push(ReverseMatch {
                page_url: page_url.clone(),
                title,
                thumbnail: None,
                domain,
                engine: "google_lens".to_owned(),
            });
        }
    }
    results
}

/// Extract short quoted strings as title candidates.
static TITLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""([^"]{2,200})""#).expect("title regex")
});

fn extract_title_candidates(data: &str) -> Vec<String> {
    TITLE_RE
        .captures_iter(data)
        .map(|c| c[1].to_owned())
        .filter(|s| {
            !s.starts_with("http")
                && !s.contains('\\')
                && !s.contains('{')
                && s.chars().any(|c| c.is_alphabetic())
        })
        .collect()
}

/// Fallback: parse `<a>` tags from the DOM.
fn parse_dom_links(html: &str) -> Vec<ReverseMatch> {
    let doc = dom_query::Document::from(html);
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for node in doc.select("a[href]").iter() {
        let href = node.attr("href").unwrap_or_default();
        let href = href.as_ref();
        if !href.starts_with("http") || is_google_url(href) {
            continue;
        }
        if !seen.insert(href.to_owned()) {
            continue;
        }
        let title = node.text().to_string();
        let title = title.trim().to_owned();
        let domain = extract_domain(href);
        results.push(ReverseMatch {
            page_url: href.to_owned(),
            title,
            thumbnail: None,
            domain,
            engine: "google_lens".to_owned(),
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_af_html(data: &str) -> String {
        format!(
            r#"<html><script>AF_initDataCallback({{key: 'ds:1', data:{data}, sideChannel: {{}}}});</script></html>"#,
        )
    }

    #[test]
    fn parse_af_callback_extracts_matches() {
        let data = r#"[null,null,["https://example.com/page1","Page One Title"],["https://other.org/article","Another Article"]]"#;
        let html = make_af_html(data);
        let results = parse_lens_html(&html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].page_url, "https://example.com/page1");
        assert_eq!(results[0].domain, "example.com");
        assert_eq!(results[0].engine, "google_lens");
        assert_eq!(results[1].page_url, "https://other.org/article");
        assert_eq!(results[1].domain, "other.org");
    }

    #[test]
    fn parse_af_callback_skips_google_urls() {
        let data = r#"[["https://www.google.com/search?q=test"],["https://lh3.googleusercontent.com/thumb.jpg"],["https://real-site.com/photo"]]"#;
        let html = make_af_html(data);
        let results = parse_lens_html(&html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].page_url, "https://real-site.com/photo");
    }

    #[test]
    fn parse_af_callback_deduplicates() {
        let data = r#"[["https://example.com/dup"],["https://example.com/dup"],["https://other.com/unique"]]"#;
        let html = make_af_html(data);
        let results = parse_lens_html(&html);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn parse_empty_html_returns_empty() {
        assert!(parse_lens_html("").is_empty());
        assert!(parse_lens_html("<html></html>").is_empty());
    }

    #[test]
    fn parse_malformed_callback_returns_empty() {
        let html = r#"<script>AF_initDataCallback({broken)</script>"#;
        assert!(parse_lens_html(html).is_empty());
    }

    #[test]
    fn extract_domain_strips_www() {
        assert_eq!(extract_domain("https://www.example.com/p"), "example.com");
        assert_eq!(extract_domain("https://blog.site.org/x"), "blog.site.org");
    }

    #[test]
    fn extract_domain_invalid_url() {
        assert_eq!(extract_domain("not-a-url"), "");
    }

    #[test]
    fn fallback_dom_links() {
        let html = r#"<html><body>
            <a href="https://result.com/page">Result Page</a>
            <a href="https://www.google.com/search">Google</a>
            <a href="/relative">Skip</a>
            <a href="https://another.net/img">Photo</a>
        </body></html>"#;
        let results = parse_dom_links(html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].page_url, "https://result.com/page");
        assert_eq!(results[0].title, "Result Page");
        assert_eq!(results[1].page_url, "https://another.net/img");
    }

    #[test]
    fn is_google_url_detects_google_domains() {
        assert!(is_google_url("https://www.google.com/search"));
        assert!(is_google_url("https://lens.google.com/x"));
        assert!(is_google_url("https://lh3.googleusercontent.com/t"));
        assert!(is_google_url("https://encrypted-tbn0.gstatic.com/x"));
        assert!(!is_google_url("https://example.com/page"));
        assert!(!is_google_url("https://notgoogle.com/page"));
    }
}
