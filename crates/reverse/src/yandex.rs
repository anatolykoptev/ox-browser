// Yandex Images reverse image search engine (URL mode).

use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::Value;

use crate::{Result, ReverseEngine, ReverseMatch};
use ox_http::HttpClient;

const YANDEX_URL: &str = "https://yandex.com/images/search/";

/// Extra headers required by Yandex to avoid blocks.
const YANDEX_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\""),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", "\"Windows\""),
    ("sec-fetch-site", "same-origin"),
    ("sec-fetch-mode", "navigate"),
    ("device-memory", "8"),
    ("ect", "4g"),
];

/// Yandex Images reverse image search via URL.
pub struct YandexImages;

#[async_trait]
impl ReverseEngine for YandexImages {
    async fn search(
        &self,
        client: &HttpClient,
        image_url: &str,
        max: usize,
    ) -> Result<Vec<ReverseMatch>> {
        let url = format!(
            "{}?rpt=imageview&url={}",
            YANDEX_URL,
            urlencoding::encode(image_url),
        );
        let resp = client.get_with_headers(&url, YANDEX_HEADERS).await?;
        if resp.status != 200 {
            tracing::warn!(
                status = resp.status,
                "yandex: unexpected status"
            );
            return Ok(Vec::new());
        }
        let mut results = parse_yandex_html(&resp.body);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "yandex"
    }
}

/// Extracts domain from a URL, stripping `www.` prefix.
fn extract_domain(page_url: &str) -> String {
    url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .map(|h| h.strip_prefix("www.").unwrap_or(&h).to_owned())
        .unwrap_or_default()
}

/// Parse Yandex HTML response into reverse matches.
fn parse_yandex_html(html: &str) -> Vec<ReverseMatch> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    // Strategy 1: data-bem attributes with serp-item (classic format).
    let doc = dom_query::Document::from(html);
    for node in doc.select("[data-bem]").iter() {
        let raw = node.attr("data-bem").unwrap_or_default();
        let raw = raw.as_ref();
        if raw.is_empty() {
            continue;
        }
        // data-bem can be HTML-entity-encoded or raw JSON.
        let decoded = if raw.contains("&quot;") {
            html_unescape(raw)
        } else {
            raw.to_owned()
        };
        let Ok(val) = serde_json::from_str::<Value>(&decoded) else {
            continue;
        };
        // Check serp-item key.
        if let Some(serp) = val.get("serp-item") {
            extract_from_dups(serp, &mut results, &mut seen);
            extract_from_preview(serp, &mut results, &mut seen);
        }
        // Check cbir-similar or other keys containing small_dups.
        for (_key, section) in val.as_object().into_iter().flatten() {
            extract_from_small_dups(section, &mut results, &mut seen);
        }
    }

    // Strategy 2: find small_dups in HTML-entity-encoded JSON anywhere in the page.
    if results.is_empty() {
        extract_small_dups_from_html(html, &mut results, &mut seen);
    }

    results
}

/// Unescape basic HTML entities.
fn html_unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
}

/// Extract matches from `dups` array structure.
fn extract_from_dups(
    serp: &Value,
    results: &mut Vec<ReverseMatch>,
    seen: &mut HashSet<String>,
) {
    let Some(dups) = serp.get("dups").and_then(|v| v.as_array()) else {
        return;
    };
    for dup in dups {
        let page_url = dup
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if page_url.is_empty() || !seen.insert(page_url.to_owned()) {
            continue;
        }
        let title = dup
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let thumbnail = dup
            .get("thumb")
            .and_then(|t| t.get("url"))
            .and_then(|v| v.as_str())
            .map(normalize_thumb_url);
        let domain = extract_domain(page_url);
        results.push(ReverseMatch {
            page_url: page_url.to_owned(),
            title,
            thumbnail,
            domain,
            engine: "yandex".to_owned(),
        });
    }
}

/// Extract matches from `preview` array structure.
fn extract_from_preview(
    serp: &Value,
    results: &mut Vec<ReverseMatch>,
    seen: &mut HashSet<String>,
) {
    let Some(previews) = serp.get("preview").and_then(|v| v.as_array())
    else {
        return;
    };
    for preview in previews {
        // Try snippet.url first, fall back to top-level url.
        let snippet = preview.get("snippet");
        let page_url = snippet
            .and_then(|s| s.get("url"))
            .and_then(|v| v.as_str())
            .or_else(|| preview.get("url").and_then(|v| v.as_str()))
            .unwrap_or_default();
        if page_url.is_empty() || !seen.insert(page_url.to_owned()) {
            continue;
        }
        let title = snippet
            .and_then(|s| s.get("title"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let thumbnail = preview
            .get("thumb")
            .and_then(|t| t.get("url"))
            .and_then(|v| v.as_str())
            .map(normalize_thumb_url);
        let domain = extract_domain(page_url);
        results.push(ReverseMatch {
            page_url: page_url.to_owned(),
            title,
            thumbnail,
            domain,
            engine: "yandex".to_owned(),
        });
    }
}

/// Extract matches from `small_dups` array in any JSON section.
fn extract_from_small_dups(
    val: &Value,
    results: &mut Vec<ReverseMatch>,
    seen: &mut HashSet<String>,
) {
    let Some(dups) = val.get("small_dups").and_then(|v| v.as_array()) else {
        return;
    };
    for dup in dups {
        let page_url = dup
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if page_url.is_empty() || !seen.insert(page_url.to_owned()) {
            continue;
        }
        let title = dup
            .get("title")
            .or_else(|| dup.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let domain = extract_domain(page_url);
        results.push(ReverseMatch {
            page_url: page_url.to_owned(),
            title,
            thumbnail: None,
            domain,
            engine: "yandex".to_owned(),
        });
    }
}

/// Fallback: find small_dups in HTML-entity-encoded JSON blocks.
fn extract_small_dups_from_html(
    html: &str,
    results: &mut Vec<ReverseMatch>,
    seen: &mut HashSet<String>,
) {
    use regex::Regex;
    use std::sync::LazyLock;

    static SMALL_DUPS_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"&quot;small_dups&quot;:\[.*?\]"#).expect("small_dups regex")
    });

    for m in SMALL_DUPS_RE.find_iter(html) {
        let decoded = html_unescape(&format!("{{{}}}", m.as_str()));
        if let Ok(val) = serde_json::from_str::<Value>(&decoded) {
            extract_from_small_dups(&val, results, seen);
        }
    }
}

/// Normalize protocol-relative thumbnail URLs.
fn normalize_thumb_url(url: &str) -> String {
    if url.starts_with("//") {
        format!("https:{url}")
    } else {
        url.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_serp_html(data_bem: &str) -> String {
        format!(
            r#"<html><body><div class="serp-item" data-bem='{data_bem}'></div></body></html>"#,
        )
    }

    #[test]
    fn parse_dups_extracts_matches() {
        let bem = r#"{"serp-item":{"id":1,"dups":[{"url":"https://example.com/page1","title":"Page One","thumb":{"url":"//thumb.yandex.com/1.jpg"}},{"url":"https://other.org/article","title":"Another","thumb":{"url":"//thumb.yandex.com/2.jpg"}}]}}"#;
        let html = make_serp_html(bem);
        let results = parse_yandex_html(&html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].page_url, "https://example.com/page1");
        assert_eq!(results[0].title, "Page One");
        assert_eq!(results[0].domain, "example.com");
        assert_eq!(results[0].engine, "yandex");
        assert_eq!(
            results[0].thumbnail.as_deref(),
            Some("https://thumb.yandex.com/1.jpg"),
        );
        assert_eq!(results[1].page_url, "https://other.org/article");
        assert_eq!(results[1].title, "Another");
    }

    #[test]
    fn parse_preview_extracts_matches() {
        let bem = r#"{"serp-item":{"preview":[{"url":"https://img.com/1.jpg","snippet":{"title":"Photo Title","url":"https://example.com/photo"},"thumb":{"url":"https://t.yandex.com/1.jpg"}}]}}"#;
        let html = make_serp_html(bem);
        let results = parse_yandex_html(&html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].page_url, "https://example.com/photo");
        assert_eq!(results[0].title, "Photo Title");
        assert_eq!(results[0].domain, "example.com");
    }

    #[test]
    fn empty_html_returns_empty() {
        assert!(parse_yandex_html("").is_empty());
        assert!(parse_yandex_html("<html></html>").is_empty());
    }

    #[test]
    fn malformed_data_bem_returns_empty() {
        let html =
            r#"<div data-bem="not valid json"></div>"#;
        assert!(parse_yandex_html(html).is_empty());
    }

    #[test]
    fn non_serp_item_data_bem_skipped() {
        let html = r#"<div data-bem='{"other-widget":{"x":1}}'></div>"#;
        assert!(parse_yandex_html(html).is_empty());
    }

    #[test]
    fn multiple_serp_items_all_extracted() {
        let bem1 = r#"{"serp-item":{"dups":[{"url":"https://a.com/1","title":"A"}]}}"#;
        let bem2 = r#"{"serp-item":{"dups":[{"url":"https://b.com/2","title":"B"}]}}"#;
        let html = format!(
            r#"<html><body>
            <div class="serp-item" data-bem='{bem1}'></div>
            <div class="serp-item" data-bem='{bem2}'></div>
            </body></html>"#,
        );
        let results = parse_yandex_html(&html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].page_url, "https://a.com/1");
        assert_eq!(results[1].page_url, "https://b.com/2");
    }

    #[test]
    fn deduplication_across_items() {
        let bem1 = r#"{"serp-item":{"dups":[{"url":"https://dup.com/page","title":"First"}]}}"#;
        let bem2 = r#"{"serp-item":{"dups":[{"url":"https://dup.com/page","title":"Second"}]}}"#;
        let html = format!(
            r#"<html><body>
            <div data-bem='{bem1}'></div>
            <div data-bem='{bem2}'></div>
            </body></html>"#,
        );
        let results = parse_yandex_html(&html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "First");
    }

    #[test]
    fn dedup_within_single_item() {
        let bem = r#"{"serp-item":{"dups":[{"url":"https://same.com/p","title":"A"},{"url":"https://same.com/p","title":"B"}]}}"#;
        let html = make_serp_html(bem);
        let results = parse_yandex_html(&html);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn extract_domain_strips_www() {
        assert_eq!(
            extract_domain("https://www.example.com/p"),
            "example.com",
        );
        assert_eq!(
            extract_domain("https://blog.site.org/x"),
            "blog.site.org",
        );
    }

    #[test]
    fn extract_domain_invalid_url() {
        assert_eq!(extract_domain("not-a-url"), "");
    }

    #[test]
    fn normalize_thumb_protocol_relative() {
        assert_eq!(
            normalize_thumb_url("//thumb.yandex.com/1.jpg"),
            "https://thumb.yandex.com/1.jpg",
        );
        assert_eq!(
            normalize_thumb_url("https://t.com/2.jpg"),
            "https://t.com/2.jpg",
        );
    }

    #[test]
    fn empty_url_in_dup_skipped() {
        let bem = r#"{"serp-item":{"dups":[{"url":"","title":"No URL"},{"url":"https://valid.com/x","title":"Valid"}]}}"#;
        let html = make_serp_html(bem);
        let results = parse_yandex_html(&html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].page_url, "https://valid.com/x");
    }
}
