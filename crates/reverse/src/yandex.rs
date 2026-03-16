// Yandex Images reverse image search engine (URL mode).

use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::Value;

use crate::{extract_domain, Result, ReverseEngine, ReverseMatch};
use ox_http::HttpClient;

const YANDEX_URL: &str = "https://yandex.ru/images/search";

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
            "{}?rpt=imageview&cbir_page=sites&url={}",
            YANDEX_URL,
            urlencoding::encode(image_url),
        );
        let resp = client.get_with_headers(&url, YANDEX_HEADERS).await?;
        if resp.status != 200 {
            tracing::warn!(status = resp.status, "yandex: unexpected status");
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

/// Parse Yandex HTML response into reverse matches (dual strategy).
fn parse_yandex_html(html: &str) -> Vec<ReverseMatch> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    let doc = dom_query::Document::from(html);

    // Strategy 1 (primary): data-state JSON from ImagesApp root div.
    for node in doc.select("div.Root[id^=\"ImagesApp-\"]").iter() {
        let raw = node.attr("data-state").unwrap_or_default();
        let raw = raw.as_ref();
        if raw.is_empty() {
            continue;
        }
        let decoded = if raw.contains("&quot;") {
            html_unescape(raw)
        } else {
            raw.to_owned()
        };
        let Ok(val) = serde_json::from_str::<Value>(&decoded) else {
            continue;
        };
        extract_from_data_state(&val, &mut results, &mut seen);
    }

    // Strategy 2 (fallback): data-bem attributes (classic format).
    if results.is_empty() {
        parse_data_bem_fallback(&doc, &mut results, &mut seen);
    }

    results
}

/// Strategy 1: extract sites from data-state JSON.
/// Path: initialState.cbirSites.sites[]
fn extract_from_data_state(
    val: &Value,
    results: &mut Vec<ReverseMatch>,
    seen: &mut HashSet<String>,
) {
    let sites = val
        .pointer("/initialState/cbirSites/sites")
        .and_then(|v| v.as_array());
    let Some(sites) = sites else { return };
    for site in sites {
        let page_url = site.get("url").and_then(|v| v.as_str()).unwrap_or_default();
        if page_url.is_empty() || !seen.insert(page_url.to_owned()) {
            continue;
        }
        let title = site
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let thumbnail = site
            .get("thumb")
            .and_then(|t| t.get("url"))
            .and_then(|v| v.as_str())
            .map(normalize_thumb_url);
        let domain = site
            .get("domain")
            .and_then(|v| v.as_str())
            .filter(|d| !d.is_empty())
            .map(String::from)
            .unwrap_or_else(|| extract_domain(page_url));
        let description = site
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from);
        let image_size = format_image_size(site.get("originalImage"));
        results.push(ReverseMatch {
            page_url: page_url.to_owned(),
            title,
            thumbnail,
            domain,
            engine: "yandex".to_owned(),
            description,
            image_size,
        });
    }
}

/// Format "WxH" from originalImage object with width/height fields.
fn format_image_size(img: Option<&Value>) -> Option<String> {
    let img = img?;
    let w = img.get("width").and_then(|v| v.as_u64())?;
    let h = img.get("height").and_then(|v| v.as_u64())?;
    Some(format!("{w}x{h}"))
}

/// Strategy 2 (fallback): parse data-bem attributes.
fn parse_data_bem_fallback(
    doc: &dom_query::Document,
    results: &mut Vec<ReverseMatch>,
    seen: &mut HashSet<String>,
) {
    for node in doc.select("[data-bem]").iter() {
        let raw = node.attr("data-bem").unwrap_or_default();
        let raw = raw.as_ref();
        if raw.is_empty() {
            continue;
        }
        let decoded = if raw.contains("&quot;") {
            html_unescape(raw)
        } else {
            raw.to_owned()
        };
        let Ok(val) = serde_json::from_str::<Value>(&decoded) else {
            continue;
        };
        if let Some(serp) = val.get("serp-item") {
            extract_from_dups(serp, results, seen);
            extract_from_preview(serp, results, seen);
        }
        for (_key, section) in val.as_object().into_iter().flatten() {
            extract_from_small_dups(section, results, seen);
        }
    }
}

/// Build a `ReverseMatch` for data-bem results (no description/image_size).
fn bem_match(page_url: &str, title: String, thumbnail: Option<String>) -> ReverseMatch {
    ReverseMatch {
        domain: extract_domain(page_url),
        page_url: page_url.to_owned(),
        title,
        thumbnail,
        engine: "yandex".to_owned(),
        description: None,
        image_size: None,
    }
}

/// Extract matches from `dups` array.
fn extract_from_dups(serp: &Value, results: &mut Vec<ReverseMatch>, seen: &mut HashSet<String>) {
    let Some(dups) = serp.get("dups").and_then(|v| v.as_array()) else { return };
    for dup in dups {
        let page_url = dup.get("url").and_then(|v| v.as_str()).unwrap_or_default();
        if page_url.is_empty() || !seen.insert(page_url.to_owned()) {
            continue;
        }
        let title = dup.get("title").and_then(|v| v.as_str()).unwrap_or_default().to_owned();
        let thumb = dup.get("thumb").and_then(|t| t.get("url")).and_then(|v| v.as_str()).map(normalize_thumb_url);
        results.push(bem_match(page_url, title, thumb));
    }
}

/// Extract matches from `preview` array.
fn extract_from_preview(serp: &Value, results: &mut Vec<ReverseMatch>, seen: &mut HashSet<String>) {
    let Some(previews) = serp.get("preview").and_then(|v| v.as_array()) else { return };
    for preview in previews {
        let snippet = preview.get("snippet");
        let page_url = snippet
            .and_then(|s| s.get("url"))
            .and_then(|v| v.as_str())
            .or_else(|| preview.get("url").and_then(|v| v.as_str()))
            .unwrap_or_default();
        if page_url.is_empty() || !seen.insert(page_url.to_owned()) {
            continue;
        }
        let title = snippet.and_then(|s| s.get("title")).and_then(|v| v.as_str()).unwrap_or_default().to_owned();
        let thumb = preview.get("thumb").and_then(|t| t.get("url")).and_then(|v| v.as_str()).map(normalize_thumb_url);
        results.push(bem_match(page_url, title, thumb));
    }
}

/// Extract matches from `small_dups` array.
fn extract_from_small_dups(val: &Value, results: &mut Vec<ReverseMatch>, seen: &mut HashSet<String>) {
    let Some(dups) = val.get("small_dups").and_then(|v| v.as_array()) else { return };
    for dup in dups {
        let page_url = dup.get("url").and_then(|v| v.as_str()).unwrap_or_default();
        if page_url.is_empty() || !seen.insert(page_url.to_owned()) {
            continue;
        }
        let title = dup.get("title").or_else(|| dup.get("text")).and_then(|v| v.as_str()).unwrap_or_default().to_owned();
        results.push(bem_match(page_url, title, None));
    }
}

/// Unescape basic HTML entities.
fn html_unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
}

/// Normalize protocol-relative thumbnail URLs.
fn normalize_thumb_url(url: &str) -> String {
    if url.starts_with("//") { format!("https:{url}") } else { url.to_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Strategy 1: data-state tests ---

    fn make_data_state_html(json: &str) -> String {
        format!(r#"<html><body><div class="Root" id="ImagesApp-1" data-state='{json}'></div></body></html>"#)
    }

    #[test]
    fn data_state_extracts_sites() {
        let json = r#"{"initialState":{"cbirSites":{"sites":[{"url":"https://example.com/page","title":"Example","thumb":{"url":"//t.yandex.com/1.jpg"},"domain":"example.com","description":"A page","originalImage":{"width":1920,"height":1080}}]}}}"#;
        let results = parse_yandex_html(&make_data_state_html(json));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].page_url, "https://example.com/page");
        assert_eq!(results[0].title, "Example");
        assert_eq!(results[0].domain, "example.com");
        assert_eq!(results[0].description.as_deref(), Some("A page"));
        assert_eq!(results[0].image_size.as_deref(), Some("1920x1080"));
        assert_eq!(results[0].thumbnail.as_deref(), Some("https://t.yandex.com/1.jpg"));
    }

    #[test]
    fn data_state_multiple_sites() {
        let json = r#"{"initialState":{"cbirSites":{"sites":[{"url":"https://a.com/1","title":"A","domain":"a.com"},{"url":"https://b.com/2","title":"B","domain":"b.com"}]}}}"#;
        let results = parse_yandex_html(&make_data_state_html(json));
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].domain, "a.com");
        assert_eq!(results[1].domain, "b.com");
    }

    #[test]
    fn data_state_deduplicates() {
        let json = r#"{"initialState":{"cbirSites":{"sites":[{"url":"https://x.com/p","title":"First","domain":"x.com"},{"url":"https://x.com/p","title":"Second","domain":"x.com"}]}}}"#;
        let results = parse_yandex_html(&make_data_state_html(json));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "First");
    }

    #[test]
    fn data_state_empty_sites() {
        let json = r#"{"initialState":{"cbirSites":{"sites":[]}}}"#;
        assert!(parse_yandex_html(&make_data_state_html(json)).is_empty());
    }

    #[test]
    fn data_state_domain_fallback() {
        let json = r#"{"initialState":{"cbirSites":{"sites":[{"url":"https://www.foo.com/bar","title":"T","domain":""}]}}}"#;
        let results = parse_yandex_html(&make_data_state_html(json));
        assert_eq!(results[0].domain, "foo.com");
    }

    #[test]
    fn data_state_no_image_size() {
        let json = r#"{"initialState":{"cbirSites":{"sites":[{"url":"https://a.com/1","title":"A","domain":"a.com"}]}}}"#;
        let results = parse_yandex_html(&make_data_state_html(json));
        assert!(results[0].image_size.is_none());
        assert!(results[0].description.is_none());
    }

    // --- Strategy 2: data-bem fallback tests ---

    fn make_bem_html(data_bem: &str) -> String {
        format!(r#"<html><body><div class="serp-item" data-bem='{data_bem}'></div></body></html>"#)
    }

    #[test]
    fn bem_dups_extracts_matches() {
        let bem = r#"{"serp-item":{"dups":[{"url":"https://example.com/page1","title":"Page One","thumb":{"url":"//thumb.yandex.com/1.jpg"}}]}}"#;
        let results = parse_yandex_html(&make_bem_html(bem));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].page_url, "https://example.com/page1");
        assert_eq!(results[0].title, "Page One");
        assert_eq!(results[0].domain, "example.com");
        assert_eq!(results[0].thumbnail.as_deref(), Some("https://thumb.yandex.com/1.jpg"));
        assert!(results[0].description.is_none());
        assert!(results[0].image_size.is_none());
    }

    #[test]
    fn bem_preview_extracts_matches() {
        let bem = r#"{"serp-item":{"preview":[{"snippet":{"title":"Photo","url":"https://ex.com/photo"},"thumb":{"url":"https://t.yandex.com/1.jpg"}}]}}"#;
        let results = parse_yandex_html(&make_bem_html(bem));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].page_url, "https://ex.com/photo");
        assert_eq!(results[0].title, "Photo");
    }

    // --- Edge cases ---

    #[test]
    fn empty_html_returns_empty() {
        assert!(parse_yandex_html("").is_empty());
        assert!(parse_yandex_html("<html></html>").is_empty());
    }

    #[test]
    fn malformed_data_returns_empty() {
        let html = r#"<div class="Root" id="ImagesApp-1" data-state="not json"></div>"#;
        assert!(parse_yandex_html(html).is_empty());
        let html = r#"<div data-bem="not json"></div>"#;
        assert!(parse_yandex_html(html).is_empty());
    }

    #[test]
    fn normalize_thumb_protocol_relative() {
        assert_eq!(normalize_thumb_url("//t.yandex.com/1.jpg"), "https://t.yandex.com/1.jpg");
        assert_eq!(normalize_thumb_url("https://t.com/2.jpg"), "https://t.com/2.jpg");
    }
}
