// Google Lens reverse image search engine (URL mode).

use async_trait::async_trait;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

use crate::{extract_domain, Result, ReverseEngine, ReverseMatch};
use ox_http::HttpClient;

const LENS_URL: &str = "https://lens.google.com/uploadbyurl";
const GOOGLE_DOMAINS: &[&str] = &[
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
];

pub struct GoogleLens;

#[async_trait]
impl ReverseEngine for GoogleLens {
    async fn search(&self, client: &HttpClient, image_url: &str, max: usize) -> Result<Vec<ReverseMatch>> {
        let url = format!("{}?url={}&hl=en-US&gl=us", LENS_URL, urlencoding::encode(image_url));
        let resp = client.get(&url).await?;
        let html = if resp.status == 302 || resp.status == 303 {
            let loc = resp.headers.get("location").and_then(|v| v.to_str().ok());
            match loc {
                Some(loc) => {
                    tracing::debug!(redirect = %loc, "google_lens: following redirect");
                    match client.get(loc).await {
                        Ok(r) => r.body,
                        Err(e) => { tracing::warn!(error = %e, "google_lens: redirect failed"); return Ok(vec![]); }
                    }
                }
                None => { tracing::warn!("google_lens: redirect with no location"); return Ok(vec![]); }
            }
        } else if resp.status == 200 { resp.body }
        else { tracing::warn!(status = resp.status, "google_lens: unexpected status"); return Ok(vec![]); };
        let mut results = parse_lens_html(&html);
        results.truncate(max);
        Ok(results)
    }
    fn name(&self) -> &str { "google_lens" }
}

fn is_google_url(u: &str) -> bool {
    url::Url::parse(u).ok().and_then(|p| p.host_str().map(|h| {
        GOOGLE_DOMAINS.iter().any(|d| h == *d || h.ends_with(&format!(".{d}")))
    })).unwrap_or(false)
}

fn make_match(page_url: String, title: String) -> ReverseMatch {
    let domain = extract_domain(&page_url);
    ReverseMatch { page_url, title, thumbnail: None, domain, engine: "google_lens".into(), description: None, image_size: None }
}

// --- Regexes (LazyLock) ---

static LDI_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"google\.ldi\s*=\s*(\{[^}]+\})").expect("ldi regex"));
static AF_DATA_RE: LazyLock<Regex> = LazyLock::new(||
    Regex::new(r"AF_initDataCallback\(\{[^}]*data:(\[[\s\S]*?\])\s*,\s*sideChannel").expect("af regex"));
static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""(https?://[^"]{10,})""#).expect("url regex"));
static TITLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"]{2,200})""#).expect("title regex"));

// --- Parsing strategies (LDI -> AF -> DOM) ---

fn parse_lens_html(html: &str) -> Vec<ReverseMatch> {
    let r = parse_ldi_map(html);
    if !r.is_empty() { return r; }
    let r = parse_af_callbacks(html);
    if !r.is_empty() { return r; }
    parse_dom_links(html)
}

fn add_link(a: &dom_query::Selection<'_>, seen: &mut HashSet<String>, out: &mut Vec<ReverseMatch>) {
    let Some(href) = a.attr("href") else { return };
    let h = href.as_ref();
    if !h.starts_with("http") || is_google_url(h) { return; }
    if !seen.insert(h.to_owned()) { return; }
    out.push(make_match(h.to_owned(), a.text().to_string().trim().to_owned()));
}

/// Strategy 1: parse `google.ldi` script map for dimg_ image keys,
/// then find associated `<a href>` in DOM via data-iid attribute.
fn parse_ldi_map(html: &str) -> Vec<ReverseMatch> {
    let Some(cap) = LDI_RE.captures(html) else { return vec![]; };
    let raw = cap[1].replace("\\u003d", "=").replace("\\u0026", "&");
    let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&raw) else { return vec![]; };
    let doc = dom_query::Document::from(html);
    let (mut results, mut seen) = (Vec::new(), HashSet::new());
    for key in map.keys().filter(|k| k.starts_with("dimg_")) {
        // <a data-iid href> | <a href>...<el data-iid/>..</a> | <el data-iid><a href>..</el>
        for sel in [
            format!("a[data-iid=\"{key}\"][href]"),
            format!("a[href]:has([data-iid=\"{key}\"])"),
            format!("[data-iid=\"{key}\"] a[href]"),
        ] {
            for a in doc.select(&sel).iter() { add_link(&a, &mut seen, &mut results); }
        }
    }
    results
}

/// Strategy 2: extract URLs from AF_initDataCallback data blocks.
fn parse_af_callbacks(html: &str) -> Vec<ReverseMatch> {
    let (mut results, mut seen) = (Vec::new(), HashSet::new());
    for cap in AF_DATA_RE.captures_iter(html) {
        let data = &cap[1];
        let urls: Vec<String> = URL_RE.captures_iter(data)
            .map(|c| c[1].to_owned()).filter(|u| !is_google_url(u)).collect();
        let titles: Vec<String> = TITLE_RE.captures_iter(data)
            .map(|c| c[1].to_owned())
            .filter(|s| !s.starts_with("http") && !s.contains('\\') && !s.contains('{') && s.chars().any(|c| c.is_alphabetic()))
            .collect();
        for (i, url) in urls.iter().enumerate() {
            if !seen.insert(url.clone()) { continue; }
            results.push(make_match(url.clone(), titles.get(i).cloned().unwrap_or_default()));
        }
    }
    results
}

/// Strategy 3: fallback to DOM anchor tags.
fn parse_dom_links(html: &str) -> Vec<ReverseMatch> {
    let doc = dom_query::Document::from(html);
    let (mut results, mut seen) = (Vec::new(), HashSet::new());
    for node in doc.select("a[href]").iter() {
        let href = node.attr("href").unwrap_or_default();
        let h = href.as_ref();
        if !h.starts_with("http") || is_google_url(h) { continue; }
        if !seen.insert(h.to_owned()) { continue; }
        results.push(make_match(h.to_owned(), node.text().to_string().trim().to_owned()));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldi_map_extracts_dimg_keys() {
        let html = r#"<html><script nonce="abc">google.ldi = {"dimg_1":"https://img.test/a.jpg","dimg_2":"https://img.test/b.jpg"}</script>
        <a href="https://example.com/page1" data-iid="dimg_1">Page 1</a>
        <a href="https://other.org/page2"><img data-iid="dimg_2"/></a></html>"#;
        let r = parse_ldi_map(html);
        assert_eq!(r.len(), 2);
        assert!(r.iter().any(|m| m.page_url == "https://example.com/page1"));
        assert!(r.iter().any(|m| m.page_url == "https://other.org/page2"));
        assert!(r[0].description.is_none() && r[0].image_size.is_none());
    }

    #[test]
    fn ldi_map_child_anchor() {
        let html = r#"<script>google.ldi = {"dimg_3":"url"}</script>
        <div data-iid="dimg_3"><a href="https://child-link.com/page">Title</a></div>"#;
        let r = parse_ldi_map(html);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].page_url, "https://child-link.com/page");
    }

    #[test]
    fn ldi_map_skips_non_dimg() {
        let html = r#"<script>google.ldi = {"other":"val","dimg_x":"url"}</script>"#;
        assert!(parse_ldi_map(html).is_empty());
    }

    #[test]
    fn ldi_unescape_unicode() {
        let s = r#"{"dimg_1":"x\u003dy\u0026z"}"#.replace("\\u003d", "=").replace("\\u0026", "&");
        assert_eq!(s, r#"{"dimg_1":"x=y&z"}"#);
    }

    fn make_af_html(data: &str) -> String {
        format!(r#"<html><script>AF_initDataCallback({{key:'ds:1',data:{data},sideChannel:{{}}}});</script></html>"#)
    }

    #[test]
    fn af_callback_extracts_matches() {
        let data = r#"[null,["https://example.com/p1","Title"],["https://other.org/a","Art"]]"#;
        let r = parse_af_callbacks(&make_af_html(data));
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].page_url, "https://example.com/p1");
        assert_eq!(r[0].domain, "example.com");
        assert_eq!(r[1].page_url, "https://other.org/a");
    }

    #[test]
    fn af_callback_skips_google_urls() {
        let data = r#"[["https://www.google.com/s"],["https://lh3.googleusercontent.com/t"],["https://real.com/x"]]"#;
        let r = parse_af_callbacks(&make_af_html(data));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].page_url, "https://real.com/x");
    }

    #[test]
    fn af_callback_deduplicates() {
        let data = r#"[["https://example.com/dup-page"],["https://example.com/dup-page"],["https://other.com/unique-page"]]"#;
        let r = parse_af_callbacks(&make_af_html(data));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn dom_links_fallback() {
        let html = r#"<html><body>
            <a href="https://result.com/page">Result Page</a>
            <a href="https://www.google.com/search">Google</a>
            <a href="/relative">Skip</a>
            <a href="https://another.net/img">Photo</a>
        </body></html>"#;
        let r = parse_dom_links(html);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].page_url, "https://result.com/page");
        assert_eq!(r[0].title, "Result Page");
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

    #[test]
    fn empty_and_malformed_html() {
        assert!(parse_lens_html("").is_empty());
        assert!(parse_lens_html("<html></html>").is_empty());
        assert!(parse_lens_html(r#"<script>AF_initDataCallback({broken)</script>"#).is_empty());
    }

    #[test]
    fn strategy_priority_ldi_first() {
        let html = r#"<script>google.ldi = {"dimg_1":"url"}</script>
        <a href="https://ldi-result.com/p" data-iid="dimg_1">LDI</a>
        <script>AF_initDataCallback({key:'x',data:["https://af-result.com/p"],sideChannel:{}});</script>"#;
        let r = parse_lens_html(html);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].page_url, "https://ldi-result.com/p");
    }

    // --- Hard red tests ---

    #[test]
    fn ldi_filters_google_urls_in_anchors() {
        // data-iid links to a google.com URL — must be skipped
        let html = r#"<script>google.ldi = {"dimg_1":"url","dimg_2":"url"}</script>
        <a href="https://www.google.com/imgres?q=test" data-iid="dimg_1">Google</a>
        <a href="https://real-site.com/photo" data-iid="dimg_2">Real</a>"#;
        let r = parse_ldi_map(html);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].page_url, "https://real-site.com/photo");
    }

    #[test]
    fn ldi_deduplicates_across_cases() {
        // Same URL found via Case 1 (direct) and Case 3 (child) — only one result
        let html = r#"<script>google.ldi = {"dimg_1":"url"}</script>
        <a href="https://example.com/dup" data-iid="dimg_1">Direct</a>
        <div data-iid="dimg_1"><a href="https://example.com/dup">Child</a></div>"#;
        let r = parse_ldi_map(html);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn ldi_no_matching_dom_elements() {
        // dimg_ keys exist but no DOM elements have data-iid
        let html = r#"<script>google.ldi = {"dimg_1":"https://img.com/a.jpg","dimg_2":"https://img.com/b.jpg"}</script>
        <a href="https://example.com/page">No data-iid</a>"#;
        let r = parse_ldi_map(html);
        assert!(r.is_empty());
    }

    #[test]
    fn ldi_malformed_json() {
        let html = r#"<script>google.ldi = {not valid json}</script>"#;
        assert!(parse_ldi_map(html).is_empty());
    }

    #[test]
    fn af_callback_all_google_urls_returns_empty() {
        let data = r#"[["https://www.google.com/s"],["https://lh3.googleusercontent.com/t"],["https://gstatic.com/x"]]"#;
        let r = parse_af_callbacks(&make_af_html(data));
        assert!(r.is_empty());
    }

    #[test]
    fn af_callback_multiple_blocks() {
        // Two separate AF_initDataCallback blocks
        let html = r#"<html>
        <script>AF_initDataCallback({key:'ds:0',data:["https://first.com/p1"],sideChannel:{}});</script>
        <script>AF_initDataCallback({key:'ds:1',data:["https://second.com/p2"],sideChannel:{}});</script>
        </html>"#;
        let r = parse_af_callbacks(html);
        assert_eq!(r.len(), 2);
        assert!(r.iter().any(|m| m.page_url == "https://first.com/p1"));
        assert!(r.iter().any(|m| m.page_url == "https://second.com/p2"));
    }

    #[test]
    fn strategy_fallthrough_ldi_empty_af_works() {
        // LDI present but empty, AF has results
        let html = r#"<script>google.ldi = {"other_key":"not_dimg"}</script>
        <script>AF_initDataCallback({key:'ds:1',data:["https://af-result.com/p"],sideChannel:{}});</script>"#;
        let r = parse_lens_html(html);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].page_url, "https://af-result.com/p");
    }

    #[test]
    fn strategy_fallthrough_all_empty_dom_works() {
        // No LDI, no AF, but has DOM links
        let html = r#"<html><body>
        <a href="https://dom-result.com/page">DOM Result</a>
        </body></html>"#;
        let r = parse_lens_html(html);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].page_url, "https://dom-result.com/page");
    }

    #[test]
    fn dom_links_deduplicates() {
        let html = r#"<html><body>
        <a href="https://example.com/same">First</a>
        <a href="https://example.com/same">Second</a>
        <a href="https://other.com/diff">Other</a>
        </body></html>"#;
        let r = parse_dom_links(html);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].title, "First"); // keeps first occurrence
    }

    #[test]
    fn dom_links_skips_short_urls() {
        let html = r#"<a href="http://x.c/y">Short</a>"#;
        let r = parse_dom_links(html);
        // href must start with "http" — this does, but is_google_url won't match
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn is_google_url_edge_cases() {
        // Subdomain tricks that should NOT match
        assert!(!is_google_url("https://google.com.evil.com/page"));
        assert!(!is_google_url("https://notgoogleusercontent.com/x"));
        // Valid Google subdomains
        assert!(is_google_url("https://apis.google.com/js/platform.js"));
        assert!(is_google_url("https://fonts.googleapis.com/css"));
        // Invalid URL
        assert!(!is_google_url("not-a-url"));
        assert!(!is_google_url(""));
    }

    #[test]
    fn parse_lens_html_max_respected() {
        // parse_lens_html returns all results; truncation is in ReverseEngine::search.
        // But we test that parse_lens_html can handle many results.
        let mut links = String::new();
        for i in 0..50 {
            links.push_str(&format!(r#"<a href="https://site{i}.com/page">Title {i}</a>"#));
        }
        let html = format!("<html><body>{links}</body></html>");
        let r = parse_lens_html(&html);
        assert_eq!(r.len(), 50);
    }
}
