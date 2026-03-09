//! Video extraction from HTML (methods 5-9).
//!
//! Extracts `<video>` tags, `og:video`, `twitter:player:stream`,
//! JSON-LD VideoObject, and inline JS video URL heuristics.

use std::collections::HashSet;
use std::sync::LazyLock;
use dom_query::Document;
use regex::Regex;
use url::Url;
use super::{ExtractedMedia, resolve_url, video_media};

/// Regex for video URLs in inline JS.
static VIDEO_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["']([^"'\s]+\.(?:mp4|m3u8|webm))["']"#).unwrap()
});

/// Run all video extraction methods and append to results.
pub(crate) fn extract_videos(
    doc: &Document,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    extract_video_tags(doc, base_url, base, seen, results);
    extract_og_video(doc, base_url, base, seen, results);
    extract_twitter_player(doc, base_url, base, seen, results);
    extract_json_ld_video(doc, base_url, base, seen, results);
    extract_inline_js_video(doc, base_url, base, seen, results);
}

/// Try to resolve a URL and insert into seen set; if new, push a video media item.
fn push_video(
    raw: &str,
    base: &Option<Url>,
    base_url: &str,
    title: &str,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    let url = resolve_url(raw, base);
    if !url.is_empty() && seen.insert(url.clone()) {
        results.push(video_media(url, title.to_string(), base_url));
    }
}

/// 5. `<video>` tags — both src attr and child `<source>` elements.
fn extract_video_tags(
    doc: &Document,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    for node in doc.select("video").iter() {
        if let Some(src) = node.attr("src") {
            push_video(src.as_ref(), base, base_url, "", seen, results);
        }
        for source in node.select("source").iter() {
            if let Some(src) = source.attr("src") {
                push_video(src.as_ref(), base, base_url, "", seen, results);
            }
        }
    }
}

/// 6. `og:video` and `og:video:secure_url` meta tags.
fn extract_og_video(
    doc: &Document,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    let sel = "meta[property='og:video'], meta[property='og:video:secure_url']";
    for node in doc.select(sel).iter() {
        if let Some(content) = node.attr("content") {
            push_video(content.as_ref(), base, base_url, "", seen, results);
        }
    }
}

/// 7. `twitter:player:stream` meta tag.
fn extract_twitter_player(
    doc: &Document,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    for node in doc.select("meta[name='twitter:player:stream']").iter() {
        if let Some(content) = node.attr("content") {
            push_video(content.as_ref(), base, base_url, "", seen, results);
        }
    }
}

/// 8. JSON-LD `VideoObject` in `<script type="application/ld+json">`.
fn extract_json_ld_video(
    doc: &Document,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    for node in doc.select("script[type='application/ld+json']").iter() {
        let text = node.text();
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        walk_json_ld(&value, base_url, base, seen, results);
    }
}

/// Recursively look for VideoObject in JSON-LD (handles @graph arrays too).
fn walk_json_ld(
    value: &serde_json::Value,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    match value {
        serde_json::Value::Object(obj) => {
            if obj.get("@type").and_then(|t| t.as_str()) == Some("VideoObject") {
                let raw = obj.get("contentUrl").or_else(|| obj.get("embedUrl"))
                    .and_then(|v| v.as_str()).unwrap_or_default();
                let title = obj.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                push_video(raw, base, base_url, title, seen, results);
            }
            if let Some(graph) = obj.get("@graph") {
                walk_json_ld(graph, base_url, base, seen, results);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                walk_json_ld(item, base_url, base, seen, results);
            }
        }
        _ => {}
    }
}

/// 9. Inline JS heuristics — regex for video URLs in script blocks.
fn extract_inline_js_video(
    doc: &Document,
    base_url: &str,
    base: &Option<Url>,
    seen: &mut HashSet<String>,
    results: &mut Vec<ExtractedMedia>,
) {
    for node in doc.select("script").iter() {
        let stype = node.attr("type").unwrap_or_default();
        if !stype.as_ref().is_empty() && stype.as_ref() != "text/javascript" {
            continue;
        }
        let text = node.text();
        for cap in VIDEO_URL_RE.captures_iter(&text) {
            if let Some(m) = cap.get(1) {
                push_video(m.as_str(), base, base_url, "", seen, results);
            }
        }
    }
}
