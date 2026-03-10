//! Video extraction from HTML (methods 5-9).
//!
//! Extracts `<video>` tags, `og:video`, `twitter:player:stream`,
//! JSON-LD VideoObject, and inline JS video URL heuristics.

use std::sync::LazyLock;
use regex::Regex;
use super::{ExtractContext, resolve_url, video_media};

/// Regex for video URLs in inline JS.
static VIDEO_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["']([^"'\s]+\.(?:mp4|m3u8|webm))["']"#).unwrap()
});

/// Run all video extraction methods and append to results.
pub(crate) fn extract_videos(ctx: &mut ExtractContext) {
    extract_video_tags(ctx);
    extract_og_video(ctx);
    extract_twitter_player(ctx);
    extract_json_ld_video(ctx);
    extract_inline_js_video(ctx);
}

/// Try to resolve a URL and insert into seen set; if new, push a video media item.
fn push_video(raw: &str, ctx: &mut ExtractContext, title: &str) {
    let url = resolve_url(raw, ctx.base);
    if !url.is_empty() && ctx.seen.insert(url.clone()) {
        ctx.results.push(video_media(url, title.to_string(), ctx.base_url));
    }
}

/// 5. `<video>` tags — both src attr and child `<source>` elements.
fn extract_video_tags(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("video").iter() {
        if let Some(src) = node.attr("src") {
            push_video(src.as_ref(), ctx, "");
        }
        for source in node.select("source").iter() {
            if let Some(src) = source.attr("src") {
                push_video(src.as_ref(), ctx, "");
            }
        }
    }
}

/// 6. `og:video` and `og:video:secure_url` meta tags.
fn extract_og_video(ctx: &mut ExtractContext) {
    let sel = "meta[property='og:video'], meta[property='og:video:secure_url']";
    for node in ctx.doc.select(sel).iter() {
        if let Some(content) = node.attr("content") {
            push_video(content.as_ref(), ctx, "");
        }
    }
}

/// 7. `twitter:player:stream` meta tag.
fn extract_twitter_player(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("meta[name='twitter:player:stream']").iter() {
        if let Some(content) = node.attr("content") {
            push_video(content.as_ref(), ctx, "");
        }
    }
}

/// 8. JSON-LD `VideoObject` in `<script type="application/ld+json">`.
fn extract_json_ld_video(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("script[type='application/ld+json']").iter() {
        let text = node.text();
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        walk_json_ld(&value, ctx);
    }
}

/// Recursively look for VideoObject in JSON-LD (handles @graph arrays too).
fn walk_json_ld(value: &serde_json::Value, ctx: &mut ExtractContext) {
    match value {
        serde_json::Value::Object(obj) => {
            if obj.get("@type").and_then(|t| t.as_str()) == Some("VideoObject") {
                let raw = obj.get("contentUrl").or_else(|| obj.get("embedUrl"))
                    .and_then(|v| v.as_str()).unwrap_or_default();
                let title = obj.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                push_video(raw, ctx, title);
            }
            if let Some(graph) = obj.get("@graph") {
                walk_json_ld(graph, ctx);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                walk_json_ld(item, ctx);
            }
        }
        _ => {}
    }
}

/// 9. Inline JS heuristics — regex for video URLs in script blocks.
fn extract_inline_js_video(ctx: &mut ExtractContext) {
    for node in ctx.doc.select("script").iter() {
        let stype = node.attr("type").unwrap_or_default();
        if !stype.as_ref().is_empty() && stype.as_ref() != "text/javascript" {
            continue;
        }
        let text = node.text();
        for cap in VIDEO_URL_RE.captures_iter(&text) {
            if let Some(m) = cap.get(1) {
                push_video(m.as_str(), ctx, "");
            }
        }
    }
}
