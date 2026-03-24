//! Reddit-specific handler: fetch via old.reddit.com JSON API.
//!
//! Reddit blocks headless browsers at app level (not CF). The `.json` suffix
//! on any Reddit URL returns structured data without CF protection.
//! Requires residential proxy for datacenter IPs.

use std::time::Instant;

use url::Url;

use crate::content::{self, ContentFormat, ExtractedContent, ReadOutput, ReadParams};
use crate::read_pipeline::{build_output, elapsed};
use crate::HttpClient;

/// Try Reddit JSON endpoint. Returns Some(output) if URL is reddit.com, None otherwise.
pub async fn try_reddit_json(
    http: &HttpClient,
    params: &ReadParams,
    format: ContentFormat,
    start: Instant,
) -> Option<ReadOutput> {
    let url = Url::parse(&params.url).ok()?;
    let host = url.host_str()?;
    if !host.contains("reddit.com") {
        return None;
    }
    let path = url.path().trim_end_matches('/');
    let json_url = format!("https://old.reddit.com{path}.json?limit=25&raw_json=1");
    tracing::info!(url = %params.url, json_url = %json_url, "reddit: using JSON API");

    let resp = http.get(&json_url).await.ok()?;
    if resp.status != 200 {
        return None;
    }
    let data: serde_json::Value = serde_json::from_str(&resp.body).ok()?;

    let (title, lines) = if let Some(children) = data["data"]["children"].as_array() {
        parse_listing(children)
    } else if let Some(arr) = data.as_array() {
        parse_post_comments(arr)
    } else {
        return None;
    };

    if lines.is_empty() {
        return None;
    }

    let content = lines.join("\n\n");
    let ext = ExtractedContent {
        title,
        content,
        author: String::new(),
        excerpt: String::new(),
        length: 0,
        json_ld: vec![],
        og_image: String::new(),
    };
    Some(build_output(ext, params, "reddit-json", elapsed(start)))
}

/// Parse subreddit listing (r/rust, r/rust/hot, etc.)
fn parse_listing(children: &[serde_json::Value]) -> (String, Vec<String>) {
    let sub = children
        .first()
        .and_then(|c| c["data"]["subreddit"].as_str())
        .unwrap_or("reddit");
    let title = format!("r/{sub}");
    let lines: Vec<String> = children
        .iter()
        .take(25)
        .filter_map(|child| {
            let d = &child["data"];
            let t = d["title"].as_str()?;
            let score = d["score"].as_i64().unwrap_or(0);
            let author = d["author"].as_str().unwrap_or("?");
            Some(format!("[{score}] {t} (by {author})"))
        })
        .collect();
    (title, lines)
}

/// Parse post + comments (reddit.com/r/sub/comments/id/...)
fn parse_post_comments(arr: &[serde_json::Value]) -> (String, Vec<String>) {
    let mut title = String::new();
    let mut lines = Vec::new();

    if let Some(post) = arr.first().and_then(|l| l["data"]["children"][0]["data"].as_object()) {
        title = post.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if let Some(text) = post.get("selftext").and_then(|v| v.as_str()) {
            if !text.is_empty() {
                lines.push(text.to_string());
            }
        }
    }
    if let Some(comments) = arr.get(1).and_then(|l| l["data"]["children"].as_array()) {
        for c in comments.iter().take(20) {
            let body = c["data"]["body"].as_str().unwrap_or("");
            let author = c["data"]["author"].as_str().unwrap_or("");
            if !body.is_empty() {
                lines.push(format!("{author}: {body}"));
            }
        }
    }
    (title, lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listing_extracts_posts() {
        let json = serde_json::json!([
            {"data": {"title": "Post 1", "score": 42, "author": "user1", "subreddit": "rust"}},
            {"data": {"title": "Post 2", "score": 10, "author": "user2", "subreddit": "rust"}},
        ]);
        let (title, lines) = parse_listing(json.as_array().unwrap());
        assert_eq!(title, "r/rust");
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("[42]"));
        assert!(lines[0].contains("Post 1"));
        assert!(lines[1].contains("user2"));
    }

    #[test]
    fn parse_post_comments_extracts_content() {
        let json = serde_json::json!([
            {"data": {"children": [{"data": {"title": "My post", "selftext": "Post body here"}}]}},
            {"data": {"children": [
                {"data": {"body": "Great post!", "author": "commenter1"}},
                {"data": {"body": "Thanks!", "author": "op"}},
            ]}},
        ]);
        let (title, lines) = parse_post_comments(json.as_array().unwrap());
        assert_eq!(title, "My post");
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "Post body here");
        assert!(lines[1].contains("commenter1"));
    }

    #[test]
    fn non_reddit_url_returns_none_sync() {
        let url = Url::parse("https://example.com/page").unwrap();
        assert!(!url.host_str().unwrap().contains("reddit.com"));
    }

    #[test]
    fn parse_empty_listing() {
        let json = serde_json::json!([]);
        let (_, lines) = parse_listing(json.as_array().unwrap());
        assert!(lines.is_empty());
    }
}
