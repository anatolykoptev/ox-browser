//! POST /readability endpoint — extract article content from a URL.

use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use readabilityrs::Readability;
use serde::{Deserialize, Serialize};

use super::AppState;

#[derive(Deserialize)]
pub struct ReadabilityRequest {
    pub url: String,
    /// Return content as plain text instead of HTML. Default: true.
    #[serde(default = "default_true")]
    pub plain_text: bool,
    /// Maximum content length in chars. 0 = unlimited. Default: 0.
    #[serde(default)]
    pub max_length: usize,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
pub struct ReadabilityResponse {
    pub title: String,
    pub content: String,
    pub author: String,
    pub excerpt: String,
    pub length: usize,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn readability(
    State(state): State<AppState>,
    Json(req): Json<ReadabilityRequest>,
) -> (StatusCode, Json<ReadabilityResponse>) {
    let start = Instant::now();

    let resp = match state.http_client.get(&req.url).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(ReadabilityResponse {
                    title: String::new(),
                    content: String::new(),
                    author: String::new(),
                    excerpt: String::new(),
                    length: 0,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: Some(format!("fetch failed: {e}")),
                }),
            );
        }
    };

    if resp.status != 200 {
        return (
            StatusCode::BAD_GATEWAY,
            Json(ReadabilityResponse {
                title: String::new(),
                content: String::new(),
                author: String::new(),
                excerpt: String::new(),
                length: 0,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some(format!("HTTP {}", resp.status)),
            }),
        );
    }

    let result = extract_article(&resp.body, &req.url, req.plain_text, req.max_length);

    (
        StatusCode::OK,
        Json(ReadabilityResponse {
            elapsed_ms: start.elapsed().as_millis() as u64,
            error: None,
            ..result
        }),
    )
}

fn extract_article(
    html: &str,
    url: &str,
    plain_text: bool,
    max_length: usize,
) -> ReadabilityResponse {
    let r = match Readability::new(html, Some(url), None) {
        Ok(r) => r,
        Err(e) => {
            return ReadabilityResponse {
                title: String::new(),
                content: String::new(),
                author: String::new(),
                excerpt: String::new(),
                length: 0,
                elapsed_ms: 0,
                error: Some(format!("readability init: {e}")),
            };
        }
    };
    let article = match r.parse() {
        Some(a) => a,
        None => {
            return ReadabilityResponse {
                title: String::new(),
                content: String::new(),
                author: String::new(),
                excerpt: String::new(),
                length: 0,
                elapsed_ms: 0,
                error: Some("readability: could not extract article".into()),
            };
        }
    };

    let raw_content = article.content.unwrap_or_default();
    let mut content = if plain_text {
        html_to_plain(&raw_content)
    } else {
        raw_content
    };

    if max_length > 0 && content.len() > max_length {
        // Truncate at char boundary
        let mut end = max_length;
        while end < content.len() && !content.is_char_boundary(end) {
            end += 1;
        }
        content.truncate(end);
        content.push('…');
    }

    let length = content.len();

    ReadabilityResponse {
        title: article.title.unwrap_or_default(),
        content,
        author: article.byline.unwrap_or_default(),
        excerpt: article.excerpt.unwrap_or_default(),
        length,
        elapsed_ms: 0,
        error: None,
    }
}

/// Strip HTML tags and normalize whitespace for plain text output.
fn html_to_plain(html: &str) -> String {
    let doc = dom_query::Document::from(html);
    let text = doc.select("body").text().to_string();
    // Collapse multiple whitespace/newlines into single spaces, trim
    let mut result = String::with_capacity(text.len());
    let mut prev_ws = true;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                result.push(' ');
                prev_ws = true;
            }
        } else {
            result.push(ch);
            prev_ws = false;
        }
    }
    result.trim().to_string()
}
