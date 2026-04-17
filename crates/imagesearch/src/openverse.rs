//! Openverse Images engine — REST JSON API (Creative Commons).
//!
//! Anonymous: 100 req/min. With OAuth2 token: 10,000 req/day.
//! Set `OPENVERSE_ACCESS_TOKEN` env var for authenticated access.

use async_trait::async_trait;
use serde::Deserialize;

use crate::{Error, ImageEngine, ImageResult, Result};
use ox_http::HttpClient;

const OPENVERSE_API: &str = "https://api.openverse.org/v1/images/";

/// Openverse image search — 842M+ Creative Commons images.
pub struct OpenverseImages {
    access_token: Option<String>,
}

impl OpenverseImages {
    /// Create from `OPENVERSE_ACCESS_TOKEN` env var if set, otherwise anonymous.
    pub fn from_env() -> Self {
        Self {
            access_token: std::env::var("OPENVERSE_ACCESS_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }
}

#[async_trait]
impl ImageEngine for OpenverseImages {
    async fn search(
        &self,
        client: &HttpClient,
        query: &str,
        max: usize,
    ) -> Result<Vec<ImageResult>> {
        let page_size = max.min(50);
        let url = format!(
            "{}?q={}&page=1&page_size={}",
            OPENVERSE_API,
            urlencoding::encode(query),
            page_size,
        );

        let mut headers = vec![("Accept", "application/json")];
        let auth_value;
        if let Some(ref token) = self.access_token {
            auth_value = format!("Bearer {token}");
            headers.push(("Authorization", &auth_value));
        }

        let resp = client.get_with_headers(&url, &headers).await?;
        if resp.status != 200 {
            return Err(Error::Parse(format!("openverse status {}", resp.status)));
        }
        let mut results = parse_openverse_json(&resp.body);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "openverse"
    }
}

#[derive(Deserialize)]
struct OpenverseResponse {
    #[serde(default)]
    results: Vec<OpenverseResult>,
}

#[derive(Deserialize)]
struct OpenverseResult {
    #[serde(default)]
    url: String,
    #[serde(default)]
    thumbnail: Option<String>,
    #[serde(default)]
    foreign_landing_url: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    width: Option<u32>,
    #[serde(default)]
    height: Option<u32>,
}

fn parse_openverse_json(body: &str) -> Vec<ImageResult> {
    let Ok(resp) = serde_json::from_str::<OpenverseResponse>(body) else {
        return Vec::new();
    };
    resp.results
        .into_iter()
        .filter(|r| !r.url.is_empty())
        .map(|r| ImageResult {
            url: r.url,
            thumbnail: r.thumbnail.unwrap_or_default(),
            source: r.foreign_landing_url.unwrap_or_default(),
            title: r.title.unwrap_or_default(),
            width: r.width.unwrap_or(0),
            height: r.height.unwrap_or(0),
            engine: "openverse".into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_openverse_json_results() {
        let json = r#"{
            "result_count": 2,
            "page_count": 1,
            "page_size": 20,
            "page": 1,
            "results": [
                {
                    "id": "aaa-111",
                    "title": "Orange sunset",
                    "url": "https://live.staticflickr.com/3080/2775233719.jpg",
                    "thumbnail": "https://api.openverse.org/v1/images/aaa-111/thumb/",
                    "foreign_landing_url": "https://www.flickr.com/photos/user/2775233719",
                    "width": 500,
                    "height": 375,
                    "creator": "@Doug88888",
                    "license": "by-nc-sa",
                    "provider": "flickr",
                    "source": "flickr"
                },
                {
                    "id": "bbb-222",
                    "title": "Mountain view",
                    "url": "https://upload.wikimedia.org/mountain.jpg",
                    "thumbnail": "https://api.openverse.org/v1/images/bbb-222/thumb/",
                    "foreign_landing_url": "https://commons.wikimedia.org/wiki/File:Mountain.jpg",
                    "width": 1024,
                    "height": 768,
                    "creator": "PhotoUser",
                    "license": "by",
                    "provider": "wikimedia",
                    "source": "wikimedia"
                }
            ]
        }"#;
        let results = parse_openverse_json(json);
        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0].url,
            "https://live.staticflickr.com/3080/2775233719.jpg"
        );
        assert_eq!(results[0].title, "Orange sunset");
        assert_eq!(results[0].width, 500);
        assert_eq!(results[0].engine, "openverse");
    }

    #[test]
    fn parse_openverse_json_empty() {
        let json = r#"{"results":[],"result_count":0,"page_count":0,"page_size":20,"page":1}"#;
        assert!(parse_openverse_json(json).is_empty());
    }

    #[test]
    fn parse_openverse_json_missing_fields() {
        let json = r#"{
            "results": [{"id":"c","url":"https://example.com/photo.jpg","width":null,"height":null}]
        }"#;
        let results = parse_openverse_json(json);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].width, 0);
        assert_eq!(results[0].title, "");
    }

    #[test]
    fn parse_openverse_json_invalid() {
        assert!(parse_openverse_json("not json at all").is_empty());
        assert!(parse_openverse_json("{broken").is_empty());
    }
}
