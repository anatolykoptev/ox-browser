//! DDG Images engine — vqd token + `/i.js` endpoint.

use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

use crate::{Error, ImageEngine, ImageResult, Result};
use ox_http::HttpClient;

const DDG_BASE: &str = "https://duckduckgo.com";

/// DDG Images search via vqd token + /i.js endpoint.
pub struct DdgImages;

#[async_trait]
impl ImageEngine for DdgImages {
    async fn search(
        &self,
        client: &HttpClient,
        query: &str,
        max: usize,
    ) -> Result<Vec<ImageResult>> {
        let token_url = format!(
            "{}/?q={}&iax=images&ia=images",
            DDG_BASE,
            urlencoding::encode(query),
        );
        let token_resp = client.get(&token_url).await?;
        let vqd = parse_vqd(&token_resp.body)
            .ok_or_else(|| Error::Parse("vqd token not found".into()))?;

        let images_url = format!(
            "{}/i.js?l=ru-ru&o=json&q={}&vqd={}&f=,,,,,&p=1",
            DDG_BASE,
            urlencoding::encode(query),
            urlencoding::encode(&vqd),
        );
        let images_resp = client.get(&images_url).await?;
        let mut results = parse_ddg_json(&images_resp.body);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "ddg"
    }
}

static VQD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"vqd=([0-9a-f-]+)").expect("vqd regex"));

fn parse_vqd(html: &str) -> Option<String> {
    VQD_RE.captures(html).map(|c| c[1].to_owned())
}

#[derive(Deserialize)]
struct DdgResponse {
    #[serde(default)]
    results: Vec<DdgResult>,
}

#[derive(Deserialize)]
struct DdgResult {
    #[serde(default)]
    image: String,
    #[serde(default)]
    thumbnail: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    width: u32,
    #[serde(default)]
    height: u32,
}

fn parse_ddg_json(body: &str) -> Vec<ImageResult> {
    let Ok(resp) = serde_json::from_str::<DdgResponse>(body) else {
        return Vec::new();
    };
    resp.results
        .into_iter()
        .filter(|r| !r.image.is_empty())
        .map(|r| ImageResult {
            url: r.image,
            thumbnail: r.thumbnail,
            source: r.url,
            title: r.title,
            width: r.width,
            height: r.height,
            engine: "ddg".into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_vqd_token() {
        let html = r#"<script>nrj('/d.js?q=cats&vqd=4-123456789-abc&kl=ru-ru')</script>"#;
        assert_eq!(parse_vqd(html), Some("4-123456789-abc".into()));
    }

    #[test]
    fn extract_vqd_missing() {
        assert_eq!(parse_vqd("<html>no token</html>"), None);
    }

    #[test]
    fn parse_ddg_json_results() {
        let json = r#"{"results":[{"image":"https://img.com/a.jpg","thumbnail":"https://th.com/a.jpg","url":"https://page.com/a","title":"Cat photo","width":800,"height":600},{"image":"https://img.com/b.jpg","thumbnail":"https://th.com/b.jpg","url":"https://page.com/b","title":"Dog photo","width":1024,"height":768}]}"#;
        let results = parse_ddg_json(json);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].url, "https://img.com/a.jpg");
        assert_eq!(results[0].width, 800);
        assert_eq!(results[0].engine, "ddg");
    }

    #[test]
    fn parse_ddg_json_empty() {
        assert!(parse_ddg_json("{}").is_empty());
        assert!(parse_ddg_json(r#"{"results":[]}"#).is_empty());
    }

    #[test]
    fn parse_ddg_json_filter_empty_image() {
        let json = r#"{"results":[{"image":"","thumbnail":"t.jpg","url":"p.com","title":"No img","width":0,"height":0},{"image":"https://real.jpg","thumbnail":"t2.jpg","url":"p2.com","title":"Real","width":100,"height":100}]}"#;
        let results = parse_ddg_json(json);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://real.jpg");
    }
}
