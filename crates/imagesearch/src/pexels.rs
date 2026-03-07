// Pexels Images engine — REST JSON API with Authorization header.

use async_trait::async_trait;
use serde::Deserialize;

use crate::{Error, ImageEngine, ImageResult, Result};
use ox_http::HttpClient;

const PEXELS_API_URL: &str = "https://api.pexels.com/v1/search";

/// Pexels image search via their REST API.
///
/// Requires an API key passed as `Authorization` header (raw key, no prefix).
pub struct PexelsImages {
    pub api_key: String,
}

#[async_trait]
impl ImageEngine for PexelsImages {
    async fn search(
        &self,
        client: &HttpClient,
        query: &str,
        max: usize,
    ) -> Result<Vec<ImageResult>> {
        let per_page = max.min(80); // Pexels max per_page is 80
        let url = format!(
            "{}?query={}&per_page={}&page=1",
            PEXELS_API_URL,
            urlencoding::encode(query),
            per_page,
        );
        let resp = client
            .get_with_headers(&url, &[("Authorization", &self.api_key)])
            .await?;
        if resp.status != 200 {
            return Err(Error::Parse(format!(
                "pexels status {}",
                resp.status
            )));
        }
        let mut results = parse_pexels_json(&resp.body);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "pexels"
    }
}

#[derive(Deserialize)]
struct PexelsResponse {
    #[serde(default)]
    photos: Vec<PexelsPhoto>,
}

#[derive(Deserialize)]
struct PexelsPhoto {
    #[serde(default)]
    url: String,
    #[serde(default)]
    alt: Option<String>,
    #[serde(default)]
    width: u32,
    #[serde(default)]
    height: u32,
    #[serde(default)]
    src: PexelsSrc,
}

#[derive(Deserialize, Default)]
struct PexelsSrc {
    #[serde(default)]
    original: String,
    #[serde(default)]
    small: String,
}

fn parse_pexels_json(body: &str) -> Vec<ImageResult> {
    let Ok(resp) = serde_json::from_str::<PexelsResponse>(body) else {
        return Vec::new();
    };
    resp.photos
        .into_iter()
        .filter(|p| !p.src.original.is_empty())
        .map(|p| ImageResult {
            url: p.src.original,
            thumbnail: p.src.small,
            source: p.url,
            title: p.alt.unwrap_or_default(),
            width: p.width,
            height: p.height,
            engine: "pexels".into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pexels_json_results() {
        let json = r#"{
            "total_results": 8000,
            "page": 1,
            "per_page": 15,
            "photos": [
                {
                    "id": 2014422,
                    "width": 3024,
                    "height": 3024,
                    "url": "https://www.pexels.com/photo/brown-rocks-2014422/",
                    "photographer": "Joey Farina",
                    "alt": "Brown Rocks During Golden Hour",
                    "src": {
                        "original": "https://images.pexels.com/photos/2014422/pexels-photo-2014422.jpeg",
                        "large": "https://images.pexels.com/photos/2014422/pexels-photo-2014422.jpeg?auto=compress&cs=tinysrgb&h=650&w=940",
                        "medium": "https://images.pexels.com/photos/2014422/pexels-photo-2014422.jpeg?auto=compress&cs=tinysrgb&h=350",
                        "small": "https://images.pexels.com/photos/2014422/pexels-photo-2014422.jpeg?auto=compress&cs=tinysrgb&h=130"
                    }
                },
                {
                    "id": 1000000,
                    "width": 1920,
                    "height": 1080,
                    "url": "https://www.pexels.com/photo/sunset-1000000/",
                    "photographer": "Jane Doe",
                    "alt": "Beautiful Sunset",
                    "src": {
                        "original": "https://images.pexels.com/photos/1000000/sunset.jpeg",
                        "small": "https://images.pexels.com/photos/1000000/sunset.jpeg?h=130"
                    }
                }
            ]
        }"#;
        let results = parse_pexels_json(json);
        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0].url,
            "https://images.pexels.com/photos/2014422/pexels-photo-2014422.jpeg"
        );
        assert_eq!(
            results[0].thumbnail,
            "https://images.pexels.com/photos/2014422/pexels-photo-2014422.jpeg?auto=compress&cs=tinysrgb&h=130"
        );
        assert_eq!(
            results[0].source,
            "https://www.pexels.com/photo/brown-rocks-2014422/"
        );
        assert_eq!(results[0].title, "Brown Rocks During Golden Hour");
        assert_eq!(results[0].width, 3024);
        assert_eq!(results[0].height, 3024);
        assert_eq!(results[0].engine, "pexels");
        assert_eq!(
            results[1].url,
            "https://images.pexels.com/photos/1000000/sunset.jpeg"
        );
        assert_eq!(results[1].width, 1920);
        assert_eq!(results[1].height, 1080);
    }

    #[test]
    fn parse_pexels_json_empty() {
        let json = r#"{"total_results":0,"page":1,"per_page":15,"photos":[]}"#;
        assert!(parse_pexels_json(json).is_empty());
    }

    #[test]
    fn parse_pexels_json_missing_alt() {
        let json = r#"{
            "photos": [{
                "id": 123,
                "width": 800,
                "height": 600,
                "url": "https://www.pexels.com/photo/test-123/",
                "src": {
                    "original": "https://images.pexels.com/photos/123/test.jpeg",
                    "small": "https://images.pexels.com/photos/123/test.jpeg?h=130"
                }
            }]
        }"#;
        let results = parse_pexels_json(json);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "");
    }

    #[test]
    fn parse_pexels_json_invalid() {
        assert!(parse_pexels_json("not json at all").is_empty());
        assert!(parse_pexels_json("{broken").is_empty());
    }
}
