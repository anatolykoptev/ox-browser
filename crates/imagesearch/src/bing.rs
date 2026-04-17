// Bing Images engine.

use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

use crate::{Error, ImageEngine, ImageResult, Result};
use ox_http::HttpClient;

const BING_IMAGES_URL: &str = "https://www.bing.com/images/async";

/// Bing Images search via the /images/async endpoint.
pub struct BingImages;

#[async_trait]
impl ImageEngine for BingImages {
    async fn search(
        &self,
        client: &HttpClient,
        query: &str,
        max: usize,
    ) -> Result<Vec<ImageResult>> {
        let count = max.min(35);
        let url = format!(
            "{}?q={}&first=0&count={}&mmasync=1",
            BING_IMAGES_URL,
            urlencoding::encode(query),
            count,
        );
        let resp = client.get(&url).await?;
        if resp.status != 200 {
            return Err(Error::Parse(format!("bing status {}", resp.status)));
        }
        let mut results = parse_bing_html(&resp.body);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "bing"
    }
}

static M_ATTR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"m="(\{[^"]*\})""#).expect("bing m-attr regex"));

#[derive(Deserialize)]
struct BingMAttr {
    murl: Option<String>,
    turl: Option<String>,
    purl: Option<String>,
    t: Option<String>,
}

fn parse_bing_html(html: &str) -> Vec<ImageResult> {
    let mut results = Vec::new();

    // Match m="..." on raw HTML (inner quotes are still &quot;),
    // then decode each captured group before JSON parsing.
    for cap in M_ATTR_RE.captures_iter(html) {
        let raw = &cap[1];
        let json_str = raw.replace("&quot;", "\"").replace("&amp;", "&");
        let Ok(attr) = serde_json::from_str::<BingMAttr>(&json_str) else {
            continue;
        };
        let Some(murl) = attr.murl.filter(|u| !u.is_empty()) else {
            continue;
        };
        results.push(ImageResult {
            url: murl,
            thumbnail: attr.turl.unwrap_or_default(),
            source: attr.purl.unwrap_or_default(),
            title: attr.t.unwrap_or_default(),
            engine: "bing".into(),
            ..Default::default()
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bing_html_extracts_images() {
        let html = r#"<div class="imgpt"><a m="{&quot;murl&quot;:&quot;https://example.com/photo.jpg&quot;,&quot;turl&quot;:&quot;https://th.bing.com/th1.jpg&quot;,&quot;purl&quot;:&quot;https://example.com/page&quot;,&quot;t&quot;:&quot;Nice Photo&quot;}"></a></div><div class="imgpt"><a m="{&quot;murl&quot;:&quot;https://other.com/cat.png&quot;,&quot;turl&quot;:&quot;https://th.bing.com/th2.jpg&quot;,&quot;purl&quot;:&quot;https://other.com/cats&quot;,&quot;t&quot;:&quot;Cat&quot;}"></a></div>"#;
        let results = parse_bing_html(html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].url, "https://example.com/photo.jpg");
        assert_eq!(results[0].thumbnail, "https://th.bing.com/th1.jpg");
        assert_eq!(results[0].source, "https://example.com/page");
        assert_eq!(results[0].title, "Nice Photo");
        assert_eq!(results[0].engine, "bing");
        assert_eq!(results[1].url, "https://other.com/cat.png");
    }

    #[test]
    fn parse_bing_html_empty_input() {
        assert!(parse_bing_html("").is_empty());
        assert!(parse_bing_html("<html><body>no images</body></html>").is_empty());
    }

    #[test]
    fn parse_bing_html_malformed_json() {
        let html = r#"<a m="{not valid json}"></a>"#;
        assert!(parse_bing_html(html).is_empty());
    }

    #[test]
    fn parse_bing_html_missing_murl() {
        let html = r#"<a m="{&quot;turl&quot;:&quot;https://th.jpg&quot;}"></a>"#;
        assert!(parse_bing_html(html).is_empty());
    }
}
