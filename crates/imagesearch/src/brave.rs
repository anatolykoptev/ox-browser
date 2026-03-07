// Brave Images engine — SvelteKit SPA with embedded JSON.

use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

use crate::{Error, ImageEngine, ImageResult, Result};
use ox_http::HttpClient;

const BRAVE_IMAGES_URL: &str = "https://search.brave.com/images";

const BRAVE_COOKIES: &str =
    "safesearch=off; useLocation=0; summarizer=0; country=us; ui_lang=en-us";

/// Brave Images search via embedded SvelteKit JSON.
pub struct BraveImages;

#[async_trait]
impl ImageEngine for BraveImages {
    async fn search(
        &self,
        client: &HttpClient,
        query: &str,
        max: usize,
    ) -> Result<Vec<ImageResult>> {
        let url = format!(
            "{}?q={}&source=web",
            BRAVE_IMAGES_URL,
            urlencoding::encode(query),
        );
        let resp = client
            .get_with_headers(
                &url,
                &[("Cookie", BRAVE_COOKIES)],
            )
            .await?;
        if resp.status != 200 {
            return Err(Error::Parse(format!(
                "brave status {}",
                resp.status
            )));
        }
        let mut results = parse_brave_results(&resp.body);
        results.truncate(max);
        Ok(results)
    }

    fn name(&self) -> &str {
        "brave"
    }
}

/// Regex to extract individual image result objects from the
/// embedded SvelteKit JSON. Each result contains `"properties":`
/// with image URL, dimensions, and a `"thumbnail":` block.
static RESULT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\{"url":"[^"]+","title":"[^"]*"[^}]*"properties":\{[^}]+\}[^}]*"thumbnail":\{[^}]+\}\}"#,
    )
    .expect("brave result regex")
});

#[derive(Deserialize)]
struct BraveResult {
    url: Option<String>,
    title: Option<String>,
    properties: Option<BraveProperties>,
    thumbnail: Option<BraveThumbnail>,
}

#[derive(Deserialize)]
struct BraveProperties {
    url: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
}

#[derive(Deserialize)]
struct BraveThumbnail {
    src: Option<String>,
}

fn parse_brave_results(html: &str) -> Vec<ImageResult> {
    let mut results = Vec::new();
    for m in RESULT_RE.find_iter(html) {
        let Ok(br) = serde_json::from_str::<BraveResult>(m.as_str())
        else {
            continue;
        };
        let Some(props) = br.properties else {
            continue;
        };
        let Some(image_url) = props.url.filter(|u| !u.is_empty())
        else {
            continue;
        };
        results.push(ImageResult {
            url: image_url,
            thumbnail: br
                .thumbnail
                .and_then(|t| t.src)
                .unwrap_or_default(),
            source: br.url.unwrap_or_default(),
            title: br.title.unwrap_or_default(),
            width: props.width.unwrap_or_default(),
            height: props.height.unwrap_or_default(),
            engine: "brave".into(),
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_html(results_json: &str) -> String {
        format!(
            r#"<html><head></head><body>
<script>
const data = [
  {{"type":"data","data":{{"body":{{"response":{{"results":{results}}}}}}}}}
];
</script>
</body></html>"#,
            results = results_json,
        )
    }

    #[test]
    fn parse_brave_results_extracts() {
        let results_json = r#"[
            {"url":"https://example.com/page","title":"Nice Photo","source":"example.com","properties":{"url":"https://cdn.example.com/image.jpg","resized":"https://imgs.search.brave.com/r1","format":"jpeg","width":1920,"height":1080},"thumbnail":{"src":"https://imgs.search.brave.com/th1.jpg"}},
            {"url":"https://other.com/cats","title":"Cat Picture","source":"other.com","properties":{"url":"https://cdn.other.com/cat.png","resized":"https://imgs.search.brave.com/r2","format":"png","width":800,"height":600},"thumbnail":{"src":"https://imgs.search.brave.com/th2.jpg"}}
        ]"#;
        let html = fake_html(results_json);
        let results = parse_brave_results(&html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].url, "https://cdn.example.com/image.jpg");
        assert_eq!(
            results[0].thumbnail,
            "https://imgs.search.brave.com/th1.jpg"
        );
        assert_eq!(results[0].source, "https://example.com/page");
        assert_eq!(results[0].title, "Nice Photo");
        assert_eq!(results[0].width, 1920);
        assert_eq!(results[0].height, 1080);
        assert_eq!(results[0].engine, "brave");
        assert_eq!(results[1].url, "https://cdn.other.com/cat.png");
        assert_eq!(results[1].width, 800);
    }

    #[test]
    fn parse_brave_empty() {
        let html = fake_html("[]");
        assert!(parse_brave_results(&html).is_empty());
    }

    #[test]
    fn parse_brave_no_data() {
        let html = "<html><body>no script data here</body></html>";
        assert!(parse_brave_results(html).is_empty());
    }

    #[test]
    fn parse_brave_missing_properties() {
        // Result without properties.url should be skipped.
        let results_json = r#"[
            {"url":"https://example.com/page","title":"No Props","source":"example.com","properties":{"resized":"https://imgs.search.brave.com/r1","format":"jpeg","width":100,"height":100},"thumbnail":{"src":"https://imgs.search.brave.com/th1.jpg"}},
            {"url":"https://ok.com/page","title":"Has Props","source":"ok.com","properties":{"url":"https://cdn.ok.com/img.jpg","format":"jpeg","width":640,"height":480},"thumbnail":{"src":"https://imgs.search.brave.com/th2.jpg"}}
        ]"#;
        let html = fake_html(results_json);
        let results = parse_brave_results(&html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://cdn.ok.com/img.jpg");
        assert_eq!(results[0].title, "Has Props");
    }
}
