//! Reverse image search with multiple engines.

use async_trait::async_trait;
use ox_http::HttpClient;
use serde::{Deserialize, Serialize};

/// A single match from reverse image search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseMatch {
    /// URL of the page where the image was found.
    pub page_url: String,
    /// Page title.
    pub title: String,
    /// Thumbnail URL (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<String>,
    /// Domain extracted from page_url.
    pub domain: String,
    /// Which engine found this match.
    pub engine: String,
    /// Page description/snippet (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Original image dimensions "WxH" (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_size: Option<String>,
}

/// Aggregated result from reverse image search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseResult {
    /// All matching pages.
    pub matches: Vec<ReverseMatch>,
    /// Whether any match domain is a known stock photo site.
    pub is_stock: bool,
    /// Stock domains found (empty if is_stock=false).
    pub stock_domains: Vec<String>,
    /// Engines that were used.
    pub engines_used: Vec<String>,
    /// Search time in milliseconds.
    pub elapsed_ms: u64,
}

/// Errors from reverse image search operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http: {0}")]
    Http(#[from] ox_http::HttpError),
    #[error("parse: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Extracts domain from a URL, stripping `www.` prefix.
pub fn extract_domain(page_url: &str) -> String {
    url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .map(|h| h.strip_prefix("www.").unwrap_or(&h).to_owned())
        .unwrap_or_default()
}

/// Trait for reverse image search engines.
#[async_trait]
pub trait ReverseEngine: Send + Sync {
    /// Search for pages containing the image at the given URL.
    async fn search(
        &self,
        client: &HttpClient,
        image_url: &str,
        max: usize,
    ) -> Result<Vec<ReverseMatch>>;

    /// Engine name for logging and response metadata.
    fn name(&self) -> &str;
}

/// Stock photo domains to check against reverse search results.
const STOCK_DOMAINS: &[&str] = &[
    "shutterstock",
    "gettyimages",
    "istockphoto",
    "adobestock",
    "depositphotos",
    "dreamstime",
    "123rf",
    "alamy",
    "bigstockphoto",
    "stocksy",
    "pond5",
    "masterfile",
    "superstock",
    "agefotostock",
    "colourbox",
    "yayimages",
    "vectorstock",
    "freepik",
    "canstockphoto",
    "loriimages",
    "fotobank",
];

/// Check if a domain matches any known stock photo site.
pub fn is_stock_domain(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    STOCK_DOMAINS.iter().any(|s| lower.contains(s))
}

mod google_lens;
mod yandex;
mod fusion;

pub use google_lens::GoogleLens;
pub use yandex::YandexImages;
pub use fusion::ReverseSearchEngine;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_domain_strips_www() {
        assert_eq!(extract_domain("https://www.example.com/p"), "example.com");
        assert_eq!(extract_domain("https://blog.site.org/x"), "blog.site.org");
    }

    #[test]
    fn extract_domain_invalid_url() {
        assert_eq!(extract_domain("not-a-url"), "");
    }

    #[test]
    fn stock_domain_detection() {
        assert!(is_stock_domain("shutterstock.com"));
        assert!(is_stock_domain("www.gettyimages.com"));
        assert!(!is_stock_domain("example.com"));
    }
}
