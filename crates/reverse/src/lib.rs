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

// TODO: uncomment when engine modules are implemented
// mod google_lens;
// mod yandex;
// mod fusion;

// pub use fusion::ReverseSearchEngine;
// pub use google_lens::GoogleLens;
// pub use yandex::YandexImages;
