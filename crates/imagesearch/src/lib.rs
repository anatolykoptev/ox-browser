//! Multi-engine image search with stealth HTTP.

pub mod bing;
pub mod brave;
pub mod ddg;
pub mod extract;
pub mod fusion;
pub mod openverse;
pub mod pexels;

use async_trait::async_trait;
use ox_http::HttpClient;
use serde::{Deserialize, Serialize};

/// A single image search result from any engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageResult {
    pub url: String,
    pub thumbnail: String,
    pub source: String,
    pub title: String,
    pub width: u32,
    pub height: u32,
    pub engine: String,
}

/// Errors from image search operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http: {0}")]
    Http(#[from] ox_http::HttpError),
    #[error("parse: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// An image search engine that can query for images.
#[async_trait]
pub trait ImageEngine: Send + Sync {
    async fn search(
        &self,
        client: &HttpClient,
        query: &str,
        max: usize,
    ) -> Result<Vec<ImageResult>>;
    fn name(&self) -> &str;
}
