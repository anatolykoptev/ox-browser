//! POST /images/search endpoint.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_imagesearch::fusion::ImageSearchEngine;
use ox_imagesearch::bing::BingImages;
use ox_imagesearch::brave::BraveImages;
use ox_imagesearch::ddg::DdgImages;
use ox_imagesearch::openverse::OpenverseImages;
use ox_imagesearch::pexels::PexelsImages;
use ox_imagesearch::{ImageEngine, ImageResult};
use serde::{Deserialize, Serialize};

use super::AppState;

#[derive(Deserialize)]
pub struct ImageSearchRequest {
    pub query: String,
    #[serde(default = "default_max")]
    pub max_results: usize,
    #[serde(default)]
    pub engines: Vec<String>,
}

fn default_max() -> usize {
    10
}

#[derive(Serialize)]
pub struct ImageSearchResponse {
    pub images: Vec<ImageResult>,
    pub engines_used: Vec<String>,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn image_search(
    State(state): State<AppState>,
    Json(req): Json<ImageSearchRequest>,
) -> (StatusCode, Json<ImageSearchResponse>) {
    let start = Instant::now();

    let mut engines: Vec<Arc<dyn ImageEngine>> = Vec::new();
    let use_all = req.engines.is_empty();

    if use_all || req.engines.iter().any(|e| e == "bing") {
        engines.push(Arc::new(BingImages));
    }
    if use_all || req.engines.iter().any(|e| e == "ddg") {
        engines.push(Arc::new(DdgImages));
    }
    if use_all || req.engines.iter().any(|e| e == "openverse") {
        engines.push(Arc::new(OpenverseImages::from_env()));
    }
    if req.engines.iter().any(|e| e == "pexels") {
        if let Ok(key) = std::env::var("PEXELS_API_KEY") {
            engines.push(Arc::new(PexelsImages { api_key: key }));
        }
    }
    if req.engines.iter().any(|e| e == "brave") {
        engines.push(Arc::new(BraveImages));
    }

    let engine_names: Vec<String> = engines.iter().map(|e| e.name().to_owned()).collect();
    let search = ImageSearchEngine::new(engines);
    let results = search
        .search(state.http_client.clone(), &req.query, req.max_results)
        .await;

    (
        StatusCode::OK,
        Json(ImageSearchResponse {
            images: results,
            engines_used: engine_names,
            elapsed_ms: start.elapsed().as_millis() as u64,
            error: None,
        }),
    )
}
