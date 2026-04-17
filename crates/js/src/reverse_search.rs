//! POST /images/reverse endpoint.

use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use ox_reverse::{GoogleLens, ReverseEngine, ReverseResult, ReverseSearchEngine, YandexImages};
use serde::Deserialize;

use super::AppState;

#[derive(Deserialize)]
pub struct ReverseSearchRequest {
    pub url: String,
    /// Engines: "google_lens", "yandex". Default: yandex only
    /// (Google Lens requires headless browser — SPA results).
    #[serde(default)]
    pub engines: Vec<String>,
    /// Max results. If not set, uses server config default.
    pub max_results: Option<usize>,
}

pub async fn reverse_search(
    State(state): State<AppState>,
    Json(req): Json<ReverseSearchRequest>,
) -> (StatusCode, Json<ReverseResult>) {
    let _start = Instant::now();

    let mut engines: Vec<Arc<dyn ReverseEngine>> = Vec::new();
    let use_all = req.engines.is_empty();

    // Google Lens disabled by default — results are SPA (no HTML data).
    // Enable explicitly with engines: ["google_lens"].
    if req.engines.iter().any(|e| e == "google_lens") {
        engines.push(Arc::new(GoogleLens));
    }
    if use_all || req.engines.iter().any(|e| e == "yandex") {
        engines.push(Arc::new(YandexImages));
    }

    let max_results = req
        .max_results
        .unwrap_or(state.defaults.reverse_max_results);
    let search = ReverseSearchEngine::new(engines);
    let result = search
        .search(state.http_client.clone(), &req.url, max_results)
        .await;

    (StatusCode::OK, Json(result))
}
