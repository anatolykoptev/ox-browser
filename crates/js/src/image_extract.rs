//! POST /images/extract endpoint.

use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_imagesearch::extract::extract_images;
use ox_imagesearch::ImageResult;
use serde::{Deserialize, Serialize};

use super::AppState;

#[derive(Deserialize)]
pub struct ImageExtractRequest {
    pub url: String,
    /// Minimum width in pixels. If not set, uses server config default.
    pub min_width: Option<u32>,
}

#[derive(Serialize)]
pub struct ImageExtractResponse {
    pub images: Vec<ImageResult>,
    pub total_on_page: usize,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn image_extract(
    State(state): State<AppState>,
    Json(req): Json<ImageExtractRequest>,
) -> (StatusCode, Json<ImageExtractResponse>) {
    let start = Instant::now();

    let resp = match state.http_client.get(&req.url).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(ImageExtractResponse {
                    images: Vec::new(),
                    total_on_page: 0,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: Some(format!("fetch failed: {e}")),
                }),
            );
        }
    };

    if resp.status != 200 {
        return (
            StatusCode::BAD_GATEWAY,
            Json(ImageExtractResponse {
                images: Vec::new(),
                total_on_page: 0,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some(format!("HTTP {}", resp.status)),
            }),
        );
    }

    let all = extract_images(&resp.body, &req.url);
    let total_on_page = all.len();

    let min_width = req.min_width.unwrap_or(state.defaults.image_min_width);
    // Filter by min_width if dimensions are known
    let filtered: Vec<ImageResult> = all
        .into_iter()
        .filter(|img| img.width == 0 || img.width >= min_width)
        .collect();

    (
        StatusCode::OK,
        Json(ImageExtractResponse {
            images: filtered,
            total_on_page,
            elapsed_ms: start.elapsed().as_millis() as u64,
            error: None,
        }),
    )
}
