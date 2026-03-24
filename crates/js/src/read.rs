//! POST /read — unified content extraction.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_http::content::ReadParams;
use ox_http::read_pipeline;

use super::AppState;

pub async fn read(
    State(state): State<AppState>,
    Json(params): Json<ReadParams>,
) -> (StatusCode, Json<ox_http::content::ReadOutput>) {
    let output = read_pipeline::read_page(&state.http_client, &params).await;

    let status = if output.error.is_some() {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::OK
    };
    (status, Json(output))
}

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;
