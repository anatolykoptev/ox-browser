//! POST /read — unified content extraction.

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use ox_http::content::ReadParams;
use ox_http::read_pipeline;

use super::AppState;
use crate::inbound_auth::Authenticated;

pub async fn read(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    Json(params): Json<ReadParams>,
) -> (StatusCode, Json<ox_http::content::ReadOutput>) {
    // SEC-CR-002: only an authenticated caller may trigger the credentialed
    // chrome fallback (see read_pipeline).
    let output = read_pipeline::read_page(
        &state.http_client,
        &params,
        &state.site_handlers,
        auth.is_some(),
    )
    .await;

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
