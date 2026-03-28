//! Chrome interact endpoints: POST /chrome/interact, DELETE /chrome/session/:id
//!
//! All Chrome operations are proxied to go-browser via HTTP.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use super::AppState;

#[axum::debug_handler]
pub async fn chrome_interact_handler(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.gobrowser_proxy.forward("/chrome/interact", &body).await {
        Ok((status, resp)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(resp),
        ),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

/// DELETE /chrome/session/:id — manually destroy a persistent Chrome session.
pub async fn destroy_session_handler(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.gobrowser_proxy.delete(&format!("/session/{session_id}")).await {
        Ok((status, resp)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::NOT_FOUND),
            Json(resp),
        ),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e})),
        ),
    }
}
