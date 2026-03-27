//! Chrome interact endpoints: POST /chrome/interact, DELETE /chrome/session/:id

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use ox_http::chrome_interact::{self, InteractRequest, InteractResponse};

use super::AppState;

#[axum::debug_handler]
pub async fn chrome_interact_handler(
    State(state): State<AppState>,
    Json(req): Json<InteractRequest>,
) -> (StatusCode, Json<InteractResponse>) {
    let resp = chrome_interact::execute(req, &state.chrome_semaphore, &state.session_pool).await;
    let status = if resp.error.is_some() {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::OK
    };
    (status, Json(resp))
}

/// DELETE /chrome/session/:id — manually destroy a persistent Chrome session.
pub async fn destroy_session_handler(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let destroyed = state.session_pool.destroy(&session_id).await;
    if destroyed {
        (StatusCode::OK, Json(serde_json::json!({"status": "destroyed", "session_id": session_id})))
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "session not found", "session_id": session_id})))
    }
}
