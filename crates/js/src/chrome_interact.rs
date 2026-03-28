//! Chrome interact endpoints: POST /chrome/interact, DELETE /chrome/session/:id

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use super::AppState;

#[axum::debug_handler]
pub async fn chrome_interact_handler(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Some(ref proxy) = state.gobrowser_proxy {
        match proxy.forward("/chrome/interact", &body).await {
            Ok((status, resp)) => (
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                Json(resp),
            ),
            Err(e) => (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": e})),
            ),
        }
    } else {
        // Fallback to local chromiumoxide (will be removed in Task 6)
        let req: ox_http::chrome_interact::InteractRequest =
            match serde_json::from_value(body) {
                Ok(r) => r,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": format!("invalid request: {e}")})),
                    );
                }
            };
        let resp = ox_http::chrome_interact::execute(
            req,
            &state.chrome_semaphore,
            &state.session_pool,
        )
        .await;
        let status = if resp.error.is_some() {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::OK
        };
        (
            status,
            Json(serde_json::to_value(resp).unwrap_or_default()),
        )
    }
}

/// DELETE /chrome/session/:id — manually destroy a persistent Chrome session.
pub async fn destroy_session_handler(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Some(ref proxy) = state.gobrowser_proxy {
        match proxy.delete(&format!("/session/{session_id}")).await {
            Ok((status, resp)) => (
                StatusCode::from_u16(status).unwrap_or(StatusCode::NOT_FOUND),
                Json(resp),
            ),
            Err(e) => (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": e})),
            ),
        }
    } else {
        let destroyed = state.session_pool.destroy(&session_id).await;
        if destroyed {
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "destroyed", "session_id": session_id})),
            )
        } else {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "session not found", "session_id": session_id})),
            )
        }
    }
}
