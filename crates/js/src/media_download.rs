//! POST /media/download endpoint.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use ox_media::{MediaError, MediaRequest, MediaResult};

use super::AppState;

pub async fn media_download(
    State(state): State<AppState>,
    Json(req): Json<MediaRequest>,
) -> Result<Json<MediaResult>, (StatusCode, Json<serde_json::Value>)> {
    match ox_media::download(&state.http_client, &req, &state.media_config).await {
        Ok(result) => Ok(Json(result)),
        Err(e) => {
            let status = match &e {
                MediaError::SizeExceeded(_) => StatusCode::PAYLOAD_TOO_LARGE,
                MediaError::FetchFailed(_) => StatusCode::BAD_GATEWAY,
                _ => StatusCode::UNPROCESSABLE_ENTITY,
            };
            Err((
                status,
                Json(serde_json::json!({
                    "error": e.to_string()
                })),
            ))
        }
    }
}
