//! POST /media/download endpoint.

use axum::http::StatusCode;
use axum::{Json, extract::State};
use ox_media::{MediaError, MediaRequest, MediaResult};

use super::AppState;
use crate::inbound_auth::InboundAuth;

pub async fn media_download(
    State(state): State<AppState>,
    auth: InboundAuth,
    Json(req): Json<MediaRequest>,
) -> Result<Json<MediaResult>, (StatusCode, Json<serde_json::Value>)> {
    // ox-browser#177 / SEC-CR-018: `client_for` stamps the gate's
    // `ok_secret` decision — see `fetch`.
    let http = state.client_for(auth);
    match ox_media::download(&http, &req, &state.media_config).await {
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
