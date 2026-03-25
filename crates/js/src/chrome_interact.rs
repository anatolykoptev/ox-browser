//! POST /chrome/interact — headless Chrome page interaction.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ox_http::chrome_interact::{self, InteractRequest, InteractResponse};

use super::AppState;

pub async fn chrome_interact_handler(
    State(state): State<AppState>,
    Json(req): Json<InteractRequest>,
) -> (StatusCode, Json<InteractResponse>) {
    let resp = chrome_interact::execute(req, &state.chrome_config, &state.chrome_semaphore).await;
    let status = if resp.error.is_some() {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::OK
    };
    (status, Json(resp))
}
