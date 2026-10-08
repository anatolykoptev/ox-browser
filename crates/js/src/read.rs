//! POST /read — unified content extraction.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use ox_http::content::ReadParams;
use ox_http::read_pipeline;

use super::AppState;
use crate::inbound_auth::InboundAuth;

pub async fn read(
    State(state): State<AppState>,
    auth: InboundAuth,
    Json(params): Json<ReadParams>,
) -> (StatusCode, Json<ox_http::content::ReadOutput>) {
    // SEC-CR-002: only an authenticated caller may trigger the credentialed
    // chrome fallback (see read_pipeline). SEC-CR-018: the decision arrives
    // stamped on the `client_for` client — there is no separate flag here
    // for a caller to force `true`.
    let http = state.client_for(auth);
    let output = read_pipeline::read_page(&http, &params, &state.site_handlers).await;

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
