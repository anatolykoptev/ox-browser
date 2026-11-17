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
    // Supplied HTML: no client is built, no handler runs — the entry point
    // takes no transport at all (structural "no network").
    if params.html.is_some() {
        return match read_pipeline::read_supplied(&params).await {
            Ok(output) => (StatusCode::OK, Json(output)),
            Err(e) => (
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::BAD_REQUEST),
                Json(read_pipeline::build_error_output(
                    &params,
                    "supplied",
                    0,
                    &e.to_string(),
                )),
            ),
        };
    }
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
