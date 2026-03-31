//! POST /security — passive security audit with Observatory-compatible scoring.

use std::collections::HashMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
pub struct SecurityRequest {
    pub url: String,
}

pub async fn security_scan(
    State(state): State<AppState>,
    Json(req): Json<SecurityRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let resp = match state.http_client.get(&req.url).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": e.to_string()})),
            );
        }
    };

    let headers: HashMap<String, String> = resp
        .headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.to_string().to_lowercase(), val.to_owned()))
        })
        .collect();

    let set_cookie_headers: Vec<String> = resp
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_owned()))
        .collect();

    let report = ox_security::analyze_security(
        &req.url, &headers, &set_cookie_headers, &resp.body, ox_security::ScanMode::Public,
    );

    let json = serde_json::to_value(&report).unwrap_or_default();
    (StatusCode::OK, Json(json))
}
