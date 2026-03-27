//! POST /twitter/login — headless Chrome Twitter login endpoint.

use std::collections::HashMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Deserialize)]
pub struct TwitterLoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub proxy: Option<String>,
}

#[derive(Serialize)]
pub struct TwitterLoginResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ct0: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookies: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screenshot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

pub async fn twitter_login(
    State(state): State<AppState>,
    Json(req): Json<TwitterLoginRequest>,
) -> impl IntoResponse {
    tracing::info!(username = %req.username, "twitter login request");

    let login_req = ox_twitter::login::LoginRequest {
        username: req.username,
        password: req.password,
        email: req.email,
        phone: req.phone,
        totp_secret: req.totp_secret,
        proxy: req.proxy,
        chrome_path: None,
    };

    match ox_twitter::login::login(&login_req, &state.twitter_config, &state.twitter_semaphore, &state.session_pool).await {
        Ok(result) => (
            StatusCode::OK,
            Json(TwitterLoginResponse {
                status: "ok".into(),
                auth_token: Some(result.auth_token),
                ct0: Some(result.ct0),
                cookies: Some(result.cookies),
                user_agent: Some(result.user_agent),
                error: None,
                message: None,
                screenshot: None,
                method: Some(result.method),
            }),
        ),
        Err(e) => {
            let status = match &e {
                ox_twitter::login::TwitterLoginError::WrongCredentials { .. } => StatusCode::UNAUTHORIZED,
                ox_twitter::login::TwitterLoginError::AccountLocked { .. } => StatusCode::FORBIDDEN,
                ox_twitter::login::TwitterLoginError::CaptchaRequired { .. } => StatusCode::UNPROCESSABLE_ENTITY,
                ox_twitter::login::TwitterLoginError::BotDetected { .. } => StatusCode::FORBIDDEN,
                ox_twitter::login::TwitterLoginError::MissingEmail => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            tracing::warn!(error = %e, code = %e.error_code(), "twitter login failed");

            (
                status,
                Json(TwitterLoginResponse {
                    status: "error".into(),
                    auth_token: None,
                    ct0: None,
                    cookies: None,
                    user_agent: None,
                    error: Some(e.error_code().into()),
                    message: Some(e.to_string()),
                    screenshot: e.screenshot().map(|p| p.display().to_string()),
                    method: None,
                }),
            )
        }
    }
}
