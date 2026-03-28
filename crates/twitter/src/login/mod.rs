pub mod api_login;
mod api_flow;
mod api_headers;
mod api_preseed; // kept for future use
mod castle;
mod ui_metrics;
mod api_subtasks;
pub mod error;
pub mod human;
pub mod selectors;

pub use error::{FlowStep, TwitterLoginError};
pub use human::HumanBehavior;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Credentials and optional 2FA secret for login.
pub struct LoginInput {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub totp_secret: Option<String>,
}

/// Successful login result with session cookies.
pub struct LoginOutput {
    pub auth_token: String,
    pub ct0: String,
    pub cookies: HashMap<String, String>,
    pub user_agent: String,
}

/// Request to perform a Twitter login via headless Chrome.
#[derive(Debug, Clone)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub totp_secret: Option<String>,
    pub proxy: Option<String>,
    pub chrome_path: Option<String>,
}

/// Successful login result with extracted cookies.
#[derive(Debug, Clone)]
pub struct LoginResult {
    pub auth_token: String,
    pub ct0: String,
    pub cookies: HashMap<String, String>,
    pub user_agent: String,
    pub method: String,
}

/// Runtime config for the login endpoint.
#[derive(Debug, Clone)]
pub struct TwitterLoginConfig {
    pub timeout: Duration,
    pub max_concurrent: usize,
    pub screenshot_on_error: bool,
    pub screenshot_dir: PathBuf,
    pub default_chrome_path: Option<String>,
    pub default_proxy: Option<String>,
}

impl Default for TwitterLoginConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(90),
            max_concurrent: 1,
            screenshot_on_error: true,
            screenshot_dir: PathBuf::from("/tmp/ox-browser/twitter-login"),
            default_chrome_path: None,
            default_proxy: None,
        }
    }
}

/// Perform Twitter login via API.
///
/// Chrome-based login has been removed — all Chrome operations are now
/// delegated to go-browser. Only API login is available.
pub async fn login(
    req: &LoginRequest,
    _config: &TwitterLoginConfig,
    _semaphore: &Semaphore,
) -> Result<LoginResult, TwitterLoginError> {
    match api_login::login(req).await {
        Ok(result) => {
            tracing::info!(username = %req.username, "API login successful");
            Ok(LoginResult {
                auth_token: result.auth_token,
                ct0: result.ct0,
                cookies: result.cookies,
                user_agent: crate::TWITTER_USER_AGENT.to_string(),
                method: "api".into(),
            })
        }
        Err(e) => {
            tracing::warn!(username = %req.username, error = %e, "API login failed");
            Err(e)
        }
    }
}

/// Generate a TOTP code from a base32-encoded secret.
pub fn generate_totp(secret_b32: &str) -> Result<String, TwitterLoginError> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let secret_bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| TwitterLoginError::TotpFailed(format!("bad base32 secret: {e}")))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
        .map_err(|e| TwitterLoginError::TotpFailed(format!("TOTP init: {e}")))?;

    totp.generate_current()
        .map_err(|e| TwitterLoginError::TotpFailed(format!("TOTP generate: {e}")))
}
