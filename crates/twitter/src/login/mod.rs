pub mod api_login;
mod api_flow;
mod api_headers;
mod api_preseed; // kept for future use
mod castle;
mod ui_metrics;
mod api_subtasks;
pub mod chrome;
pub mod error;
pub mod flow;
pub mod human;
pub mod selectors;

pub use error::{FlowStep, TwitterLoginError};
pub use human::HumanBehavior;
pub use chrome::{ChromeLoginConfig, ChromeSession};
pub use flow::{LoginInput, LoginOutput};

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::Semaphore;

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

/// Perform Twitter login with API→Chrome fallback.
///
/// First tries fast API login (no Chrome needed). If API login fails
/// with a non-permanent error, falls back to headless Chrome login.
/// Permanent errors (wrong credentials, locked, missing email) fail immediately.
pub async fn login(
    req: &LoginRequest,
    config: &TwitterLoginConfig,
    semaphore: &Semaphore,
    pool: &ox_http::SessionPool,
) -> Result<LoginResult, TwitterLoginError> {
    // Primary: API login (fast, no Chrome)
    match api_login::login(req).await {
        Ok(result) => {
            tracing::info!(username = %req.username, "API login successful");
            return Ok(LoginResult {
                auth_token: result.auth_token,
                ct0: result.ct0,
                cookies: result.cookies,
                user_agent: crate::TWITTER_USER_AGENT.to_string(),
                method: "api".into(),
            });
        }
        Err(e) if e.is_permanent() => {
            tracing::warn!(username = %req.username, error = %e, "API login permanently failed");
            return Err(e);
        }
        Err(e) => {
            tracing::warn!(username = %req.username, error = %e, "API login failed, trying Chrome");
        }
    }

    // Fallback: Chrome login
    let _permit = semaphore.acquire().await.map_err(|e| {
        TwitterLoginError::ChromeLaunch(format!("semaphore closed: {e}"))
    })?;
    tracing::info!(username = %req.username, "starting Chrome login fallback");
    chrome_login(req, config, pool).await
}

async fn chrome_login(
    req: &LoginRequest,
    config: &TwitterLoginConfig,
    pool: &ox_http::SessionPool,
) -> Result<LoginResult, TwitterLoginError> {
    // Use the pool to get cookie persistence and Castle.io JS execution.
    let proxy = req.proxy.as_deref().or(config.default_proxy.as_deref());
    let session_id = pool.create(proxy).await
        .map_err(TwitterLoginError::ChromeLaunch)?;

    let page = pool.get(&session_id).await
        .ok_or_else(|| TwitterLoginError::ChromeLaunch("session lost after create".into()))?;

    let input = flow::LoginInput {
        username: req.username.clone(),
        password: req.password.clone(),
        email: req.email.clone(),
        phone: req.phone.clone(),
        totp_secret: req.totp_secret.clone(),
    };

    let mut login_flow = flow::LoginFlow::new(
        &page, &input,
        config.screenshot_dir.clone(),
        config.screenshot_on_error,
        config.timeout,
    );

    let result = login_flow.run().await;

    // Always destroy pool session after login (success or fail).
    pool.destroy(&session_id).await;

    let output = result?;

    tracing::info!(username = %req.username, "Chrome login successful");
    Ok(LoginResult {
        auth_token: output.auth_token,
        ct0: output.ct0,
        cookies: output.cookies,
        user_agent: output.user_agent,
        method: "chrome".into(),
    })
}
