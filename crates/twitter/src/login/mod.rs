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

/// Perform Twitter login via headless Chrome.
///
/// Launches Chrome, navigates to Twitter login page, enters credentials
/// with human-like behavior, handles 2FA, extracts auth cookies.
/// Browser is always cleaned up regardless of success/failure.
pub async fn login(
    req: &LoginRequest,
    config: &TwitterLoginConfig,
    semaphore: &Semaphore,
) -> Result<LoginResult, TwitterLoginError> {
    let _permit = semaphore.acquire().await.map_err(|e| {
        TwitterLoginError::ChromeLaunch(format!("semaphore closed: {e}"))
    })?;

    tracing::info!(username = %req.username, "starting Twitter login flow");

    let chrome_config = ChromeLoginConfig {
        proxy_url: req.proxy.clone().or_else(|| config.default_proxy.clone()),
        chrome_path: req.chrome_path.clone().or_else(|| config.default_chrome_path.clone()),
        screenshot_dir: config.screenshot_dir.clone(),
        screenshot_on_error: config.screenshot_on_error,
    };

    let (session, page) = ChromeSession::launch(&chrome_config)
        .await
        .map_err(TwitterLoginError::ChromeLaunch)?;

    let input = flow::LoginInput {
        username: req.username.clone(),
        password: req.password.clone(),
        email: req.email.clone(),
        phone: req.phone.clone(),
        totp_secret: req.totp_secret.clone(),
    };

    let mut login_flow = flow::LoginFlow::new(
        &page,
        &input,
        config.screenshot_dir.clone(),
        config.screenshot_on_error,
        config.timeout,
    );

    let result = login_flow.run().await;

    // Always cleanup Chrome
    session.shutdown().await;

    let output = result?;
    tracing::info!(username = %req.username, "login successful");

    Ok(LoginResult {
        auth_token: output.auth_token,
        ct0: output.ct0,
        cookies: output.cookies,
        user_agent: output.user_agent,
    })
}
