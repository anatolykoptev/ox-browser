//! Core login flow state machine — drives Chrome through Twitter's multi-step login.

pub(super) mod actions;
mod detect;
mod helpers;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use chromiumoxide::Page;
use tokio::time::Instant;

use super::error::{FlowStep, TwitterLoginError};
use super::human::{HumanBehavior, Speed};
use super::selectors;

pub(super) const LOGIN_URL: &str = "https://x.com/i/flow/login";
pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(300);
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

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

/// State machine that drives Chrome through the Twitter login flow.
pub struct LoginFlow<'a> {
    pub(super) page: &'a Page,
    pub(super) input: &'a LoginInput,
    pub(super) human: HumanBehavior,
    pub(super) screenshot_dir: PathBuf,
    pub(super) screenshot_on_error: bool,
    pub(super) step_timeout: Duration,
    pub(super) deadline: Instant,
}

impl<'a> LoginFlow<'a> {
    pub fn new(
        page: &'a Page,
        input: &'a LoginInput,
        screenshot_dir: PathBuf,
        screenshot_on_error: bool,
        total_timeout: Duration,
    ) -> Self {
        Self {
            page,
            input,
            human: HumanBehavior::new(),
            screenshot_dir,
            screenshot_on_error,
            step_timeout: STEP_TIMEOUT,
            deadline: Instant::now() + total_timeout,
        }
    }

    /// Execute the full login flow, returning cookies on success.
    pub async fn run(&mut self) -> Result<LoginOutput, TwitterLoginError> {
        self.navigate().await?;

        self.take_error_screenshot("step1-before-username").await;
        self.enter_username().await?;
        tracing::info!("chrome: username entered");

        self.take_error_screenshot("step2-after-username").await;
        self.click_next_button().await?;
        tracing::info!("chrome: next clicked");

        self.take_error_screenshot("step3-after-next").await;
        self.handle_post_username().await?;
        tracing::info!("chrome: post-username handled");

        self.enter_password().await?;
        tracing::info!("chrome: password entered");
        self.click_login_button().await?;
        tracing::info!("chrome: login clicked");
        self.handle_post_login().await?;
        self.extract_cookies().await
    }

    // --- Navigation ---

    async fn navigate(&mut self) -> Result<(), TwitterLoginError> {
        // Step 1: Visit x.com first to get cookies (avoids bot detection).
        tracing::info!("chrome login: pre-navigating to x.com");
        self.page
            .goto("https://x.com")
            .await
            .map_err(|e| TwitterLoginError::Navigation(format!("pre-nav x.com: {e}")))?;

        let pause = self.human.page_load_pause(); // 1-3s random
        tokio::time::sleep(pause).await;
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Step 2: Navigate to login page.
        tracing::info!("chrome login: navigating to login page");
        self.page
            .goto(LOGIN_URL)
            .await
            .map_err(|e| TwitterLoginError::Navigation(e.to_string()))?;

        let pause = self.human.page_load_pause();
        tokio::time::sleep(pause).await;
        Ok(())
    }

    // --- Username step ---

    async fn enter_username(&mut self) -> Result<(), TwitterLoginError> {
        let el = self
            .wait_for_element(selectors::USERNAME_INPUT, FlowStep::Username)
            .await?;

        // Click to establish browser-level focus
        el.click().await.ok();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Type using native DispatchKeyEvent (works in headless Chrome)
        self.type_human(selectors::USERNAME_INPUT, &self.input.username.clone(), Speed::Fast)
            .await?;

        Ok(())
    }

    // --- Password step ---

    async fn enter_password(&mut self) -> Result<(), TwitterLoginError> {
        self.wait_for_element(selectors::PASSWORD_INPUT, FlowStep::Password)
            .await?;

        self.focus_and_clear(selectors::PASSWORD_INPUT).await?;

        let pause = self.human.reading_pause();
        tokio::time::sleep(pause).await;

        self.type_human(selectors::PASSWORD_INPUT, &self.input.password.clone(), Speed::Slow)
            .await?;

        Ok(())
    }
}
