//! Core login flow state machine — drives Chrome through Twitter's multi-step login.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use chromiumoxide::cdp::browser_protocol::input::{DispatchKeyEventParams, DispatchKeyEventType};
use chromiumoxide::Page;
use tokio::time::Instant;

use super::chrome::ChromeSession;
use super::error::{FlowStep, TwitterLoginError};
use super::human::{HumanBehavior, Speed};
use super::selectors;

const LOGIN_URL: &str = "https://x.com/i/flow/login";
const POLL_INTERVAL: Duration = Duration::from_millis(300);
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
    page: &'a Page,
    input: &'a LoginInput,
    human: HumanBehavior,
    screenshot_dir: PathBuf,
    screenshot_on_error: bool,
    step_timeout: Duration,
    deadline: Instant,
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
        self.enter_username().await?;
        self.click_next_button().await?;
        self.handle_post_username().await?;
        self.enter_password().await?;
        self.click_login_button().await?;
        self.handle_post_login().await?;
        self.extract_cookies().await
    }

    // --- Navigation ---

    async fn navigate(&mut self) -> Result<(), TwitterLoginError> {
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

        el.click().await.map_err(|_| TwitterLoginError::ElementNotFound {
            selector: selectors::USERNAME_INPUT.to_string(),
            step: FlowStep::Username,
            screenshot: None,
        })?;

        let pause = self.human.reading_pause();
        tokio::time::sleep(pause).await;

        self.type_human(&self.input.username.clone(), Speed::Fast)
            .await?;

        Ok(())
    }

    async fn click_next_button(&mut self) -> Result<(), TwitterLoginError> {
        let pause = self.human.pre_click_delay();
        tokio::time::sleep(pause).await;

        // Click Next button via JS (text matching needed)
        let js_click = r#"
            (() => {
                const btns = document.querySelectorAll('button[role="button"]');
                for (const b of btns) {
                    if (b.textContent.trim() === 'Next') { b.click(); return true; }
                }
                return false;
            })()
        "#;

        let clicked: bool = self
            .page
            .evaluate(js_click)
            .await
            .map_err(|_| TwitterLoginError::ElementNotFound {
                selector: "Next button click".to_string(),
                step: FlowStep::ClickNext,
                screenshot: None,
            })?
            .into_value()
            .unwrap_or(false);

        if !clicked {
            let screenshot = self.take_error_screenshot("click-next-failed").await;
            return Err(TwitterLoginError::ElementNotFound {
                selector: "Next button".to_string(),
                step: FlowStep::ClickNext,
                screenshot,
            });
        }

        let pause = self.human.reading_pause();
        tokio::time::sleep(pause).await;
        Ok(())
    }

    // --- Post-username detection ---

    async fn handle_post_username(&mut self) -> Result<(), TwitterLoginError> {
        let step_deadline = self.step_deadline();

        loop {
            self.check_deadline(FlowStep::DetectScreen).await?;
            if Instant::now() > step_deadline {
                let screenshot = self.take_error_screenshot("detect-screen-timeout").await;
                return Err(TwitterLoginError::Timeout {
                    step: FlowStep::DetectScreen,
                    screenshot,
                });
            }

            // Check for password input — normal flow
            if self.element_exists(selectors::PASSWORD_INPUT).await {
                return Ok(());
            }

            // Check for OCF text input — username confirmation or 2FA
            if self.element_exists(selectors::OCF_TEXT_INPUT).await {
                return self.handle_ocf_screen().await;
            }

            // Check for error message
            if let Some(msg) = self.read_error_message().await {
                let screenshot = self.take_error_screenshot("post-username-error").await;
                return Err(TwitterLoginError::WrongCredentials {
                    message: msg,
                    screenshot,
                });
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    async fn handle_ocf_screen(&mut self) -> Result<(), TwitterLoginError> {
        // Read heading to disambiguate
        let heading: String = self
            .page
            .evaluate(selectors::JS_READ_HEADING)
            .await
            .ok()
            .and_then(|r| r.into_value().ok())
            .unwrap_or_default();

        let heading_lower = heading.to_lowercase();

        // If heading mentions phone/email/username confirmation
        if heading_lower.contains("phone")
            || heading_lower.contains("email")
            || heading_lower.contains("enter your")
            || heading_lower.contains("verify")
        {
            let confirm_value = self
                .input
                .email
                .as_deref()
                .or(self.input.phone.as_deref())
                .ok_or(TwitterLoginError::MissingEmail)?;

            let el = self
                .wait_for_element(selectors::OCF_TEXT_INPUT, FlowStep::DetectScreen)
                .await?;
            el.click().await.ok();

            let val = confirm_value.to_string();
            self.type_human(&val, Speed::Fast).await?;

            // Click Next again
            self.click_next_button().await?;

            // Now wait for password input
            self.wait_for_element(selectors::PASSWORD_INPUT, FlowStep::Password)
                .await?;
            return Ok(());
        }

        // Otherwise it might be an unexpected screen
        let screenshot = self.take_error_screenshot("unknown-ocf-screen").await;
        Err(TwitterLoginError::ElementNotFound {
            selector: format!("unknown OCF screen: {heading}"),
            step: FlowStep::DetectScreen,
            screenshot,
        })
    }

    // --- Password step ---

    async fn enter_password(&mut self) -> Result<(), TwitterLoginError> {
        let el = self
            .wait_for_element(selectors::PASSWORD_INPUT, FlowStep::Password)
            .await?;

        el.click().await.ok();

        let pause = self.human.reading_pause();
        tokio::time::sleep(pause).await;

        self.type_human(&self.input.password.clone(), Speed::Slow)
            .await?;

        Ok(())
    }

    async fn click_login_button(&mut self) -> Result<(), TwitterLoginError> {
        let pause = self.human.pre_click_delay();
        tokio::time::sleep(pause).await;

        let el = self
            .wait_for_element(selectors::LOGIN_BUTTON, FlowStep::ClickLogin)
            .await?;

        el.click()
            .await
            .map_err(|_| TwitterLoginError::ElementNotFound {
                selector: selectors::LOGIN_BUTTON.to_string(),
                step: FlowStep::ClickLogin,
                screenshot: None,
            })?;

        let pause = self.human.reading_pause();
        tokio::time::sleep(pause).await;
        Ok(())
    }

    // --- Post-login detection ---

    async fn handle_post_login(&mut self) -> Result<(), TwitterLoginError> {
        let step_deadline = self.step_deadline();

        loop {
            self.check_deadline(FlowStep::DetectPostLogin).await?;
            if Instant::now() > step_deadline {
                let screenshot =
                    self.take_error_screenshot("post-login-timeout").await;
                return Err(TwitterLoginError::Timeout {
                    step: FlowStep::DetectPostLogin,
                    screenshot,
                });
            }

            // Check for home page
            if self.is_on_home().await {
                return Ok(());
            }

            // Check for 2FA input
            if self.element_exists(selectors::OCF_TEXT_INPUT).await {
                return self.handle_two_factor().await;
            }

            // Check for error
            if let Some(msg) = self.read_error_message().await {
                let screenshot =
                    self.take_error_screenshot("post-login-error").await;
                return Err(TwitterLoginError::WrongCredentials {
                    message: msg,
                    screenshot,
                });
            }

            // Check for account locked
            let page_text: String = self
                .page
                .evaluate("document.body.innerText || ''")
                .await
                .ok()
                .and_then(|r| r.into_value().ok())
                .unwrap_or_default();

            if page_text.to_lowercase().contains("account is locked")
                || page_text.to_lowercase().contains("suspended")
            {
                let screenshot =
                    self.take_error_screenshot("account-locked").await;
                return Err(TwitterLoginError::AccountLocked { screenshot });
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    async fn handle_two_factor(&mut self) -> Result<(), TwitterLoginError> {
        let secret = self
            .input
            .totp_secret
            .as_deref()
            .ok_or_else(|| TwitterLoginError::TotpFailed("no TOTP secret provided".into()))?;

        let code = generate_totp(secret)?;

        let el = self
            .wait_for_element(selectors::OCF_TEXT_INPUT, FlowStep::TwoFactor)
            .await?;
        el.click().await.ok();

        let pause = self.human.reading_pause();
        tokio::time::sleep(pause).await;

        self.type_human(&code, Speed::Slow).await?;

        // Click Next/Verify button
        let js_click = r#"
            (() => {
                const btns = document.querySelectorAll('button[role="button"]');
                for (const b of btns) {
                    const t = b.textContent.trim().toLowerCase();
                    if (t === 'next' || t === 'verify') { b.click(); return true; }
                }
                return false;
            })()
        "#;
        self.page.evaluate(js_click).await.ok();

        let pause = self.human.reading_pause();
        tokio::time::sleep(pause).await;

        // Wait for home page after 2FA
        self.wait_for_home().await
    }

    async fn wait_for_home(&mut self) -> Result<(), TwitterLoginError> {
        let step_deadline = self.step_deadline();

        loop {
            self.check_deadline(FlowStep::WaitHome).await?;
            if Instant::now() > step_deadline {
                let screenshot =
                    self.take_error_screenshot("wait-home-timeout").await;
                return Err(TwitterLoginError::Timeout {
                    step: FlowStep::WaitHome,
                    screenshot,
                });
            }

            if self.is_on_home().await {
                return Ok(());
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    // --- Cookie extraction ---

    async fn extract_cookies(&self) -> Result<LoginOutput, TwitterLoginError> {
        let cookies = self
            .page
            .get_cookies()
            .await
            .map_err(|_| TwitterLoginError::CookiesNotFound)?;

        let mut cookie_map = HashMap::new();
        let mut auth_token = None;
        let mut ct0 = None;

        for c in &cookies {
            cookie_map.insert(c.name.clone(), c.value.clone());
            if c.name == "auth_token" {
                auth_token = Some(c.value.clone());
            }
            if c.name == "ct0" {
                ct0 = Some(c.value.clone());
            }
        }

        let auth_token = auth_token.ok_or(TwitterLoginError::CookiesNotFound)?;
        let ct0 = ct0.ok_or(TwitterLoginError::CookiesNotFound)?;

        Ok(LoginOutput {
            auth_token,
            ct0,
            cookies: cookie_map,
            user_agent: super::chrome::STEALTH_UA.to_string(),
        })
    }

    // --- Helpers ---

    async fn type_human(&mut self, text: &str, speed: Speed) -> Result<(), TwitterLoginError> {
        for ch in text.chars() {
            let key_str = ch.to_string();

            // KeyDown with text
            let down = DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::KeyDown)
                .text(&key_str)
                .key(&key_str)
                .build()
                .unwrap();
            self.page
                .execute(down)
                .await
                .map_err(|e| TwitterLoginError::Navigation(format!("key down: {e}")))?;

            // KeyUp
            let up = DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::KeyUp)
                .key(&key_str)
                .build()
                .unwrap();
            self.page
                .execute(up)
                .await
                .map_err(|e| TwitterLoginError::Navigation(format!("key up: {e}")))?;

            let delay = self.human.char_delay(speed);
            tokio::time::sleep(delay).await;

            if self.human.should_micro_pause() {
                let pause = self.human.micro_pause_delay();
                tokio::time::sleep(pause).await;
            }
        }
        Ok(())
    }

    async fn wait_for_element(
        &mut self,
        selector: &str,
        step: FlowStep,
    ) -> Result<chromiumoxide::element::Element, TwitterLoginError> {
        let step_deadline = self.step_deadline();

        loop {
            self.check_deadline(step).await?;
            if Instant::now() > step_deadline {
                let label = format!("wait-element-{step}");
                let screenshot = self.take_error_screenshot(&label).await;
                return Err(TwitterLoginError::Timeout {
                    step,
                    screenshot,
                });
            }

            match self.page.find_element(selector).await {
                Ok(el) => return Ok(el),
                Err(_) => tokio::time::sleep(POLL_INTERVAL).await,
            }
        }
    }

    async fn element_exists(&self, selector: &str) -> bool {
        self.page.find_element(selector).await.is_ok()
    }

    async fn is_on_home(&self) -> bool {
        self.page
            .evaluate(selectors::JS_CHECK_HOME_URL)
            .await
            .ok()
            .and_then(|r| r.into_value::<bool>().ok())
            .unwrap_or(false)
    }

    async fn read_error_message(&self) -> Option<String> {
        let el = self.page.find_element(selectors::ERROR_MESSAGE).await.ok()?;
        let text = el.inner_text().await.ok()??;
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    async fn check_deadline(&self, step: FlowStep) -> Result<(), TwitterLoginError> {
        if Instant::now() > self.deadline {
            let screenshot = if self.screenshot_on_error {
                ChromeSession::screenshot(
                    self.page,
                    &self.screenshot_dir,
                    &format!("deadline-{step}"),
                )
                .await
            } else {
                None
            };
            return Err(TwitterLoginError::Timeout { step, screenshot });
        }
        Ok(())
    }

    fn step_deadline(&self) -> Instant {
        let step = Instant::now() + self.step_timeout;
        // Don't exceed the overall deadline
        step.min(self.deadline)
    }

    async fn take_error_screenshot(&self, label: &str) -> Option<PathBuf> {
        if self.screenshot_on_error {
            ChromeSession::screenshot(self.page, &self.screenshot_dir, label).await
        } else {
            None
        }
    }
}

/// Generate a TOTP code from a base32-encoded secret.
fn generate_totp(secret_b32: &str) -> Result<String, TwitterLoginError> {
    use totp_rs::{Algorithm, TOTP};

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_b32.as_bytes().to_vec())
        .map_err(|e| TwitterLoginError::TotpFailed(format!("TOTP init: {e}")))?;

    let code = totp
        .generate_current()
        .map_err(|e| TwitterLoginError::TotpFailed(format!("TOTP generate: {e}")))?;

    Ok(code)
}
