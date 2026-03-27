//! Post-username and post-login detection/branching logic.

use tokio::time::Instant;

use super::super::error::{FlowStep, TwitterLoginError};
use super::super::human::Speed;
use super::super::selectors;
use super::actions::generate_totp;
use super::{LoginFlow, POLL_INTERVAL};

impl<'a> LoginFlow<'a> {
    // --- Post-username detection ---

    pub(super) async fn handle_post_username(&mut self) -> Result<(), TwitterLoginError> {
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

            // Check for bot detection toast (399 "Could not log you in")
            if let Ok(val) = self.eval_isolated(selectors::JS_DETECT_TOAST).await {
                if let Some(msg) = val.as_str() {
                    if !msg.is_empty() {
                        let screenshot = self.take_error_screenshot("bot-detected").await;
                        return Err(TwitterLoginError::BotDetected {
                            message: msg.to_string(),
                            screenshot,
                        });
                    }
                }
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    async fn handle_ocf_screen(&mut self) -> Result<(), TwitterLoginError> {
        // Read heading to disambiguate (isolated world to avoid detection)
        let heading: String = self
            .eval_isolated(selectors::JS_READ_HEADING)
            .await
            .ok()
            .and_then(|v| v.as_str().map(String::from))
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

            self.wait_for_element(selectors::OCF_TEXT_INPUT, FlowStep::DetectScreen)
                .await?;
            self.focus_and_clear(selectors::OCF_TEXT_INPUT).await?;

            let val = confirm_value.to_string();
            self.type_human(selectors::OCF_TEXT_INPUT, &val, Speed::Fast).await?;

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

    // --- Post-login detection ---

    pub(super) async fn handle_post_login(&mut self) -> Result<(), TwitterLoginError> {
        let step_deadline = self.step_deadline();

        loop {
            self.check_deadline(FlowStep::DetectPostLogin).await?;
            if Instant::now() > step_deadline {
                let screenshot = self.take_error_screenshot("post-login-timeout").await;
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
                let screenshot = self.take_error_screenshot("post-login-error").await;
                return Err(TwitterLoginError::WrongCredentials {
                    message: msg,
                    screenshot,
                });
            }

            // Check for account locked (via heading, isolated world)
            let heading: String = self
                .eval_isolated(selectors::JS_READ_HEADING)
                .await
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default();
            let h = heading.to_lowercase();
            if h.contains("locked") || h.contains("suspended") {
                let screenshot = self.take_error_screenshot("account-locked").await;
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

        self.wait_for_element(selectors::OCF_TEXT_INPUT, FlowStep::TwoFactor)
            .await?;
        self.focus_and_clear(selectors::OCF_TEXT_INPUT).await?;

        let pause = self.human.reading_pause();
        tokio::time::sleep(pause).await;

        self.type_human(selectors::OCF_TEXT_INPUT, &code, Speed::Slow).await?;

        // Click Next/Verify button (isolated world to avoid detection)
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
        self.eval_isolated(js_click).await.ok();

        // Wait for navigation after 2FA submit
        self.wait_for_navigation_or_timeout().await;
        let pause = self.human.pre_click_delay();
        tokio::time::sleep(pause).await;

        // Wait for home page after 2FA
        self.wait_for_home().await
    }

    pub(super) async fn wait_for_home(&mut self) -> Result<(), TwitterLoginError> {
        let step_deadline = self.step_deadline();

        loop {
            self.check_deadline(FlowStep::WaitHome).await?;
            if Instant::now() > step_deadline {
                let screenshot = self.take_error_screenshot("wait-home-timeout").await;
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
}

