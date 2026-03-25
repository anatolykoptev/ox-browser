//! Helper methods for the login flow: typing, element queries, screenshots, TOTP.

use std::path::PathBuf;

use chromiumoxide::cdp::browser_protocol::input::{DispatchKeyEventParams, DispatchKeyEventType};
use tokio::time::Instant;

use super::super::chrome::ChromeSession;
use super::super::error::{FlowStep, TwitterLoginError};
use super::super::human::Speed;
use super::super::selectors;
use super::{LoginFlow, POLL_INTERVAL};

impl<'a> LoginFlow<'a> {
    pub(super) async fn type_human(
        &mut self,
        text: &str,
        speed: Speed,
    ) -> Result<(), TwitterLoginError> {
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

    pub(super) async fn wait_for_element(
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

    /// Wait for a page navigation event, with a short timeout.
    /// Twitter is an SPA — navigation events may or may not fire.
    /// Returns Ok(true) if navigation fired, Ok(false) if timeout.
    pub(super) async fn wait_for_navigation_or_timeout(&self) -> bool {
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.page.wait_for_navigation(),
        )
        .await
        {
            Ok(Ok(_)) => {
                tracing::debug!("navigation event received");
                true
            }
            _ => {
                tracing::debug!("navigation timeout (SPA transition)");
                false
            }
        }
    }

    pub(super) async fn element_exists(&self, selector: &str) -> bool {
        self.page.find_element(selector).await.is_ok()
    }

    pub(super) async fn is_on_home(&self) -> bool {
        self.page
            .evaluate(selectors::JS_CHECK_HOME_URL)
            .await
            .ok()
            .and_then(|r| r.into_value::<bool>().ok())
            .unwrap_or(false)
    }

    pub(super) async fn read_error_message(&self) -> Option<String> {
        let el = self.page.find_element(selectors::ERROR_MESSAGE).await.ok()?;
        let text = el.inner_text().await.ok()??;
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    pub(super) async fn check_deadline(
        &self,
        step: FlowStep,
    ) -> Result<(), TwitterLoginError> {
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

    pub(super) fn step_deadline(&self) -> Instant {
        let step = Instant::now() + self.step_timeout;
        // Don't exceed the overall deadline
        step.min(self.deadline)
    }

    pub(super) async fn take_error_screenshot(&self, label: &str) -> Option<PathBuf> {
        if self.screenshot_on_error {
            ChromeSession::screenshot(self.page, &self.screenshot_dir, label).await
        } else {
            None
        }
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

/// Generate a TOTP code from a base32-encoded secret.
pub(super) fn generate_totp(secret_b32: &str) -> Result<String, TwitterLoginError> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let secret_bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| TwitterLoginError::TotpFailed(format!("bad base32 secret: {e}")))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
        .map_err(|e| TwitterLoginError::TotpFailed(format!("TOTP init: {e}")))?;

    let code = totp
        .generate_current()
        .map_err(|e| TwitterLoginError::TotpFailed(format!("TOTP generate: {e}")))?;

    Ok(code)
}
