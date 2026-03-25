//! Button click and cookie extraction actions for the login flow.

use std::collections::HashMap;

use super::super::chrome::STEALTH_UA;
use super::super::error::{FlowStep, TwitterLoginError};
use super::super::selectors;
use super::{LoginFlow, LoginOutput};

impl<'a> LoginFlow<'a> {
    pub(super) async fn click_next_button(&mut self) -> Result<(), TwitterLoginError> {
        let pause = self.human.pre_click_delay();
        tokio::time::sleep(pause).await;

        // Find Next button by text, click via CDP mouse
        let mut clicked = false;
        if let Ok(elements) = self.page.find_elements(r#"button[role="button"]"#).await {
            for el in &elements {
                if let Ok(Some(text)) = el.inner_text().await {
                    if text.trim() == "Next" {
                        el.click().await.ok();
                        clicked = true;
                        break;
                    }
                }
            }
        }

        if !clicked {
            let screenshot = self.take_error_screenshot("click-next-not-found").await;
            return Err(TwitterLoginError::ElementNotFound {
                selector: "Next button".into(),
                step: FlowStep::ClickNext,
                screenshot,
            });
        }

        // Screenshot right after click for intermediate screen diagnosis
        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
        self.take_error_screenshot("post-next-click").await;

        self.wait_for_navigation_or_timeout().await;
        Ok(())
    }

    pub(super) async fn click_login_button(&mut self) -> Result<(), TwitterLoginError> {
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

        // Wait for navigation after login click
        self.wait_for_navigation_or_timeout().await;
        let pause = self.human.pre_click_delay();
        tokio::time::sleep(pause).await;
        Ok(())
    }

    pub(super) async fn extract_cookies(&self) -> Result<LoginOutput, TwitterLoginError> {
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
            user_agent: STEALTH_UA.to_string(),
        })
    }
}

/// Generate a TOTP code from a base32-encoded secret.
pub(in crate::login) fn generate_totp(secret_b32: &str) -> Result<String, TwitterLoginError> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let secret_bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| TwitterLoginError::TotpFailed(format!("bad base32 secret: {e}")))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
        .map_err(|e| TwitterLoginError::TotpFailed(format!("TOTP init: {e}")))?;

    totp.generate_current()
        .map_err(|e| TwitterLoginError::TotpFailed(format!("TOTP generate: {e}")))
}
