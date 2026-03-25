//! Helper methods for the login flow: typing, element queries, screenshots, TOTP.

use std::path::PathBuf;

use tokio::time::Instant;

use super::super::chrome::ChromeSession;
use super::super::error::{FlowStep, TwitterLoginError};
use super::super::human::Speed;
use super::super::selectors;
use super::{LoginFlow, POLL_INTERVAL};

impl<'a> LoginFlow<'a> {
    /// Type text character-by-character with human-like delays.
    /// Uses element.click() for focus + document.execCommand('insertText')
    /// per char — creates trusted InputEvents that React accepts.
    pub(super) async fn type_human(
        &mut self,
        selector: &str,
        text: &str,
        speed: Speed,
    ) -> Result<(), TwitterLoginError> {
        // Click the element (CDP mouse dispatch → establishes browser-level focus)
        let el = self.page.find_element(selector).await.map_err(|_| {
            TwitterLoginError::Navigation(format!("type_human: element not found: {selector}"))
        })?;
        el.click().await.map_err(|e| {
            TwitterLoginError::Navigation(format!("type_human: click failed: {e}"))
        })?;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Debug screenshot to verify focus state
        tracing::debug!(selector, "type_human: element clicked, starting typing");

        // React controlled inputs: set value via native setter + trigger
        // React's internal onChange via a synthetic-looking InputEvent.
        // We set the full value at once, then simulate human-like delay.
        let mut typed = String::new();
        for ch in text.chars() {
            typed.push(ch);
            let escaped = typed.replace('\\', "\\\\").replace('"', "\\\"");
            // Use React fiber trick: get native setter, set value, then
            // dispatch InputEvent that React's onChange handler will process.
            let js = format!(
                r#"(() => {{
                    const el = document.querySelector('{selector}');
                    if (!el) return false;
                    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                        window.HTMLInputElement.prototype, 'value'
                    ).set;
                    nativeInputValueSetter.call(el, "{escaped}");
                    const ev = new Event('input', {{ bubbles: true }});
                    // React 16+ checks _valueTracker — reset it so React sees the change
                    const tracker = el._valueTracker;
                    if (tracker) tracker.setValue('');
                    el.dispatchEvent(ev);
                    return true;
                }})()"#
            );
            let ok: bool = self.page.evaluate(js).await
                .ok()
                .and_then(|r| r.into_value().ok())
                .unwrap_or(false);
            if !ok {
                return Err(TwitterLoginError::Navigation(
                    format!("type_human: element not found: {selector}")
                ));
            }

            let delay = self.human.char_delay(speed);
            tokio::time::sleep(delay).await;

            if self.human.should_micro_pause() {
                tokio::time::sleep(self.human.micro_pause_delay()).await;
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

    /// Focus an input element via JS and clear its value.
    /// More reliable than element.click() for React-controlled inputs.
    pub(super) async fn focus_and_clear(&self, selector: &str) -> Result<(), TwitterLoginError> {
        let js = format!(
            r#"(() => {{
                const el = document.querySelector('{selector}');
                if (!el) return false;
                el.focus();
                el.value = '';
                el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                return true;
            }})()"#
        );
        let focused: bool = self
            .page
            .evaluate(js)
            .await
            .ok()
            .and_then(|r| r.into_value().ok())
            .unwrap_or(false);

        if !focused {
            tracing::warn!(selector, "focus_and_clear: element not found");
        }
        // Small delay after focus
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(())
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

}
