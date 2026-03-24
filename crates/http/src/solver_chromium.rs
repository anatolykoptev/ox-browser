//! ChromiumSolver — native Rust CookieProvider using chromiumoxide (CDP).
//!
//! Launches headless Chrome, navigates to a CF-protected URL, waits for the
//! `cf_clearance` cookie, and returns it. Uses a semaphore for concurrency
//! control so we never spin up more browser instances than the host can handle.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use chromiumoxide::Browser;
use chromiumoxide::browser::BrowserConfig;
use futures::StreamExt;
use tokio::sync::Semaphore;

use crate::cloudflare::ChallengeType;
use crate::cookie_provider::{CookieProvider, SolvedChallenge};

/// Stealth bootstrap script injected before page navigation.
const STEALTH_JS: &str = include_str!("stealth.js");

/// Cookie name set by Cloudflare after a successful challenge.
const CF_CLEARANCE: &str = "cf_clearance";

/// User-Agent that matches the stealth script's Client Hints profile.
const STEALTH_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";

/// Configuration for the chromiumoxide-based solver.
#[derive(Debug, Clone)]
pub struct ChromiumConfig {
    /// How long to wait for `cf_clearance` before giving up.
    pub timeout: Duration,
    /// Maximum number of browser instances running simultaneously.
    pub max_concurrent: usize,
    /// Proxy URL to pass to Chrome (e.g. `http://user:pass@host:port`).
    pub proxy_url: Option<String>,
    /// Full path to the Chrome/Chromium binary. Auto-detected when `None`.
    pub chrome_path: Option<String>,
}

impl Default for ChromiumConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_concurrent: 3,
            proxy_url: None,
            chrome_path: None,
        }
    }
}

/// Solves Cloudflare challenges by launching a real headless Chrome via CDP.
pub struct ChromiumSolver {
    config: ChromiumConfig,
    semaphore: Semaphore,
}

impl ChromiumSolver {
    pub fn new(config: ChromiumConfig) -> Self {
        let max = config.max_concurrent;
        tracing::info!(max_concurrent = max, "chromium solver initialized");
        Self {
            config,
            semaphore: Semaphore::new(max),
        }
    }

    async fn launch_and_solve(&self, url: &str) -> Result<SolvedChallenge, String> {
        let mut builder = BrowserConfig::builder()
            .no_sandbox()
            .new_headless_mode()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--no-first-run")
            .arg("--disable-blink-features=AutomationControlled")
            .arg("--window-size=1920,1080")
            .arg("--lang=en-US,en");

        if let Some(ref path) = self.config.chrome_path {
            builder = builder.chrome_executable(path);
        }

        if let Some(ref proxy) = self.config.proxy_url {
            builder = builder.arg(format!("--proxy-server={proxy}"));
        }

        let browser_config = builder
            .build()
            .map_err(|e| format!("chromium config error: {e}"))?;

        let (mut browser, mut handler) = Browser::launch(browser_config)
            .await
            .map_err(|e| format!("chromium launch error: {e}"))?;

        // Drive the CDP connection in the background.
        let handler_task = tokio::spawn(async move {
            loop {
                if handler.next().await.is_none() {
                    break;
                }
            }
        });

        let result = self.solve_in_browser(&browser, url).await;

        // Shut down browser; ignore errors (process may already be gone).
        let _ = browser.close().await;
        handler_task.abort();

        result
    }

    async fn solve_in_browser(
        &self,
        browser: &Browser,
        url: &str,
    ) -> Result<SolvedChallenge, String> {
        // Open blank page so we can inject stealth BEFORE navigation.
        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| format!("chromium new_page error: {e}"))?;

        // Inject stealth script — runs on every document, including navigation.
        page.evaluate_on_new_document(STEALTH_JS)
            .await
            .map_err(|e| format!("chromium stealth inject error: {e}"))?;

        // Override UA to strip "HeadlessChrome" from the UA string.
        page.set_user_agent(STEALTH_UA)
            .await
            .map_err(|e| format!("chromium set_user_agent error: {e}"))?;

        // Navigate to target URL now that stealth is in place.
        page.goto(url)
            .await
            .map_err(|e| format!("chromium goto error: {e}"))?;

        let deadline = tokio::time::Instant::now() + self.config.timeout;

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(format!(
                    "chromium solver timeout after {}s",
                    self.config.timeout.as_secs()
                ));
            }

            let cookies = page
                .get_cookies()
                .await
                .map_err(|e| format!("chromium get_cookies error: {e}"))?;

            if cookies.iter().any(|c| c.name == CF_CLEARANCE) {
                let cookie_map: HashMap<String, String> = cookies
                    .into_iter()
                    .map(|c| (c.name, c.value))
                    .collect();

                return Ok(SolvedChallenge {
                    cookies: cookie_map,
                    user_agent: STEALTH_UA.to_string(),
                    body: None,
                });
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

#[async_trait]
impl CookieProvider for ChromiumSolver {
    async fn solve(
        &self,
        url: &str,
        _challenge_type: ChallengeType,
    ) -> Result<SolvedChallenge, String> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| format!("chromium semaphore closed: {e}"))?;
        self.launch_and_solve(url).await
    }
}

#[cfg(test)]
#[path = "solver_chromium_tests.rs"]
mod tests;
