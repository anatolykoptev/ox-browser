//! Twitter headless login settings.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TwitterSection {
    /// Total timeout for one login flow (seconds).
    pub login_timeout_secs: u64,
    /// Max concurrent login flows (Chrome instances).
    pub max_concurrent_logins: usize,
    /// Save screenshot on error.
    pub screenshot_on_error: bool,
    /// Directory for error screenshots.
    pub screenshot_dir: String,
}

impl Default for TwitterSection {
    fn default() -> Self {
        Self {
            login_timeout_secs: 90,
            max_concurrent_logins: 1,
            screenshot_on_error: true,
            screenshot_dir: "/tmp/ox-browser/twitter-login".into(),
        }
    }
}
