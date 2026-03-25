//! Chrome headless settings (shared by twitter login + chrome_interact).

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ChromeSection {
    /// Max concurrent Chrome instances.
    pub max_concurrent: usize,
    /// Default timeout for chrome_interact actions (seconds).
    pub timeout_secs: u64,
    /// Directory for screenshots.
    pub screenshot_dir: String,
}

impl Default for ChromeSection {
    fn default() -> Self {
        Self {
            max_concurrent: 2,
            timeout_secs: 30,
            screenshot_dir: "/tmp/ox-browser/chrome".into(),
        }
    }
}
