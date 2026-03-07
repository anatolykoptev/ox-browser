//! Logging configuration.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct LogSection {
    /// Log level: trace, debug, info, warn, error.
    pub level: String,
}

impl Default for LogSection {
    fn default() -> Self {
        Self {
            level: "info".into(),
        }
    }
}
