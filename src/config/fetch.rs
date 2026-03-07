//! Default parameters for /fetch and /fetch-smart endpoints.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FetchSection {
    /// Default timeout for /fetch (seconds). Caller can override per-request.
    pub default_timeout_secs: u64,
    /// Default timeout for /fetch-smart (seconds). Caller can override per-request.
    pub smart_timeout_secs: u64,
}

impl Default for FetchSection {
    fn default() -> Self {
        Self {
            default_timeout_secs: 15,
            smart_timeout_secs: 30,
        }
    }
}
