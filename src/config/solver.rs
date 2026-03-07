//! CF challenge solver (Byparr/FlareSolverr) configuration.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct SolverSection {
    /// FlareSolverr-compatible endpoint URL.
    pub byparr_url: Option<String>,
    /// Solver request timeout in seconds.
    pub byparr_timeout_secs: u64,
}

impl Default for SolverSection {
    fn default() -> Self {
        Self {
            byparr_url: None,
            byparr_timeout_secs: 60,
        }
    }
}
