//! CF challenge solver configuration (Byparr/FlareSolverr and ChromiumSolver).

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct SolverSection {
    /// FlareSolverr-compatible endpoint URL. When set, Byparr solver is used.
    pub byparr_url: Option<String>,
    /// Solver request timeout in seconds (Byparr).
    pub byparr_timeout_secs: u64,
    /// Memory budget for solver container in MB (used to calc max concurrent browsers).
    pub byparr_memory_mb: usize,

    /// URL of go-browser service (e.g. "http://go-browser:8906").
    /// When set, GoBrowserSolver is used (highest priority).
    pub go_browser_url: Option<String>,

    /// Enable the native Chromium CDP solver (takes priority over byparr when true).
    pub chromium_enabled: bool,
    /// Full path to Chrome/Chromium binary. Auto-detected when not set.
    pub chromium_path: Option<String>,
    /// Maximum concurrent browser instances for the Chromium solver.
    pub chromium_max_concurrent: usize,
    /// Timeout in seconds for the Chromium solver to obtain `cf_clearance`.
    pub chromium_timeout_secs: u64,
}

impl Default for SolverSection {
    fn default() -> Self {
        Self {
            byparr_url: None,
            byparr_timeout_secs: 60,
            byparr_memory_mb: 768,
            go_browser_url: None,
            chromium_enabled: false,
            chromium_path: None,
            chromium_max_concurrent: 3,
            chromium_timeout_secs: 30,
        }
    }
}
