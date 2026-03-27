//! Shared types for the `chrome_interact` module.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::logs::{ConsoleEntry, NetworkEntry};

fn default_timeout() -> u64 { 30 }
fn default_wait() -> u64 { 5000 }
fn default_cookie_path() -> String { "/".to_string() }

#[derive(Debug, Deserialize)]
pub struct InteractRequest {
    pub url: String,
    pub actions: Vec<ChromeAction>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChromeAction {
    Click {
        selector: String,
        #[serde(default)]
        humanize: bool,
    },
    #[serde(alias = "type")]
    TypeText {
        selector: String,
        text: String,
        #[serde(default)]
        humanize: bool,
    },
    WaitFor {
        selector: String,
        #[serde(default = "default_wait")]
        timeout_ms: u64,
    },
    Screenshot {
        label: String,
    },
    Evaluate {
        js: String,
    },
    Press {
        key: String,
    },
    Sleep {
        ms: u64,
    },
    GetCookies,
    SetCookies {
        cookies: Vec<CookieInput>,
    },
    DestroySession,
    Snapshot {
        #[serde(default)]
        label: Option<String>,
    },
    HandleDialog {
        accept: bool,
        #[serde(default)]
        prompt_text: Option<String>,
    },
    Hover {
        selector: String,
        #[serde(default)]
        humanize: bool,
    },
    GoBack,
    GetLogs,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CookieInput {
    pub name: String,
    pub value: String,
    pub domain: String,
    #[serde(default = "default_cookie_path")]
    pub path: String,
    #[serde(default)]
    pub secure: bool,
    #[serde(default)]
    pub http_only: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieEntry {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScreenshotResult {
    pub label: String,
    pub base64_png: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvalResult {
    pub js: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotResult {
    pub label: String,
    pub tree: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InteractStatus {
    Ok,
    Error,
    Partial,
}

#[derive(Debug, Serialize)]
pub struct InteractResponse {
    pub status: InteractStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub screenshots: Vec<ScreenshotResult>,
    pub evaluations: Vec<EvalResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub snapshots: Vec<SnapshotResult>,
    pub cookies: HashMap<String, String>,
    pub final_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_log: Vec<NetworkEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub console_log: Vec<ConsoleEntry>,
}

pub struct ActionAccumulator {
    pub screenshots: Vec<ScreenshotResult>,
    pub evaluations: Vec<EvalResult>,
    pub snapshots: Vec<SnapshotResult>,
    pub network_log: Vec<NetworkEntry>,
    pub console_log: Vec<ConsoleEntry>,
    /// Current virtual cursor X position (for humanized movements).
    pub cursor_x: f64,
    /// Current virtual cursor Y position (for humanized movements).
    pub cursor_y: f64,
}

impl Default for ActionAccumulator {
    fn default() -> Self {
        Self {
            screenshots: Vec::new(),
            evaluations: Vec::new(),
            snapshots: Vec::new(),
            network_log: Vec::new(),
            console_log: Vec::new(),
            cursor_x: 960.0,
            cursor_y: 540.0,
        }
    }
}

impl InteractResponse {
    /// Build an error response with no action results.
    pub(crate) fn error(msg: String) -> Self {
        Self {
            status: InteractStatus::Error,
            error: Some(msg),
            screenshots: vec![],
            evaluations: vec![],
            snapshots: vec![],
            cookies: HashMap::new(),
            final_url: String::new(),
            session_id: None,
            network_log: vec![],
            console_log: vec![],
        }
    }

    /// Build a partial response preserving results collected so far.
    pub(crate) fn partial(
        msg: String,
        acc: ActionAccumulator,
        page_state: (HashMap<String, String>, String),
    ) -> Self {
        Self {
            status: InteractStatus::Partial,
            error: Some(msg),
            screenshots: acc.screenshots,
            evaluations: acc.evaluations,
            snapshots: acc.snapshots,
            cookies: page_state.0,
            final_url: page_state.1,
            session_id: None,
            network_log: acc.network_log,
            console_log: acc.console_log,
        }
    }
}

/// Output from a single action execution.
pub enum ActionOutput {
    None,
    Screenshot(ScreenshotResult),
    Eval(EvalResult),
    Snapshot(SnapshotResult),
    Cookies(Vec<CookieEntry>),
    Logs {
        network: Vec<NetworkEntry>,
        console: Vec<ConsoleEntry>,
    },
}
