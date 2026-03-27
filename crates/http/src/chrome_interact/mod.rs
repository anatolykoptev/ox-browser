//! Core execution engine for the `chrome_interact` tool.
//!
//! Launches headless Chrome, navigates to a URL, executes sequential
//! actions (click, type, wait, screenshot, evaluate, press, sleep),
//! and returns structured results.

use std::collections::HashMap;

use chromiumoxide::Page;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::chrome_session::ChromeLoginConfig;
use crate::ChromeSession;

mod actions;
pub use actions::execute_action;

pub mod logs;
pub use logs::{ConsoleEntry, NetworkEntry, SessionLogs};

fn default_timeout() -> u64 {
    30
}

fn default_wait() -> u64 {
    5000
}

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
    },
    #[serde(alias = "type")]
    TypeText {
        selector: String,
        text: String,
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

fn default_cookie_path() -> String {
    "/".to_string()
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

#[derive(Debug, Serialize)]
pub struct InteractResponse {
    pub status: String,
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

/// Execute a chrome interaction session.
///
/// 1. Validates URL against SSRF
/// 2. Acquires semaphore permit
/// 3. Dispatches to one of three paths based on `session_id`:
///    - `Some("new")` — create a new persistent session in the pool
///    - `Some(id)` — reuse an existing pool session
///    - `None` — ephemeral (launch + shutdown per request)
pub async fn execute(
    req: InteractRequest,
    config: &ChromeLoginConfig,
    semaphore: &Semaphore,
    pool: &crate::SessionPool,
) -> InteractResponse {
    // SSRF validation
    if let Err(e) = crate::middleware_ssrf::validate_url(&req.url) {
        return error_response(format!("SSRF blocked: {e}"));
    }

    // Acquire concurrency permit
    let _permit = match semaphore.acquire().await {
        Ok(p) => p,
        Err(_) => return error_response("semaphore closed".into()),
    };

    match req.session_id.as_deref() {
        // Path B — create new persistent session
        Some("new") => {
            let proxy = req.proxy.as_deref();
            let session_id = match pool.create(proxy).await {
                Ok(id) => id,
                Err(e) => return error_response(format!("session create: {e}")),
            };
            let page = match pool.get(&session_id).await {
                Some(p) => p,
                None => return error_response("session vanished after create".into()),
            };
            let has_destroy = req
                .actions
                .iter()
                .any(|a| matches!(a, ChromeAction::DestroySession));
            let mut result = run_actions(&page, &req, None).await;
            // On error or explicit destroy — clean up session to avoid stale locks
            if has_destroy || result.error.is_some() {
                pool.destroy(&session_id).await;
                result.session_id = None;
            } else {
                result.session_id = Some(session_id);
            }
            result
        }

        // Path A — reuse existing session
        Some(id) => {
            let page = match pool.get(id).await {
                Some(p) => p,
                None => {
                    return error_response(format!("session not found or expired: {id}"))
                }
            };
            let has_destroy = req
                .actions
                .iter()
                .any(|a| matches!(a, ChromeAction::DestroySession));
            let mut result = run_actions(&page, &req, None).await;
            // On error or explicit destroy — clean up session
            if has_destroy || result.error.is_some() {
                pool.destroy(id).await;
                result.session_id = None;
            } else {
                result.session_id = Some(id.to_owned());
            }
            result
        }

        // Path C — ephemeral (original behavior)
        None => {
            let launch_config = if req.proxy.is_some() {
                let mut c = config.clone();
                c.proxy_url.clone_from(&req.proxy);
                c
            } else {
                config.clone()
            };

            let (session, page) = match ChromeSession::launch(&launch_config).await {
                Ok(sp) => sp,
                Err(e) => return error_response(format!("chrome launch: {e}")),
            };

            let result = run_actions(&page, &req, None).await;
            session.shutdown().await;
            result
        }
    }
}

async fn run_actions(
    page: &Page,
    req: &InteractRequest,
    _logs: Option<&SessionLogs>,
) -> InteractResponse {
    // Attach log listeners BEFORE navigation so we capture all network/console
    // events fired during page load (fixes empty GetLogs bug).
    let logs = SessionLogs::new();
    if let Err(e) = ChromeSession::attach_log_listeners(page, &logs).await {
        tracing::warn!(error = %e, "failed to attach log listeners — GetLogs will be empty");
    }

    // Navigate to URL
    if let Err(e) = page.goto(&req.url).await {
        return error_response(format!("navigate: {e}"));
    }
    // Brief settle after navigation
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let deadline = Instant::now()
        + std::time::Duration::from_secs(req.timeout_secs);

    let mut screenshots = Vec::new();
    let mut evaluations = Vec::new();
    let mut snapshots = Vec::new();
    let mut network_log = Vec::new();
    let mut console_log = Vec::new();

    for (i, action) in req.actions.iter().enumerate() {
        if Instant::now() > deadline {
            return partial_response(
                format!("timeout at action {i}"),
                screenshots,
                evaluations,
                snapshots,
                network_log,
                console_log,
                get_page_state(page).await,
            );
        }

        match execute_action(page, action, deadline, Some(&logs)).await {
            Ok(ActionOutput::None) => {}
            Ok(ActionOutput::Screenshot(s)) => screenshots.push(s),
            Ok(ActionOutput::Eval(e)) => evaluations.push(e),
            Ok(ActionOutput::Snapshot(s)) => snapshots.push(s),
            Ok(ActionOutput::Cookies(entries)) => {
                let json = serde_json::to_string(&entries).unwrap_or_default();
                evaluations.push(EvalResult {
                    js: "get_cookies".into(),
                    result: json,
                });
            }
            Ok(ActionOutput::Logs { network, console }) => {
                network_log.extend(network);
                console_log.extend(console);
            }
            Err(e) => {
                return partial_response(
                    format!("action {i} failed: {e}"),
                    screenshots,
                    evaluations,
                    snapshots,
                    network_log,
                    console_log,
                    get_page_state(page).await,
                );
            }
        }
    }

    let (cookies, final_url) = get_page_state(page).await;

    InteractResponse {
        status: "ok".into(),
        error: None,
        screenshots,
        evaluations,
        snapshots,
        cookies,
        final_url,
        session_id: None,
        network_log,
        console_log,
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

async fn get_page_state(page: &Page) -> (HashMap<String, String>, String) {
    let cookies = page
        .get_cookies()
        .await
        .map(|cs| cs.into_iter().map(|c| (c.name, c.value)).collect())
        .unwrap_or_default();

    let final_url: String = page
        .evaluate("window.location.href")
        .await
        .ok()
        .and_then(|r| r.into_value().ok())
        .unwrap_or_default();

    (cookies, final_url)
}

fn error_response(msg: String) -> InteractResponse {
    InteractResponse {
        status: "error".into(),
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

fn partial_response(
    msg: String,
    screenshots: Vec<ScreenshotResult>,
    evaluations: Vec<EvalResult>,
    snapshots: Vec<SnapshotResult>,
    network_log: Vec<NetworkEntry>,
    console_log: Vec<ConsoleEntry>,
    (cookies, final_url): (HashMap<String, String>, String),
) -> InteractResponse {
    InteractResponse {
        status: "partial".into(),
        error: Some(msg),
        screenshots,
        evaluations,
        snapshots,
        cookies,
        final_url,
        session_id: None,
        network_log,
        console_log,
    }
}
