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

#[derive(Debug, Serialize)]
pub struct InteractResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub screenshots: Vec<ScreenshotResult>,
    pub evaluations: Vec<EvalResult>,
    pub cookies: HashMap<String, String>,
    pub final_url: String,
}

/// Execute a chrome interaction session.
///
/// 1. Validates URL against SSRF
/// 2. Acquires semaphore permit
/// 3. Launches Chrome, navigates, runs actions
/// 4. Returns partial results on failure
pub async fn execute(
    req: InteractRequest,
    config: &ChromeLoginConfig,
    semaphore: &Semaphore,
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

    // Launch Chrome
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

    let result = run_actions(&page, &req).await;

    session.shutdown().await;
    result
}

async fn run_actions(page: &Page, req: &InteractRequest) -> InteractResponse {
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

    for (i, action) in req.actions.iter().enumerate() {
        if Instant::now() > deadline {
            return partial_response(
                format!("timeout at action {i}"),
                screenshots,
                evaluations,
                get_page_state(page).await,
            );
        }

        match execute_action(page, action, deadline).await {
            Ok(ActionOutput::None) => {}
            Ok(ActionOutput::Screenshot(s)) => screenshots.push(s),
            Ok(ActionOutput::Eval(e)) => evaluations.push(e),
            Err(e) => {
                return partial_response(
                    format!("action {i} failed: {e}"),
                    screenshots,
                    evaluations,
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
        cookies,
        final_url,
    }
}

/// Output from a single action execution.
pub enum ActionOutput {
    None,
    Screenshot(ScreenshotResult),
    Eval(EvalResult),
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
        cookies: HashMap::new(),
        final_url: String::new(),
    }
}

fn partial_response(
    msg: String,
    screenshots: Vec<ScreenshotResult>,
    evaluations: Vec<EvalResult>,
    (cookies, final_url): (HashMap<String, String>, String),
) -> InteractResponse {
    InteractResponse {
        status: "partial".into(),
        error: Some(msg),
        screenshots,
        evaluations,
        cookies,
        final_url,
    }
}
