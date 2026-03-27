//! Core execution engine: session dispatch, action loop, finalization.

use std::collections::HashMap;

use chromiumoxide::Page;
use tokio::sync::Semaphore;
use tokio::time::Instant;

use super::actions::execute_action;
use super::logs::SessionLogs;
use super::types::{
    ActionAccumulator, ActionOutput, ChromeAction, EvalResult, InteractRequest,
    InteractResponse, InteractStatus,
};
use crate::ChromeSession;

/// Execute a chrome interaction session.
///
/// Validates URL (SSRF), acquires semaphore, dispatches to session path:
/// - `Some("new")` -- new persistent session
/// - `Some(id)` -- reuse existing
/// - `None` -- ephemeral (one-shot tab from pool, no persistent state)
pub async fn execute(
    req: InteractRequest,
    semaphore: &Semaphore,
    pool: &crate::SessionPool,
) -> InteractResponse {
    if let Err(e) = crate::middleware_ssrf::validate_url(&req.url) {
        return InteractResponse::error(format!("SSRF blocked: {e}"));
    }
    let _permit = match semaphore.acquire().await {
        Ok(p) => p,
        Err(_) => return InteractResponse::error("semaphore closed".into()),
    };

    match req.session_id.as_deref() {
        Some("new") => execute_new_session(req, pool).await,
        Some(id) => {
            let id = id.to_owned();
            execute_existing_session(req, &id, pool).await
        }
        None => execute_ephemeral(req, pool).await,
    }
}

async fn execute_new_session(
    req: InteractRequest,
    pool: &crate::SessionPool,
) -> InteractResponse {
    let session_id = match pool.create(req.proxy.as_deref()).await {
        Ok(id) => id,
        Err(e) => return InteractResponse::error(format!("session create: {e}")),
    };
    let page = match pool.get(&session_id).await {
        Some(p) => p,
        None => return InteractResponse::error("session vanished after create".into()),
    };
    let has_destroy = has_destroy_action(&req.actions);
    let mut result = run_actions(&page, &req).await;
    finalize_session(pool, &session_id, &mut result, has_destroy).await;
    result
}

async fn execute_existing_session(
    req: InteractRequest,
    id: &str,
    pool: &crate::SessionPool,
) -> InteractResponse {
    let page = match pool.get(id).await {
        Some(p) => p,
        None => return InteractResponse::error(format!("session not found or expired: {id}")),
    };
    let has_destroy = has_destroy_action(&req.actions);
    let mut result = run_actions(&page, &req).await;
    finalize_session(pool, id, &mut result, has_destroy).await;
    result
}

async fn execute_ephemeral(
    req: InteractRequest,
    pool: &crate::SessionPool,
) -> InteractResponse {
    let browser_pool = pool.browser_pool();
    let (session_id, page) = match browser_pool.create(req.proxy.as_deref()).await {
        Ok(sp) => sp,
        Err(e) => return InteractResponse::error(format!("chrome launch: {e}")),
    };
    let result = run_actions(&page, &req).await;
    browser_pool.destroy(&session_id).await;
    result
}

/// Run all actions in sequence, collecting results into an `InteractResponse`.
async fn run_actions(page: &Page, req: &InteractRequest) -> InteractResponse {
    // Attach log listeners BEFORE navigation (fixes empty GetLogs bug).
    // Returned handles are detached -- tasks run until the page/browser closes.
    let logs = SessionLogs::new();
    let needs_logs = has_get_logs_action(&req.actions);
    if needs_logs {
        if let Err(e) = ChromeSession::attach_log_listeners(page, &logs).await {
            tracing::warn!(error = %e, "failed to attach log listeners");
        }
    }

    if let Err(e) = page.goto(&req.url).await {
        return InteractResponse::error(format!("navigate: {e}"));
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let deadline = Instant::now() + std::time::Duration::from_secs(req.timeout_secs);
    let mut acc = ActionAccumulator::default();

    for (i, action) in req.actions.iter().enumerate() {
        if Instant::now() > deadline {
            return InteractResponse::partial(
                format!("timeout at action {i}"),
                acc,
                get_page_state(page).await,
            );
        }
        match execute_action(page, action, deadline, if needs_logs { Some(&logs) } else { None }, &mut acc).await {
            Ok(ActionOutput::None) => {}
            Ok(ActionOutput::Screenshot(s)) => acc.screenshots.push(s),
            Ok(ActionOutput::Eval(e)) => acc.evaluations.push(e),
            Ok(ActionOutput::Snapshot(s)) => acc.snapshots.push(s),
            Ok(ActionOutput::Cookies(entries)) => {
                let json = serde_json::to_string(&entries).unwrap_or_default();
                acc.evaluations.push(EvalResult { js: "get_cookies".into(), result: json });
            }
            Ok(ActionOutput::Logs { network, console }) => {
                acc.network_log.extend(network);
                acc.console_log.extend(console);
            }
            Err(e) => {
                return InteractResponse::partial(
                    format!("action {i} failed: {e}"),
                    acc,
                    get_page_state(page).await,
                );
            }
        }
    }

    let (cookies, final_url) = get_page_state(page).await;
    InteractResponse {
        status: InteractStatus::Ok,
        error: None,
        screenshots: acc.screenshots,
        evaluations: acc.evaluations,
        snapshots: acc.snapshots,
        cookies,
        final_url,
        session_id: None,
        network_log: acc.network_log,
        console_log: acc.console_log,
    }
}

fn has_destroy_action(actions: &[ChromeAction]) -> bool {
    actions.iter().any(|a| matches!(a, ChromeAction::DestroySession))
}

fn has_get_logs_action(actions: &[ChromeAction]) -> bool {
    actions.iter().any(|a| matches!(a, ChromeAction::GetLogs))
}

async fn finalize_session(
    pool: &crate::SessionPool,
    session_id: &str,
    result: &mut InteractResponse,
    has_destroy: bool,
) {
    if has_destroy || result.error.is_some() {
        pool.destroy(session_id).await;
        result.session_id = None;
    } else {
        result.session_id = Some(session_id.to_owned());
    }
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
