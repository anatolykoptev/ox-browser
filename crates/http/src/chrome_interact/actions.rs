//! Action execution for chrome_interact -- one function per action type.

use base64::Engine;
use chromiumoxide::cdp::browser_protocol::input::InsertTextParams;
use chromiumoxide::cdp::browser_protocol::network::SetCookieParams;
use chromiumoxide::page::ScreenshotParams;
use chromiumoxide::Page;
use tokio::time::Instant;

use super::logs::SessionLogs;
use super::types::{
    ActionOutput, ChromeAction, CookieEntry, CookieInput, EvalResult,
    ScreenshotResult,
};

const POLL_INTERVAL_MS: u64 = 300;
const CHAR_DELAY_MS: u64 = 30;

/// Execute a single Chrome action, returning its output or an error.
pub async fn execute_action(
    page: &Page,
    action: &ChromeAction,
    deadline: Instant,
    logs: Option<&SessionLogs>,
) -> Result<ActionOutput, String> {
    match action {
        ChromeAction::Click { selector } => do_click(page, selector).await,
        ChromeAction::TypeText { selector, text } => do_type(page, selector, text).await,
        ChromeAction::WaitFor { selector, timeout_ms } => {
            do_wait(page, selector, *timeout_ms, deadline).await
        }
        ChromeAction::Screenshot { label } => do_screenshot(page, label).await,
        ChromeAction::Evaluate { js } => do_evaluate(page, js).await,
        ChromeAction::Press { key } => do_press(page, key).await,
        ChromeAction::Sleep { ms } => {
            let dur = std::time::Duration::from_millis(*ms);
            let remaining = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(dur.min(remaining)).await;
            Ok(ActionOutput::None)
        }
        ChromeAction::GetCookies => do_get_cookies(page).await,
        ChromeAction::SetCookies { cookies } => do_set_cookies(page, cookies).await,
        ChromeAction::DestroySession => Ok(ActionOutput::None),
        ChromeAction::Snapshot { label } => {
            super::snapshot::do_snapshot(page, label.as_deref()).await
        }
        ChromeAction::HandleDialog { accept, prompt_text } => {
            super::navigation::do_handle_dialog(page, *accept, prompt_text.as_deref()).await
        }
        ChromeAction::Hover { selector } => super::navigation::do_hover(page, selector).await,
        ChromeAction::GoBack => super::navigation::do_go_back(page).await,
        ChromeAction::GetLogs => do_get_logs(logs).await,
    }
}

async fn do_get_logs(logs: Option<&SessionLogs>) -> Result<ActionOutput, String> {
    match logs {
        Some(l) => {
            let network = l.take_network().await;
            let console = l.take_console().await;
            Ok(ActionOutput::Logs { network, console })
        }
        None => Ok(ActionOutput::Logs { network: vec![], console: vec![] }),
    }
}

async fn do_click(page: &Page, selector: &str) -> Result<ActionOutput, String> {
    let el = page
        .find_element(selector)
        .await
        .map_err(|e| format!("click: element '{selector}' not found: {e}"))?;
    el.click().await.map_err(|e| format!("click '{selector}': {e}"))?;
    Ok(ActionOutput::None)
}

async fn do_type(page: &Page, selector: &str, text: &str) -> Result<ActionOutput, String> {
    let el = page
        .find_element(selector)
        .await
        .map_err(|e| format!("type: element '{selector}' not found: {e}"))?;
    el.click().await.map_err(|e| format!("type: focus click '{selector}': {e}"))?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    for ch in text.chars() {
        let params = InsertTextParams { text: ch.to_string() };
        page.execute(params).await.map_err(|e| format!("InsertText '{ch}': {e}"))?;
        tokio::time::sleep(std::time::Duration::from_millis(CHAR_DELAY_MS)).await;
    }
    Ok(ActionOutput::None)
}

async fn do_wait(
    page: &Page,
    selector: &str,
    timeout_ms: u64,
    deadline: Instant,
) -> Result<ActionOutput, String> {
    let wait_until = Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let effective_deadline = wait_until.min(deadline);
    loop {
        if page.find_element(selector).await.is_ok() {
            return Ok(ActionOutput::None);
        }
        if Instant::now() > effective_deadline {
            return Err(format!("wait_for '{selector}' timed out after {timeout_ms}ms"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

async fn do_screenshot(page: &Page, label: &str) -> Result<ActionOutput, String> {
    let bytes = page
        .screenshot(ScreenshotParams::builder().build())
        .await
        .map_err(|e| format!("screenshot '{label}': {e}"))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(ActionOutput::Screenshot(ScreenshotResult {
        label: label.to_string(),
        base64_png: b64,
    }))
}

async fn do_evaluate(page: &Page, js: &str) -> Result<ActionOutput, String> {
    let value: serde_json::Value = page
        .evaluate(js.to_string())
        .await
        .map_err(|e| format!("evaluate: {e}"))?
        .into_value()
        .unwrap_or(serde_json::Value::Null);

    let result = match &value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    Ok(ActionOutput::Eval(EvalResult { js: js.to_string(), result }))
}

async fn do_set_cookies(page: &Page, cookies: &[CookieInput]) -> Result<ActionOutput, String> {
    for c in cookies {
        let params = SetCookieParams::builder()
            .name(&c.name)
            .value(&c.value)
            .domain(&c.domain)
            .path(&c.path)
            .secure(c.secure)
            .http_only(c.http_only)
            .build()
            .map_err(|e| format!("build cookie '{}': {e}", c.name))?;
        page.execute(params).await.map_err(|e| format!("set cookie '{}': {e}", c.name))?;
    }
    Ok(ActionOutput::None)
}

async fn do_get_cookies(page: &Page) -> Result<ActionOutput, String> {
    let cookies = page.get_cookies().await.map_err(|e| format!("get_cookies: {e}"))?;
    let entries: Vec<CookieEntry> = cookies
        .into_iter()
        .map(|c| CookieEntry {
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            secure: c.secure,
            http_only: c.http_only,
        })
        .collect();
    Ok(ActionOutput::Cookies(entries))
}

async fn do_press(page: &Page, key: &str) -> Result<ActionOutput, String> {
    let js = format!(
        r#"(() => {{
            const e = new KeyboardEvent('keydown', {{ key: '{key}', code: '{key}', bubbles: true }});
            document.body.dispatchEvent(e);
            const e2 = new KeyboardEvent('keyup', {{ key: '{key}', code: '{key}', bubbles: true }});
            document.body.dispatchEvent(e2);
        }})()"#,
    );
    page.evaluate(js).await.map_err(|e| format!("press '{key}': {e}"))?;
    Ok(ActionOutput::None)
}
