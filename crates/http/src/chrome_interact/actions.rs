//! Action execution for chrome_interact — one function per action type.

use std::collections::HashMap;

use base64::Engine;
use chromiumoxide::cdp::browser_protocol::accessibility::GetFullAxTreeParams;
use chromiumoxide::cdp::browser_protocol::input::InsertTextParams;
use chromiumoxide::cdp::browser_protocol::network::SetCookieParams;
use chromiumoxide::page::ScreenshotParams;
use chromiumoxide::Page;
use tokio::time::Instant;

use super::{ActionOutput, ChromeAction, EvalResult, ScreenshotResult, SessionLogs, SnapshotResult};

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
        ChromeAction::Click { selector } => {
            do_click(page, selector).await
        }
        ChromeAction::TypeText { selector, text } => {
            do_type(page, selector, text).await
        }
        ChromeAction::WaitFor {
            selector,
            timeout_ms,
        } => do_wait(page, selector, *timeout_ms, deadline).await,
        ChromeAction::Screenshot { label } => {
            do_screenshot(page, label).await
        }
        ChromeAction::Evaluate { js } => do_evaluate(page, js).await,
        ChromeAction::Press { key } => do_press(page, key).await,
        ChromeAction::Sleep { ms } => {
            let dur = std::time::Duration::from_millis(*ms);
            let remaining = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(dur.min(remaining)).await;
            Ok(ActionOutput::None)
        }
        ChromeAction::GetCookies => do_get_cookies(page).await,
        ChromeAction::SetCookies { cookies } => {
            do_set_cookies(page, cookies).await
        }
        // No-op in actions — actual destroy happens in execute() after all actions complete.
        ChromeAction::DestroySession => Ok(ActionOutput::None),
        ChromeAction::Snapshot { label } => do_snapshot(page, label.as_deref()).await,
        ChromeAction::HandleDialog { accept, prompt_text } => {
            do_handle_dialog(page, *accept, prompt_text.as_deref()).await
        }
        ChromeAction::Hover { selector } => do_hover(page, selector).await,
        ChromeAction::GoBack => do_go_back(page).await,
        ChromeAction::GetLogs => do_get_logs(logs).await,
    }
}

async fn do_get_logs(
    logs: Option<&SessionLogs>,
) -> Result<ActionOutput, String> {
    match logs {
        Some(l) => {
            let network = l.take_network().await;
            let console = l.take_console().await;
            Ok(ActionOutput::Logs { network, console })
        }
        None => Ok(ActionOutput::Logs {
            network: vec![],
            console: vec![],
        }),
    }
}

async fn do_click(page: &Page, selector: &str) -> Result<ActionOutput, String> {
    let el = page
        .find_element(selector)
        .await
        .map_err(|e| format!("click: element '{selector}' not found: {e}"))?;
    el.click()
        .await
        .map_err(|e| format!("click '{selector}': {e}"))?;
    Ok(ActionOutput::None)
}

async fn do_type(
    page: &Page,
    selector: &str,
    text: &str,
) -> Result<ActionOutput, String> {
    // Click to focus
    let el = page
        .find_element(selector)
        .await
        .map_err(|e| format!("type: element '{selector}' not found: {e}"))?;
    el.click()
        .await
        .map_err(|e| format!("type: focus click '{selector}': {e}"))?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Insert text char-by-char via CDP InsertText
    for ch in text.chars() {
        let params = InsertTextParams {
            text: ch.to_string(),
        };
        page.execute(params)
            .await
            .map_err(|e| format!("InsertText '{ch}': {e}"))?;
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
    let wait_until = Instant::now()
        + std::time::Duration::from_millis(timeout_ms);
    let effective_deadline = wait_until.min(deadline);

    loop {
        if page.find_element(selector).await.is_ok() {
            return Ok(ActionOutput::None);
        }
        if Instant::now() > effective_deadline {
            return Err(format!(
                "wait_for '{selector}' timed out after {timeout_ms}ms"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(
            POLL_INTERVAL_MS,
        ))
        .await;
    }
}

async fn do_screenshot(
    page: &Page,
    label: &str,
) -> Result<ActionOutput, String> {
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

async fn do_evaluate(
    page: &Page,
    js: &str,
) -> Result<ActionOutput, String> {
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

    Ok(ActionOutput::Eval(EvalResult {
        js: js.to_string(),
        result,
    }))
}

async fn do_set_cookies(
    page: &Page,
    cookies: &[super::CookieInput],
) -> Result<ActionOutput, String> {
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
        page.execute(params)
            .await
            .map_err(|e| format!("set cookie '{}': {e}", c.name))?;
    }
    Ok(ActionOutput::None)
}

async fn do_get_cookies(page: &Page) -> Result<ActionOutput, String> {
    let cookies = page
        .get_cookies()
        .await
        .map_err(|e| format!("get_cookies: {e}"))?;
    let entries: Vec<super::CookieEntry> = cookies
        .into_iter()
        .map(|c| super::CookieEntry {
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
    // Use JS to dispatch a KeyboardEvent on document.body
    let js = format!(
        r#"(() => {{
            const e = new KeyboardEvent('keydown', {{
                key: '{key}', code: '{key}', bubbles: true
            }});
            document.body.dispatchEvent(e);
            const e2 = new KeyboardEvent('keyup', {{
                key: '{key}', code: '{key}', bubbles: true
            }});
            document.body.dispatchEvent(e2);
        }})()"#,
    );
    page.evaluate(js)
        .await
        .map_err(|e| format!("press '{key}': {e}"))?;
    Ok(ActionOutput::None)
}

async fn do_snapshot(page: &Page, label: Option<&str>) -> Result<ActionOutput, String> {
    let params = GetFullAxTreeParams::builder().build();
    let result = page
        .execute(params)
        .await
        .map_err(|e| format!("snapshot: {e}"))?;

    let nodes = result.result.nodes;

    // Build node_id → index lookup for O(1) child resolution (avoids O(n^2)
    // from nodes.iter().position() on pages with many nodes).
    let id_to_idx: HashMap<String, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.node_id.as_ref().to_owned(), i))
        .collect();

    // Find root (no parent)
    let root_idx = nodes
        .iter()
        .position(|n| n.parent_id.is_none())
        .unwrap_or(0);

    // Recursively format tree
    let mut out = String::new();
    format_node(&nodes, &id_to_idx, root_idx, 0, &mut out);

    let label = label.unwrap_or("snapshot").to_owned();
    Ok(ActionOutput::Snapshot(SnapshotResult { label, tree: out }))
}

// NOTE: ChromeSession::launch() registers an auto-dismiss listener that always
// accepts JS dialogs (accept=true). If a dialog fires before this explicit
// HandleDialog action runs, the auto-dismiss will have already accepted it,
// making accept=false ineffective. To reliably dismiss dialogs, the HandleDialog
// action must be placed BEFORE the action that triggers the dialog (e.g., before
// an Evaluate that calls confirm()). This is a known limitation — the auto-dismiss
// exists to prevent session freezes from unexpected alerts.
async fn do_handle_dialog(
    page: &Page,
    accept: bool,
    prompt_text: Option<&str>,
) -> Result<ActionOutput, String> {
    use chromiumoxide::cdp::browser_protocol::page::HandleJavaScriptDialogParams;
    let mut builder = HandleJavaScriptDialogParams::builder().accept(accept);
    if let Some(text) = prompt_text {
        builder = builder.prompt_text(text);
    }
    page.execute(builder.build().map_err(|e| format!("handle_dialog build: {e}"))?)
        .await
        .map_err(|e| format!("handle_dialog: {e}"))?;
    Ok(ActionOutput::None)
}

// Verified: DispatchMouseEventParams x/y fields are f64, matching the f64
// values from getBoundingClientRect(). No silent truncation occurs.
async fn do_hover(page: &Page, selector: &str) -> Result<ActionOutput, String> {
    let js = format!(
        r#"(() => {{
            const el = document.querySelector('{}');
            if (!el) return null;
            const r = el.getBoundingClientRect();
            return JSON.stringify({{ x: r.x + r.width / 2, y: r.y + r.height / 2 }});
        }})()"#,
        selector.replace('\'', "\\'")
    );
    let coords_str: String = page
        .evaluate(js)
        .await
        .map_err(|e| format!("hover coords: {e}"))?
        .into_value()
        .unwrap_or_default();

    let coords: serde_json::Value = serde_json::from_str(&coords_str)
        .map_err(|_| format!("hover: element '{selector}' not found or not visible"))?;

    let x = coords["x"].as_f64().unwrap_or(0.0);
    let y = coords["y"].as_f64().unwrap_or(0.0);

    use chromiumoxide::cdp::browser_protocol::input::{
        DispatchMouseEventParams, DispatchMouseEventType,
    };

    let params = DispatchMouseEventParams::builder()
        .r#type(DispatchMouseEventType::MouseMoved)
        .x(x)
        .y(y)
        .build()
        .map_err(|e| format!("hover params: {e}"))?;

    page.execute(params)
        .await
        .map_err(|e| format!("hover dispatch: {e}"))?;

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Ok(ActionOutput::None)
}

async fn do_go_back(page: &Page) -> Result<ActionOutput, String> {
    page.evaluate("window.history.back()")
        .await
        .map_err(|e| format!("go_back: {e}"))?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Ok(ActionOutput::None)
}

fn format_node(
    nodes: &[chromiumoxide::cdp::browser_protocol::accessibility::AxNode],
    id_to_idx: &HashMap<String, usize>,
    idx: usize,
    depth: usize,
    out: &mut String,
) {
    let node = &nodes[idx];
    if node.ignored {
        // Still recurse into ignored nodes' children
        if let Some(child_ids) = &node.child_ids {
            for cid in child_ids {
                if let Some(&ci) = id_to_idx.get(cid.as_ref()) {
                    format_node(nodes, id_to_idx, ci, depth, out);
                }
            }
        }
        return;
    }

    let role = node
        .role
        .as_ref()
        .and_then(|v| v.value.as_ref())
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Skip structurally noisy nodes deep in the tree
    if depth > 2 && matches!(role, "generic" | "none" | "unknown") {
        if let Some(child_ids) = &node.child_ids {
            for cid in child_ids {
                if let Some(&ci) = id_to_idx.get(cid.as_ref()) {
                    format_node(nodes, id_to_idx, ci, depth, out);
                }
            }
        }
        return;
    }

    let name = node
        .name
        .as_ref()
        .and_then(|v| v.value.as_ref())
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    out.push_str(&"  ".repeat(depth));
    out.push_str("- ");
    out.push_str(role);
    if let Some(n) = name {
        out.push_str(" \"");
        out.push_str(n);
        out.push('"');
    }
    out.push('\n');

    if let Some(child_ids) = &node.child_ids {
        for cid in child_ids {
            if let Some(&ci) = id_to_idx.get(cid.as_ref()) {
                format_node(nodes, id_to_idx, ci, depth + 1, out);
            }
        }
    }
}
