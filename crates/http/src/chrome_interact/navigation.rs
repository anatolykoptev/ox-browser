//! Navigation and interaction actions: hover, go_back, handle_dialog.

use chromiumoxide::Page;

use super::types::ActionOutput;

// NOTE: ChromeSession::launch() registers an auto-dismiss listener that always
// accepts JS dialogs (accept=true). If a dialog fires before this explicit
// HandleDialog action runs, the auto-dismiss will have already accepted it,
// making accept=false ineffective. To reliably dismiss dialogs, the HandleDialog
// action must be placed BEFORE the action that triggers the dialog (e.g., before
// an Evaluate that calls confirm()). This is a known limitation -- the auto-dismiss
// exists to prevent session freezes from unexpected alerts.
pub(crate) async fn do_handle_dialog(
    page: &Page,
    accept: bool,
    prompt_text: Option<&str>,
) -> Result<ActionOutput, String> {
    use chromiumoxide::cdp::browser_protocol::page::HandleJavaScriptDialogParams;
    let mut builder = HandleJavaScriptDialogParams::builder().accept(accept);
    if let Some(text) = prompt_text {
        builder = builder.prompt_text(text);
    }
    page.execute(
        builder
            .build()
            .map_err(|e| format!("handle_dialog build: {e}"))?,
    )
    .await
    .map_err(|e| format!("handle_dialog: {e}"))?;
    Ok(ActionOutput::None)
}

// Verified: DispatchMouseEventParams x/y fields are f64, matching the f64
// values from getBoundingClientRect(). No silent truncation occurs.
pub(crate) async fn do_hover(
    page: &Page,
    selector: &str,
    humanize: bool,
    acc: &mut super::types::ActionAccumulator,
) -> Result<ActionOutput, String> {
    if humanize {
        use super::humanize::bezier::Point;
        use super::humanize::mouse::{ensure_visible, move_to};
        let bounds = ensure_visible(page, selector).await?;
        let target = Point::new(
            bounds.x + bounds.width / 2.0,
            bounds.y + bounds.height / 2.0,
        );
        let from = Point::new(acc.cursor_x, acc.cursor_y);
        move_to(page, from, target, false).await?;
        acc.cursor_x = target.x;
        acc.cursor_y = target.y;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        return Ok(ActionOutput::None);
    }

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

pub(crate) async fn do_go_back(page: &Page) -> Result<ActionOutput, String> {
    use chromiumoxide::cdp::browser_protocol::page::GetNavigationHistoryParams;

    // Use CDP to check if there's a previous entry to go back to.
    let history = page
        .execute(GetNavigationHistoryParams {})
        .await
        .map_err(|e| format!("go_back history: {e}"))?;

    let idx = history.result.current_index as usize;
    if idx == 0 {
        // Already at the first entry -- nothing to go back to.
        return Ok(ActionOutput::None);
    }

    // Check the previous entry isn't about:blank (Chrome's initial page).
    let entries = &history.result.entries;
    if idx > 0 {
        if let Some(prev) = entries.get(idx - 1) {
            if prev.url == "about:blank" {
                return Ok(ActionOutput::None);
            }
        }
    }

    page.evaluate("window.history.back()")
        .await
        .map_err(|e| format!("go_back: {e}"))?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Ok(ActionOutput::None)
}
