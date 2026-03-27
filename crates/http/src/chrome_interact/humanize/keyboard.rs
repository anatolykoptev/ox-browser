//! Human-like keyboard input with variable delays.
//!
//! Uses dispatchKeyEvent for CDP events (Castle.io sees proper keyboard activity)
//! plus InsertText for actual text insertion (React controlled inputs need this).

use chromiumoxide::cdp::browser_protocol::input::{
    DispatchKeyEventParams, DispatchKeyEventType, InsertTextParams,
};
use chromiumoxide::Page;
use rand::Rng;
use rand_distr::{Distribution, Normal};

/// Type text with Gaussian-distributed delays (mean 80ms, sigma 25ms).
/// Fires keyDown/keyUp events AND InsertText for React compatibility.
pub async fn humanized_type(page: &Page, text: &str) -> Result<(), String> {
    let normal = Normal::new(80.0, 25.0).unwrap();
    let mut prev_char = '\0';

    for ch in text.chars() {
        dispatch_char(page, ch).await?;

        let delay = {
            let mut rng = rand::thread_rng();
            let sampled: f64 = normal.sample(&mut rng);
            let mut d = sampled.clamp(30.0_f64, 200.0_f64);
            if ch == prev_char { d *= 0.6; }
            if ch == ' ' || ch == '.' || ch == ',' {
                d += rng.gen_range(80.0..200.0);
            }
            d
        };

        tokio::time::sleep(std::time::Duration::from_millis(delay as u64)).await;
        prev_char = ch;
    }
    Ok(())
}

/// Dispatch a single character: keyDown → InsertText → keyUp.
/// keyDown/keyUp generate proper CDP keyboard events for bot detection.
/// InsertText ensures React controlled inputs get the value update.
pub(crate) async fn dispatch_char(page: &Page, ch: char) -> Result<(), String> {
    let text = ch.to_string();

    // 1. keyDown — Castle.io sees keyboard activity
    let mut down = DispatchKeyEventParams::new(DispatchKeyEventType::KeyDown);
    down.key = Some(text.clone());
    page.execute(down)
        .await
        .map_err(|e| format!("keyDown '{ch}': {e}"))?;

    // 2. InsertText — React gets the value change
    page.execute(InsertTextParams { text: text.clone() })
        .await
        .map_err(|e| format!("insertText '{ch}': {e}"))?;

    // 3. keyUp — completes the keyboard event chain
    let mut up = DispatchKeyEventParams::new(DispatchKeyEventType::KeyUp);
    up.key = Some(text);
    page.execute(up)
        .await
        .map_err(|e| format!("keyUp '{ch}': {e}"))?;

    Ok(())
}
