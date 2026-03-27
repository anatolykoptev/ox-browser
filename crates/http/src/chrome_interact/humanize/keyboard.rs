//! Human-like keyboard input with variable delays via dispatchKeyEvent.

use chromiumoxide::cdp::browser_protocol::input::{
    DispatchKeyEventParams, DispatchKeyEventType,
};
use chromiumoxide::Page;
use rand::Rng;
use rand_distr::{Distribution, Normal};

/// Type text with Gaussian-distributed delays (mean 80ms, sigma 25ms).
/// Uses dispatchKeyEvent (keyDown + keyUp) instead of InsertText
/// to match real browser keyboard event chains.
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

/// Dispatch a single character as keyDown(text) + keyUp.
pub(crate) async fn dispatch_char(page: &Page, ch: char) -> Result<(), String> {
    let text = ch.to_string();

    let mut down = DispatchKeyEventParams::new(DispatchKeyEventType::KeyDown);
    down.text = Some(text.clone());
    down.unmodified_text = Some(text.clone());
    down.key = Some(text.clone());
    page.execute(down)
        .await
        .map_err(|e| format!("keyDown '{ch}': {e}"))?;

    let up = DispatchKeyEventParams::new(DispatchKeyEventType::KeyUp);
    page.execute(up)
        .await
        .map_err(|e| format!("keyUp '{ch}': {e}"))?;

    Ok(())
}
