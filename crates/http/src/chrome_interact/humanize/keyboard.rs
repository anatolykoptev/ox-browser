//! Human-like keyboard input with variable delays.

use chromiumoxide::cdp::browser_protocol::input::InsertTextParams;
use chromiumoxide::Page;
use rand::Rng;
use rand_distr::{Distribution, Normal};

/// Type text with Gaussian-distributed delays (mean 80ms, σ25ms).
/// Pauses longer at word boundaries. Faster on repeated chars.
pub async fn humanized_type(page: &Page, text: &str) -> Result<(), String> {
    let normal = Normal::new(80.0, 25.0).unwrap();
    let mut prev_char = '\0';

    for ch in text.chars() {
        page.execute(InsertTextParams { text: ch.to_string() })
            .await
            .map_err(|e| format!("type '{ch}': {e}"))?;

        // Generate delay before the .await to avoid holding !Send ThreadRng across it.
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
