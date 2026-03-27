//! Idle cursor micro-movements to prevent "dead cursor" detection.

use chromiumoxide::cdp::browser_protocol::input::{
    DispatchMouseEventParams, DispatchMouseEventType,
};
use chromiumoxide::Page;
use rand::Rng;

/// Small random mouse drifts during a wait period.
/// 1-3 moves per second, ±3px drift, clamped to ±15px from center.
pub async fn idle_drift(
    page: &Page,
    center_x: f64,
    center_y: f64,
    duration_ms: u64,
) -> Result<(), String> {
    let mut rng = rand::thread_rng();
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(duration_ms);
    let mut x = center_x;
    let mut y = center_y;

    while tokio::time::Instant::now() < deadline {
        x = (x + rng.gen_range(-3.0..3.0)).clamp(center_x - 15.0, center_x + 15.0);
        y = (y + rng.gen_range(-3.0..3.0)).clamp(center_y - 15.0, center_y + 15.0);

        let params = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MouseMoved)
            .x(x).y(y)
            .build()
            .map_err(|e| format!("idle drift: {e}"))?;
        page.execute(params).await.map_err(|e| format!("idle: {e}"))?;

        tokio::time::sleep(std::time::Duration::from_millis(
            rng.gen_range(300..800),
        )).await;
    }
    Ok(())
}
