//! Human-like mouse movement via CDP with auto-scroll and clickability checks.

use chromiumoxide::cdp::browser_protocol::input::{
    DispatchMouseEventParams, DispatchMouseEventType, MouseButton,
};
use chromiumoxide::Page;
use rand::Rng;

use super::bezier::{bezier_path, with_overshoot, Point};

/// Element bounding rectangle.
#[derive(Debug, Clone, Copy)]
pub struct ElementBounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// Get element bounds via JS getBoundingClientRect.
pub async fn get_element_bounds(page: &Page, selector: &str) -> Result<ElementBounds, String> {
    let js = format!(
        r#"(() => {{
            const el = document.querySelector('{}');
            if (!el) return null;
            const r = el.getBoundingClientRect();
            return JSON.stringify({{ x: r.x, y: r.y, w: r.width, h: r.height }});
        }})()"#,
        selector.replace('\'', "\\'")
    );
    let result: serde_json::Value = page
        .evaluate(js)
        .await
        .map_err(|e| format!("bounds: {e}"))?
        .into_value()
        .unwrap_or(serde_json::Value::Null);

    let json_str = match &result {
        serde_json::Value::String(s) => s.clone(),
        _ => return Err(format!("element '{selector}' not found")),
    };

    let v: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|_| format!("element '{selector}' not found"))?;

    Ok(ElementBounds {
        x: v["x"].as_f64().unwrap_or(0.0),
        y: v["y"].as_f64().unwrap_or(0.0),
        width: v["w"].as_f64().unwrap_or(0.0),
        height: v["h"].as_f64().unwrap_or(0.0),
    })
}

/// Check if element is in viewport. If not, scroll to it smoothly.
/// Returns updated bounds after potential scroll.
pub async fn ensure_visible(page: &Page, selector: &str) -> Result<ElementBounds, String> {
    let js = format!(
        r#"(() => {{
            const el = document.querySelector('{}');
            if (!el) return null;
            const r = el.getBoundingClientRect();
            const vw = window.innerWidth;
            const vh = window.innerHeight;
            const inView = r.top >= 0 && r.left >= 0 && r.bottom <= vh && r.right <= vw;
            if (!inView) {{
                el.scrollIntoView({{ behavior: 'smooth', block: 'center', inline: 'center' }});
            }}
            return JSON.stringify({{ inView }});
        }})()"#,
        selector.replace('\'', "\\'")
    );
    page.evaluate(js).await.map_err(|e| format!("ensure_visible: {e}"))?;

    // Wait for smooth scroll to finish
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    // Get fresh bounds after scroll
    get_element_bounds(page, selector).await
}

/// Check if element at given point is the expected one (not obscured by overlay).
/// Uses document.elementFromPoint — the standard clickability check from GhostCursor.
pub async fn is_clickable(page: &Page, selector: &str, x: f64, y: f64) -> Result<bool, String> {
    let js = format!(
        r#"(() => {{
            const target = document.querySelector('{}');
            if (!target) return false;
            const topEl = document.elementFromPoint({x}, {y});
            if (!topEl) return false;
            return target === topEl || target.contains(topEl) || topEl.contains(target);
        }})()"#,
        selector.replace('\'', "\\'"),
        x = x,
        y = y,
    );
    let result: bool = page
        .evaluate(js)
        .await
        .map_err(|e| format!("clickable check: {e}"))?
        .into_value()
        .unwrap_or(false);
    Ok(result)
}

/// Move mouse from `from` to `to` along a Bezier curve with Fitts's Law timing.
pub async fn move_to(
    page: &Page,
    from: Point,
    to: Point,
    overshoot: bool,
) -> Result<(), String> {
    let distance = from.distance(&to);
    let steps = (distance / 5.0).clamp(10.0, 80.0) as usize;

    let mut path = bezier_path(from, to, steps);
    if overshoot && distance > 50.0 {
        // Generate before any .await to avoid holding !Send ThreadRng across suspension.
        let overshoot_px = rand::thread_rng().gen_range(3.0..12.0);
        with_overshoot(&mut path, to, overshoot_px);
    }

    let base_delay_ms = (2.0 + distance.ln().max(0.0) * 0.5) as u64;

    for point in &path {
        let params = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MouseMoved)
            .x(point.x)
            .y(point.y)
            .build()
            .map_err(|e| format!("mouse move: {e}"))?;
        page.execute(params).await.map_err(|e| format!("mouse dispatch: {e}"))?;

        // Generate jitter before .await to avoid holding !Send ThreadRng across suspension.
        let jitter = rand::thread_rng().gen_range(0u64..=2);
        tokio::time::sleep(std::time::Duration::from_millis(base_delay_ms + jitter)).await;
    }
    Ok(())
}

/// Full humanized click: scroll into view → check clickable → Bezier move → click with hesitation.
pub async fn humanized_click(
    page: &Page,
    from: Point,
    selector: &str,
) -> Result<Point, String> {
    // 1. Ensure element is in viewport
    let bounds = ensure_visible(page, selector).await?;

    // 2. Pick random point within element bounds (biased toward center).
    // Generate all random values upfront to avoid holding !Send ThreadRng across .await.
    let target = {
        let mut rng = rand::thread_rng();
        Point::new(
            bounds.x + bounds.width * rng.gen_range(0.25..0.75),
            bounds.y + bounds.height * rng.gen_range(0.25..0.75),
        )
    };

    // 3. Check clickability (not obscured by overlay)
    if !is_clickable(page, selector, target.x, target.y).await? {
        return Err(format!(
            "element '{selector}' is obscured by another element at ({:.0}, {:.0})",
            target.x, target.y
        ));
    }

    // 4. Move mouse along Bezier curve
    move_to(page, from, target, true).await?;

    // 5. Hesitation before click (50-150ms) — generate before .await
    let hesitation = rand::thread_rng().gen_range(50u64..150);
    tokio::time::sleep(std::time::Duration::from_millis(hesitation)).await;

    // 6. Mouse down
    let down = DispatchMouseEventParams::builder()
        .r#type(DispatchMouseEventType::MousePressed)
        .x(target.x)
        .y(target.y)
        .button(MouseButton::Left)
        .click_count(1i64)
        .build()
        .map_err(|e| format!("mouse down: {e}"))?;
    page.execute(down).await.map_err(|e| format!("click down: {e}"))?;

    // 7. Hold (30-80ms) — generate before .await
    let hold = rand::thread_rng().gen_range(30u64..80);
    tokio::time::sleep(std::time::Duration::from_millis(hold)).await;

    // 8. Mouse up
    let up = DispatchMouseEventParams::builder()
        .r#type(DispatchMouseEventType::MouseReleased)
        .x(target.x)
        .y(target.y)
        .button(MouseButton::Left)
        .click_count(1i64)
        .build()
        .map_err(|e| format!("mouse up: {e}"))?;
    page.execute(up).await.map_err(|e| format!("click up: {e}"))?;

    Ok(target)
}
