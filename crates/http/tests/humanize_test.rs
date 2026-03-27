//! Tests for the humanize layer — bezier math (unit) + humanized actions (integration).
//!
//! Unit tests: no Chrome required.
//! Integration tests: launch real headless Chrome via `launch_and_navigate`, tagged `#[serial]`.

use std::time::Duration;

use ox_http::chrome_interact::{execute_action, ActionAccumulator, ActionOutput, ChromeAction, SessionLogs};
use ox_http::chrome_interact::humanize::bezier::{bezier_path, with_overshoot, Point};
use ox_http::chrome_session::{ChromeLoginConfig, ChromeSession};
use serial_test::serial;
use tokio::time::Instant;

fn default_deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

/// Launch Chrome, navigate to a data: URI, and return the session + page.
async fn launch_and_navigate(html: &str) -> (ChromeSession, chromiumoxide::Page, SessionLogs) {
    let config = ChromeLoginConfig::default();
    let (session, page) = ChromeSession::launch(&config)
        .await
        .expect("chrome launch failed");

    let logs = SessionLogs::new();
    ChromeSession::attach_log_listeners(&page, &logs)
        .await
        .expect("attach_log_listeners failed");

    page.goto(html).await.expect("navigation failed");
    tokio::time::sleep(Duration::from_millis(500)).await;

    (session, page, logs)
}

// ==========================================================================
// Unit tests — bezier math, no Chrome needed
// ==========================================================================

#[test]
fn test_bezier_path_correct_endpoints() {
    let start = Point::new(100.0, 200.0);
    let end = Point::new(500.0, 400.0);
    let path = bezier_path(start, end, 20);

    // bezier_path(start, end, N) produces N+1 points
    assert_eq!(path.len(), 21, "expected 21 points (0..=20)");

    // First point must be exactly at start (t=0)
    let first = path[0];
    assert!(
        (first.x - start.x).abs() < 1e-9 && (first.y - start.y).abs() < 1e-9,
        "first point should equal start: got ({:.4}, {:.4}), expected ({:.4}, {:.4})",
        first.x, first.y, start.x, start.y
    );

    // Last point must be exactly at end (t=1)
    let last = *path.last().unwrap();
    assert!(
        (last.x - end.x).abs() < 1e-9 && (last.y - end.y).abs() < 1e-9,
        "last point should equal end: got ({:.4}, {:.4}), expected ({:.4}, {:.4})",
        last.x, last.y, end.x, end.y
    );
}

#[test]
fn test_bezier_path_not_straight_line() {
    // Horizontal path: start and end share y=0.  A straight line would keep y=0
    // for all midpoints.  The Bezier curve adds random control-point offsets
    // proportional to `spread = distance * 0.3`, so at least some midpoints
    // should deviate from y=0 (with very high probability for any non-trivial
    // distance).  We run several samples and require at least one curved path.
    let start = Point::new(0.0, 0.0);
    let end = Point::new(400.0, 0.0);

    let mut found_curve = false;
    for _ in 0..10 {
        let path = bezier_path(start, end, 20);
        // Check midpoints (skip first and last which are exact endpoints)
        let any_off = path[1..path.len() - 1]
            .iter()
            .any(|p| p.y.abs() > 1e-6);
        if any_off {
            found_curve = true;
            break;
        }
    }
    assert!(
        found_curve,
        "expected at least one curved path over 10 samples for a horizontal 400px move"
    );
}

#[test]
fn test_overshoot_extends_path() {
    let start = Point::new(0.0, 0.0);
    let target = Point::new(300.0, 0.0);
    let mut path = bezier_path(start, target, 20);
    let original_len = path.len();

    with_overshoot(&mut path, target, 10.0);

    // with_overshoot adds the overshoot point + correction path (at least 2 extra points)
    assert!(
        path.len() > original_len,
        "path should be longer after overshoot: was {original_len}, now {}",
        path.len()
    );

    // After correction, the last point should be close to the original target
    let last = *path.last().unwrap();
    let dist_to_target = ((last.x - target.x).powi(2) + (last.y - target.y).powi(2)).sqrt();
    assert!(
        dist_to_target < 5.0,
        "last point should be near target after correction: dist = {dist_to_target:.2}"
    );
}

#[test]
fn test_fitts_law_scaling() {
    // Longer distance → more steps (mirrors `move_to`: steps = (dist/5).clamp(10, 80))
    // We verify the formula directly: short distance → ~10 steps, long → ~80.

    // Short: 40px → (40/5).clamp(10,80) = 10 steps → 11 points
    let short_steps = ((40.0_f64 / 5.0).clamp(10.0, 80.0)) as usize;
    let path_short = bezier_path(Point::new(0.0, 0.0), Point::new(40.0, 0.0), short_steps);
    assert_eq!(path_short.len(), 11, "short path should have 11 points");

    // Long: 800px → (800/5).clamp(10,80) = 80 steps → 81 points
    let long_steps = ((800.0_f64 / 5.0).clamp(10.0, 80.0)) as usize;
    let path_long = bezier_path(Point::new(0.0, 0.0), Point::new(800.0, 0.0), long_steps);
    assert_eq!(path_long.len(), 81, "long path should have 81 points");

    // Longer distance produces more path points than shorter distance
    assert!(
        path_long.len() > path_short.len(),
        "longer distance should produce more steps: short={}, long={}",
        path_short.len(),
        path_long.len()
    );
}

// ==========================================================================
// Integration tests — real Chrome required
// ==========================================================================

// --------------------------------------------------------------------------
// Humanized click triggers JS event
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_humanized_click_triggers_event() {
    // The button onclick sets document.title so we can assert it was fired.
    let html = r#"data:text/html,<button id="btn" onclick="document.title='clicked'" style="width:120px;height:50px;">Click me</button>"#;
    let (session, page, logs) = launch_and_navigate(html).await;
    let deadline = default_deadline();

    let mut acc = ActionAccumulator::default();

    // Click with humanize: true
    let click = ChromeAction::Click {
        selector: "#btn".to_string(),
        humanize: true,
    };
    execute_action(&page, &click, deadline, Some(&logs), &mut acc)
        .await
        .expect("humanized click failed");

    // Read document.title
    let eval = ChromeAction::Evaluate {
        js: "document.title".to_string(),
    };
    let result = execute_action(&page, &eval, deadline, Some(&logs), &mut acc)
        .await
        .expect("evaluate failed");

    if let ActionOutput::Eval(e) = result {
        assert_eq!(
            e.result, "clicked",
            "humanized click should have triggered onclick and set document.title"
        );
    } else {
        panic!("expected Eval output");
    }

    session.shutdown().await;
}

// --------------------------------------------------------------------------
// Humanized type produces text in input
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_humanized_type_produces_text() {
    // The input event handler copies the input value to document.title.
    let html = r#"data:text/html,<input id="inp" oninput="document.title=this.value" style="width:200px;">"#;
    let (session, page, logs) = launch_and_navigate(html).await;
    let deadline = default_deadline();

    let mut acc = ActionAccumulator::default();

    // Click the input first to focus it (humanize: false for speed)
    let click = ChromeAction::Click {
        selector: "#inp".to_string(),
        humanize: false,
    };
    execute_action(&page, &click, deadline, Some(&logs), &mut acc)
        .await
        .expect("focus click failed");

    // Type with humanize: true
    let type_action = ChromeAction::TypeText {
        selector: "#inp".to_string(),
        text: "hello".to_string(),
        humanize: true,
    };
    execute_action(&page, &type_action, deadline, Some(&logs), &mut acc)
        .await
        .expect("humanized type failed");

    // Give the last input event a moment to fire
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Read document.title (set by oninput)
    let eval = ChromeAction::Evaluate {
        js: "document.title".to_string(),
    };
    let result = execute_action(&page, &eval, deadline, Some(&logs), &mut acc)
        .await
        .expect("evaluate failed");

    if let ActionOutput::Eval(e) = result {
        assert!(
            e.result.contains("hello"),
            "humanized type should have produced 'hello' in title, got: {:?}",
            e.result
        );
    } else {
        panic!("expected Eval output");
    }

    session.shutdown().await;
}

// --------------------------------------------------------------------------
// humanize: false is backward-compatible (click still fires the event)
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_humanize_false_backward_compatible() {
    let html = r#"data:text/html,<button id="btn" onclick="document.title='clicked'" style="width:120px;height:50px;">Click me</button>"#;
    let (session, page, logs) = launch_and_navigate(html).await;
    let deadline = default_deadline();

    let mut acc = ActionAccumulator::default();

    // Click with humanize: false (legacy code path)
    let click = ChromeAction::Click {
        selector: "#btn".to_string(),
        humanize: false,
    };
    execute_action(&page, &click, deadline, Some(&logs), &mut acc)
        .await
        .expect("non-humanized click failed");

    let eval = ChromeAction::Evaluate {
        js: "document.title".to_string(),
    };
    let result = execute_action(&page, &eval, deadline, Some(&logs), &mut acc)
        .await
        .expect("evaluate failed");

    if let ActionOutput::Eval(e) = result {
        assert_eq!(
            e.result, "clicked",
            "non-humanized click should also fire onclick and set document.title"
        );
    } else {
        panic!("expected Eval output");
    }

    session.shutdown().await;
}
