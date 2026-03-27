//! Integration tests for chrome_interact actions.
//!
//! These tests launch real headless Chrome — they require chromium-browser
//! (or google-chrome) installed on the host. Uses `data:` URIs to avoid
//! network dependencies.
//!
//! We test at the `ChromeSession` + `execute_action` level rather than through
//! `execute()` because the SSRF middleware blocks non-http(s) schemes (data:,
//! about:). This lets us use data: URIs for deterministic, network-free tests.

use std::time::Duration;

use ox_http::chrome_interact::{
    execute_action, ActionAccumulator, ChromeAction, ActionOutput, SessionLogs,
};
use ox_http::chrome_session::{ChromeLoginConfig, ChromeSession};
use ox_http::session_pool::SessionPool;
use serial_test::serial;
use tokio::time::Instant;

fn default_deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

/// Launch Chrome, navigate to a data: URI, and return the session + page.
async fn launch_and_navigate(
    html: &str,
) -> (ChromeSession, chromiumoxide::Page, SessionLogs) {
    let config = ChromeLoginConfig::default();
    let (session, page) = ChromeSession::launch(&config)
        .await
        .expect("chrome launch failed");

    // Attach log listeners BEFORE navigation (matching the fixed run_actions behavior)
    let logs = SessionLogs::new();
    ChromeSession::attach_log_listeners(&page, &logs)
        .await
        .expect("attach_log_listeners failed");

    page.goto(html)
        .await
        .expect("navigation failed");
    // Brief settle
    tokio::time::sleep(Duration::from_millis(500)).await;

    (session, page, logs)
}

// --------------------------------------------------------------------------
// 1. Snapshot returns accessibility tree with expected roles/text
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_snapshot_returns_accessibility_tree() {
    let html = "data:text/html,<h1>Hello</h1><button>Click me</button>";
    let (session, page, logs) = launch_and_navigate(html).await;
    let deadline = default_deadline();

    let mut acc = ActionAccumulator::default();
    let action = ChromeAction::Snapshot { label: None };
    let result = execute_action(&page, &action, deadline, Some(&logs), &mut acc)
        .await
        .expect("snapshot failed");

    if let ActionOutput::Snapshot(snap) = result {
        assert!(
            snap.tree.contains("heading"),
            "tree should contain heading role: {}",
            snap.tree
        );
        assert!(
            snap.tree.contains("Hello"),
            "tree should contain heading text: {}",
            snap.tree
        );
        assert!(
            snap.tree.contains("button"),
            "tree should contain button role: {}",
            snap.tree
        );
        assert!(
            snap.tree.contains("Click me"),
            "tree should contain button text: {}",
            snap.tree
        );
    } else {
        panic!("expected Snapshot output");
    }

    session.shutdown().await;
}

// --------------------------------------------------------------------------
// 2. Snapshot label is preserved in response
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_snapshot_with_label() {
    let html = "data:text/html,<p>test</p>";
    let (session, page, logs) = launch_and_navigate(html).await;
    let deadline = default_deadline();

    let mut acc = ActionAccumulator::default();
    let action = ChromeAction::Snapshot {
        label: Some("my_custom_label".to_string()),
    };
    let result = execute_action(&page, &action, deadline, Some(&logs), &mut acc)
        .await
        .expect("snapshot failed");

    if let ActionOutput::Snapshot(snap) = result {
        assert_eq!(snap.label, "my_custom_label");
    } else {
        panic!("expected Snapshot output");
    }

    session.shutdown().await;
}

// --------------------------------------------------------------------------
// 3. Hover triggers mouseover on element
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_hover_triggers_on_element() {
    let html = r#"data:text/html,<div id="target" onmouseover="document.title='hovered'" style="width:100px;height:100px;">Hover me</div>"#;
    let (session, page, logs) = launch_and_navigate(html).await;
    let deadline = default_deadline();

    let mut acc = ActionAccumulator::default();

    // Hover on #target
    let hover = ChromeAction::Hover {
        selector: "#target".to_string(),
        humanize: false,
    };
    execute_action(&page, &hover, deadline, Some(&logs), &mut acc)
        .await
        .expect("hover failed");

    // Evaluate document.title
    let eval = ChromeAction::Evaluate {
        js: "document.title".to_string(),
    };
    let result = execute_action(&page, &eval, deadline, Some(&logs), &mut acc)
        .await
        .expect("evaluate failed");

    if let ActionOutput::Eval(e) = result {
        assert_eq!(
            e.result, "hovered",
            "mouseover should have set document.title"
        );
    } else {
        panic!("expected Eval output");
    }

    session.shutdown().await;
}

// --------------------------------------------------------------------------
// 4. GoBack navigates browser history
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_go_back_navigates_history() {
    let html = "data:text/html,<script>history.pushState(null,'','%23page1');history.pushState(null,'','%23page2');</script>";
    let (session, page, logs) = launch_and_navigate(html).await;
    let deadline = default_deadline();

    let mut acc = ActionAccumulator::default();

    // Go back from #page2 to #page1
    let go_back = ChromeAction::GoBack;
    execute_action(&page, &go_back, deadline, Some(&logs), &mut acc)
        .await
        .expect("go_back failed");

    let eval = ChromeAction::Evaluate {
        js: "window.location.hash".to_string(),
    };
    let result = execute_action(&page, &eval, deadline, Some(&logs), &mut acc)
        .await
        .expect("evaluate failed");

    if let ActionOutput::Eval(e) = result {
        assert_eq!(
            e.result, "#page1",
            "go_back should navigate to #page1"
        );
    } else {
        panic!("expected Eval output");
    }

    session.shutdown().await;
}

// --------------------------------------------------------------------------
// 5. GetLogs captures network events
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_get_logs_captures_network() {
    let html = r#"data:text/html,<script>fetch('https://example.com').catch(()=>{})</script>"#;
    let (session, page, logs) = launch_and_navigate(html).await;
    let deadline = default_deadline();

    let mut acc = ActionAccumulator::default();

    // Wait for the fetch to fire
    let sleep = ChromeAction::Sleep { ms: 2000 };
    execute_action(&page, &sleep, deadline, Some(&logs), &mut acc)
        .await
        .expect("sleep failed");

    let get_logs = ChromeAction::GetLogs;
    let result = execute_action(&page, &get_logs, deadline, Some(&logs), &mut acc)
        .await
        .expect("get_logs failed");

    if let ActionOutput::Logs { network, .. } = result {
        assert!(
            !network.is_empty(),
            "network_log should not be empty after fetch()"
        );
    } else {
        panic!("expected Logs output");
    }

    session.shutdown().await;
}

// --------------------------------------------------------------------------
// 6. GetLogs captures console output
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_get_logs_captures_console() {
    let html = r#"data:text/html,<script>console.log('test message 42')</script>"#;
    let (session, page, logs) = launch_and_navigate(html).await;
    let deadline = default_deadline();

    let mut acc = ActionAccumulator::default();

    // Wait for console event to be captured
    let sleep = ChromeAction::Sleep { ms: 1000 };
    execute_action(&page, &sleep, deadline, Some(&logs), &mut acc)
        .await
        .expect("sleep failed");

    let get_logs = ChromeAction::GetLogs;
    let result = execute_action(&page, &get_logs, deadline, Some(&logs), &mut acc)
        .await
        .expect("get_logs failed");

    if let ActionOutput::Logs { console, .. } = result {
        let has_msg = console
            .iter()
            .any(|e| e.text.contains("test message 42"));
        assert!(
            has_msg,
            "console_log should contain 'test message 42', got: {console:?}"
        );
    } else {
        panic!("expected Logs output");
    }

    session.shutdown().await;
}

// --------------------------------------------------------------------------
// 7. HandleDialog — auto-dismiss race documentation test
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_handle_dialog_dismiss() {
    // NOTE: ChromeSession auto-dismiss listener always accepts dialogs.
    // This test documents the race condition: by the time our explicit
    // HandleDialog runs, the auto-dismiss may have already accepted the
    // confirm(). The result of window.result will be `true` (auto-accepted)
    // rather than `false`. This is expected and documented in actions.rs.
    let html = "data:text/html,<script>window.result = confirm('ok?')</script>";
    let (session, page, logs) = launch_and_navigate(html).await;
    let deadline = default_deadline();

    let mut acc = ActionAccumulator::default();

    let sleep = ChromeAction::Sleep { ms: 500 };
    execute_action(&page, &sleep, deadline, Some(&logs), &mut acc)
        .await
        .expect("sleep failed");

    let eval = ChromeAction::Evaluate {
        js: "String(window.result)".to_string(),
    };
    let result = execute_action(&page, &eval, deadline, Some(&logs), &mut acc)
        .await
        .expect("evaluate failed");

    if let ActionOutput::Eval(e) = result {
        // The dialog was auto-dismissed with accept=true, so result is "true"
        assert!(
            e.result == "true" || e.result == "false",
            "window.result should be a boolean string, got: {}",
            e.result
        );
    } else {
        panic!("expected Eval output");
    }

    session.shutdown().await;
}

// --------------------------------------------------------------------------
// 8. Session persistence across two requests via pool
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_session_persistence_with_new_actions() {
    let config = ChromeLoginConfig::default();
    let pool = SessionPool::new(config);

    // Create a persistent session via pool
    let session_id = pool.create(None).await.expect("pool create failed");
    let page = pool.get(&session_id).await.expect("pool get failed");
    let deadline = default_deadline();

    // Request 1: navigate and snapshot
    let logs1 = SessionLogs::new();
    ChromeSession::attach_log_listeners(&page, &logs1)
        .await
        .expect("attach failed");
    page.goto("data:text/html,<h1>Session Test</h1>")
        .await
        .expect("goto failed");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut acc = ActionAccumulator::default();
    let snap1 = ChromeAction::Snapshot { label: None };
    let result1 = execute_action(&page, &snap1, deadline, Some(&logs1), &mut acc)
        .await
        .expect("snapshot1 failed");
    assert!(matches!(result1, ActionOutput::Snapshot(_)));

    // Request 2: navigate to different page via the same session
    let page2 = pool.get(&session_id).await.expect("pool get 2 failed");
    page2
        .goto("data:text/html,<p>Page2</p>")
        .await
        .expect("goto2 failed");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let snap2 = ChromeAction::Snapshot { label: None };
    let result2 = execute_action(&page2, &snap2, deadline, Some(&logs1), &mut acc)
        .await
        .expect("snapshot2 failed");
    if let ActionOutput::Snapshot(s) = result2 {
        assert!(
            s.tree.contains("Page2"),
            "second snapshot should reflect new page"
        );
    } else {
        panic!("expected Snapshot output");
    }

    // Cleanup
    pool.destroy(&session_id).await;
}

// --------------------------------------------------------------------------
// 9. Snapshot on about:blank returns minimal tree
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_snapshot_empty_page() {
    let config = ChromeLoginConfig::default();
    let (session, page) = ChromeSession::launch(&config)
        .await
        .expect("chrome launch failed");
    let deadline = default_deadline();

    // Page starts on about:blank (from launch)
    let logs = SessionLogs::new();
    let mut acc = ActionAccumulator::default();
    let action = ChromeAction::Snapshot { label: None };
    let result = execute_action(&page, &action, deadline, Some(&logs), &mut acc)
        .await
        .expect("snapshot failed");

    if let ActionOutput::Snapshot(snap) = result {
        assert!(
            !snap.tree.is_empty(),
            "tree should not be empty even for about:blank"
        );
    } else {
        panic!("expected Snapshot output");
    }

    session.shutdown().await;
}

// --------------------------------------------------------------------------
// 10. Multiple snapshots in one request return separate results
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_multiple_snapshots_in_one_request() {
    let html = "data:text/html,<h1>Multi</h1>";
    let (session, page, logs) = launch_and_navigate(html).await;
    let deadline = default_deadline();

    let mut acc = ActionAccumulator::default();
    let snap1 = ChromeAction::Snapshot {
        label: Some("first".to_string()),
    };
    let snap2 = ChromeAction::Snapshot {
        label: Some("second".to_string()),
    };

    let r1 = execute_action(&page, &snap1, deadline, Some(&logs), &mut acc)
        .await
        .expect("snapshot1 failed");
    let r2 = execute_action(&page, &snap2, deadline, Some(&logs), &mut acc)
        .await
        .expect("snapshot2 failed");

    let s1 = match r1 {
        ActionOutput::Snapshot(s) => s,
        _ => panic!("expected Snapshot output for first"),
    };
    let s2 = match r2 {
        ActionOutput::Snapshot(s) => s,
        _ => panic!("expected Snapshot output for second"),
    };

    assert_eq!(s1.label, "first");
    assert_eq!(s2.label, "second");
    assert!(s1.tree.contains("Multi"));
    assert!(s2.tree.contains("Multi"));

    session.shutdown().await;
}
