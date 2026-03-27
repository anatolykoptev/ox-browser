//! Hard red tests for BrowserPool — edge cases, error paths, lifecycle bugs.
//!
//! Each test targets a specific bug hypothesis. If a test fails, the hypothesis
//! is confirmed and the bug needs fixing.

use std::time::Duration;

use ox_http::browser_pool::BrowserPool;
use ox_http::chrome_session::ChromeLoginConfig;
use serial_test::serial;

// --------------------------------------------------------------------------
// 1. Double destroy — second call must return false, not panic
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn hard_red_double_destroy() {
    let pool = BrowserPool::new(ChromeLoginConfig::default());
    let (id, _page) = pool.create(None).await.unwrap();

    assert!(pool.destroy(&id).await, "first destroy should return true");
    assert!(!pool.destroy(&id).await, "second destroy must return false");
    assert_eq!(pool.len().await, 0);
}

// --------------------------------------------------------------------------
// 2. Get nonexistent session — must return None, not panic
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn hard_red_get_nonexistent() {
    let pool = BrowserPool::new(ChromeLoginConfig::default());
    assert!(pool.get("nonexistent-id-12345").await.is_none());
}

// --------------------------------------------------------------------------
// 3. Destroy nonexistent session — must return false
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn hard_red_destroy_nonexistent() {
    let pool = BrowserPool::new(ChromeLoginConfig::default());
    assert!(!pool.destroy("nonexistent-id-12345").await);
}

// --------------------------------------------------------------------------
// 4. Page becomes unusable after destroy (context disposed)
//    Bug hypothesis: page handle still works after BrowserContext is disposed
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn hard_red_page_after_destroy() {
    let pool = BrowserPool::new(ChromeLoginConfig::default());
    let (id, page) = pool.create(None).await.unwrap();

    // Navigate while session is alive — should work
    page.goto("data:text/html,<h1>alive</h1>").await.unwrap();

    // Destroy disposes the BrowserContext
    pool.destroy(&id).await;

    // Page handle still exists but context is disposed — navigation should fail
    let result = page.goto("data:text/html,<h1>dead</h1>").await;
    assert!(
        result.is_err(),
        "BUG: page.goto succeeded after context was disposed — page should be unusable"
    );
}

// --------------------------------------------------------------------------
// 5. Create after full cleanup — browser must restart
//    Bug hypothesis: after all sessions destroyed + browser closed,
//    next create fails because browser map has stale state
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn hard_red_create_after_full_cleanup() {
    let pool = BrowserPool::new(ChromeLoginConfig::default());

    // Create and destroy — should trigger close_empty_browsers in reap
    let (id1, _p1) = pool.create(None).await.unwrap();
    pool.destroy(&id1).await;

    // Force reap to close the empty browser
    pool.reap_expired().await;

    // Now create again — must launch a new browser, not fail
    let (id2, page2) = pool.create(None).await.expect(
        "BUG: create failed after full cleanup — browser wasn't re-launched"
    );
    page2.goto("data:text/html,<h1>reborn</h1>").await.unwrap();

    pool.destroy(&id2).await;
}

// --------------------------------------------------------------------------
// 6. Rapid create/destroy cycles — tab_count must stay consistent
//    Bug hypothesis: tab_count drifts after many create/destroy cycles
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn hard_red_rapid_create_destroy_cycles() {
    let pool = BrowserPool::new(ChromeLoginConfig::default());

    for i in 0..5 {
        let (id, _page) = pool.create(None).await
            .unwrap_or_else(|e| panic!("BUG: create failed at cycle {i}: {e}"));
        pool.destroy(&id).await;
    }

    assert_eq!(pool.len().await, 0, "BUG: sessions leaked after create/destroy cycles");

    // After all destroyed, reap should clean up the browser
    pool.reap_expired().await;

    // One more create to verify browser is healthy
    let (id, page) = pool.create(None).await
        .expect("BUG: create failed after rapid cycles — tab_count or browser state corrupted");
    page.goto("data:text/html,<h1>healthy</h1>").await.unwrap();
    pool.destroy(&id).await;
}

// --------------------------------------------------------------------------
// 7. Session IDs are unique — no collisions across creates
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn hard_red_session_id_uniqueness() {
    let pool = BrowserPool::new(ChromeLoginConfig::default());

    let (id1, _) = pool.create(None).await.unwrap();
    let (id2, _) = pool.create(None).await.unwrap();
    let (id3, _) = pool.create(None).await.unwrap();

    assert_ne!(id1, id2, "BUG: duplicate session IDs");
    assert_ne!(id2, id3, "BUG: duplicate session IDs");
    assert_ne!(id1, id3, "BUG: duplicate session IDs");

    // All 32 hex chars
    assert_eq!(id1.len(), 32, "session ID should be 32 hex chars");

    pool.destroy(&id1).await;
    pool.destroy(&id2).await;
    pool.destroy(&id3).await;
}

// --------------------------------------------------------------------------
// 8. Stealth injection per-tab — each new tab must have stealth.js
//    Bug hypothesis: stealth only injected on first tab, not subsequent
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn hard_red_stealth_per_tab() {
    let pool = BrowserPool::new(ChromeLoginConfig::default());

    let (id1, page1) = pool.create(None).await.unwrap();
    let (id2, page2) = pool.create(None).await.unwrap();

    page1.goto("data:text/html,<h1>Tab1</h1>").await.unwrap();
    page2.goto("data:text/html,<h1>Tab2</h1>").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Check navigator.webdriver is hidden (stealth.js patches this)
    let wd1: bool = page1.evaluate("navigator.webdriver === true")
        .await.unwrap().into_value().unwrap_or(true);
    let wd2: bool = page2.evaluate("navigator.webdriver === true")
        .await.unwrap().into_value().unwrap_or(true);

    assert!(!wd1, "BUG: stealth.js not applied to tab 1 — navigator.webdriver is true");
    assert!(!wd2, "BUG: stealth.js not applied to tab 2 — navigator.webdriver is true");

    pool.destroy(&id1).await;
    pool.destroy(&id2).await;
}

// --------------------------------------------------------------------------
// 9. Dialog on one tab doesn't freeze another
//    Bug hypothesis: dialog listener cross-talk between tabs
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn hard_red_dialog_isolation() {
    let pool = BrowserPool::new(ChromeLoginConfig::default());

    let (id1, page1) = pool.create(None).await.unwrap();
    let (id2, page2) = pool.create(None).await.unwrap();

    // Tab1 triggers an alert — auto-dismiss should handle it
    page1.goto("data:text/html,<script>alert('tab1')</script>").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Tab2 should be fully operational — not blocked by tab1's dialog
    page2.goto("data:text/html,<h1>Tab2 OK</h1>").await.unwrap();
    let title: String = page2.evaluate("document.querySelector('h1').textContent")
        .await.unwrap().into_value().unwrap_or_default();

    assert_eq!(title, "Tab2 OK", "BUG: tab2 blocked or corrupted by tab1's dialog");

    pool.destroy(&id1).await;
    pool.destroy(&id2).await;
}

// --------------------------------------------------------------------------
// 10. Partial destroy — remaining sessions still work
//     Bug hypothesis: destroying one session kills the shared browser
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn hard_red_partial_destroy() {
    let pool = BrowserPool::new(ChromeLoginConfig::default());

    let (id1, _p1) = pool.create(None).await.unwrap();
    let (id2, page2) = pool.create(None).await.unwrap();
    let (id3, page3) = pool.create(None).await.unwrap();

    // Destroy session 1 — should NOT kill the shared browser
    pool.destroy(&id1).await;
    assert_eq!(pool.len().await, 2);

    // Sessions 2 and 3 must still work
    page2.goto("data:text/html,<h1>Still alive</h1>").await
        .expect("BUG: session 2 died after session 1 was destroyed");
    page3.goto("data:text/html,<h1>Also alive</h1>").await
        .expect("BUG: session 3 died after session 1 was destroyed");

    let val: String = page2.evaluate("document.querySelector('h1').textContent")
        .await.unwrap().into_value().unwrap_or_default();
    assert_eq!(val, "Still alive");

    pool.destroy(&id2).await;
    pool.destroy(&id3).await;
}
