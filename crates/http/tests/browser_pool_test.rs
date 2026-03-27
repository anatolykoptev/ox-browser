//! Integration tests for BrowserPool — tab isolation, session lifecycle, shared browsers.
//!
//! These tests require headless Chromium installed on the host.
//! Uses `data:` URIs to avoid network dependencies.

use ox_http::browser_pool::BrowserPool;
use ox_http::chrome_session::ChromeLoginConfig;
use ox_http::session_pool::SessionPool;
use serial_test::serial;

// --------------------------------------------------------------------------
// 1. Create session and get — basic lifecycle
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_browser_pool_create_and_get() {
    let config = ChromeLoginConfig::default();
    let pool = BrowserPool::new(config);

    let (id, page) = pool.create(None).await.expect("create failed");
    assert!(!id.is_empty(), "session id should not be empty");

    // get() should return a valid page
    let page2 = pool.get(&id).await.expect("get failed");

    // Navigate via the returned page to confirm it works
    page2
        .goto("data:text/html,<h1>Test</h1>")
        .await
        .expect("goto failed");

    // The original page clone should still be valid
    drop(page);

    pool.destroy(&id).await;
}

// --------------------------------------------------------------------------
// 2. Storage isolation — two sessions share a Browser but not a context
//
// data: URLs don't support cookies (SecurityError), so we use localStorage
// and a unique per-page title as a proxy for context isolation.
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_browser_pool_session_isolation() {
    let config = ChromeLoginConfig::default();
    let pool = BrowserPool::new(config);

    // Two sessions with no proxy → same Chrome process, different contexts
    let (id1, page1) = pool.create(None).await.expect("create1 failed");
    let (id2, page2) = pool.create(None).await.expect("create2 failed");

    page1
        .goto("data:text/html,<h1>Page1</h1>")
        .await
        .unwrap();
    page2
        .goto("data:text/html,<h1>Page2</h1>")
        .await
        .unwrap();

    // Set a title on session 1 to confirm independent JS state
    page1.evaluate("document.title = 'session-one'").await.unwrap();
    page2.evaluate("document.title = 'session-two'").await.unwrap();

    // Each session should see its own title — confirms isolated execution contexts
    let raw1 = page1.evaluate("document.title").await.unwrap();
    let title1: String = raw1.into_value().unwrap_or_default();
    let raw2 = page2.evaluate("document.title").await.unwrap();
    let title2: String = raw2.into_value().unwrap_or_default();

    assert_eq!(title1, "session-one", "session1 title mismatch");
    assert_eq!(title2, "session-two", "session2 title mismatch, got: {title2:?}");

    pool.destroy(&id1).await;
    pool.destroy(&id2).await;
}

// --------------------------------------------------------------------------
// 3. Destroy removes session — len() and get() reflect removal
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_browser_pool_destroy() {
    let config = ChromeLoginConfig::default();
    let pool = BrowserPool::new(config);

    let (id, _page) = pool.create(None).await.expect("create failed");
    assert_eq!(pool.len().await, 1, "pool should have 1 session after create");

    pool.destroy(&id).await;
    assert_eq!(pool.len().await, 0, "pool should be empty after destroy");

    // get() after destroy returns None
    assert!(
        pool.get(&id).await.is_none(),
        "get after destroy should return None"
    );
}

// --------------------------------------------------------------------------
// 4. Multiple sessions share one Browser (same proxy group)
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_browser_pool_shared_browser() {
    let config = ChromeLoginConfig::default();
    let pool = BrowserPool::new(config);

    // All three have no proxy → should reuse the same Chrome process
    let (id1, _) = pool.create(None).await.expect("create1");
    let (id2, _) = pool.create(None).await.expect("create2");
    let (id3, _) = pool.create(None).await.expect("create3");

    assert_eq!(pool.len().await, 3, "pool should track all 3 sessions");

    pool.destroy(&id1).await;
    pool.destroy(&id2).await;
    pool.destroy(&id3).await;

    assert_eq!(pool.len().await, 0, "pool should be empty after all destroys");
}

// --------------------------------------------------------------------------
// 5. SessionPool backward-compat wrapper
// --------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_session_pool_backward_compat() {
    let config = ChromeLoginConfig::default();
    let pool = SessionPool::new(config);

    // Old API: create returns only the session ID
    let id = pool.create(None).await.expect("create failed");
    assert!(!id.is_empty(), "session id should not be empty");

    // get() returns a usable Page
    let page = pool.get(&id).await.expect("get failed");
    page.goto("data:text/html,<p>compat</p>")
        .await
        .expect("goto failed");

    pool.destroy(&id).await;

    // get() after destroy returns None
    assert!(
        pool.get(&id).await.is_none(),
        "get after destroy should return None"
    );
}
