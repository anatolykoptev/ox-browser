//! Tab creation and Chrome launch helpers for BrowserPool.

use std::time::Instant;

use chromiumoxide::cdp::browser_protocol::browser::BrowserContextId;
use chromiumoxide::cdp::browser_protocol::target::{
    CreateBrowserContextParams, CreateTargetParams,
};
use chromiumoxide::browser::BrowserConfig;
use chromiumoxide::{Browser, Page};
use futures::StreamExt;
use tokio::task::JoinHandle;

use crate::chrome_session::{stealth_js, stealth_ua};
use crate::ChromeLoginConfig;

/// A running Chrome process with its CDP handler.
#[allow(dead_code)] // created_at planned for metrics/diagnostics
pub(super) struct BrowserEntry {
    pub browser: Browser,
    pub handler_task: JoinHandle<()>,
    pub tab_count: usize,
    pub created_at: Instant,
}

/// Launch a new Chrome with optimized flags for a proxy group.
pub(super) async fn launch_browser(
    config: &ChromeLoginConfig,
    proxy: Option<&str>,
) -> Result<BrowserEntry, String> {
    let browser_config = build_browser_config(config, proxy)?;
    let (browser, mut handler) = Browser::launch(browser_config)
        .await
        .map_err(|e| format!("chrome launch: {e}"))?;
    let handler_task = tokio::spawn(async move {
        while handler.next().await.is_some() {}
    });
    Ok(BrowserEntry {
        browser,
        handler_task,
        tab_count: 0,
        created_at: Instant::now(),
    })
}

/// Connect to an already-running Chrome via WebSocket (CDP).
///
/// Used for CloakBrowser sidecar: fingerprint patches are active at the C++ level,
/// no need to pass `--fingerprint-*` args through chromiumoxide.
///
/// `ws_url` can be `ws://host:port` — the actual debugger URL (with browser GUID)
/// is discovered from the `/json/version` HTTP endpoint automatically.
pub(super) async fn connect_browser(ws_url: &str) -> Result<BrowserEntry, String> {
    let actual_url = discover_ws_url(ws_url).await?;
    tracing::info!(ws_url = %actual_url, "connecting to remote Chrome (sidecar)");
    let (browser, mut handler) = Browser::connect(&actual_url)
        .await
        .map_err(|e| format!("chrome connect to {actual_url}: {e}"))?;
    let handler_task = tokio::spawn(async move {
        while handler.next().await.is_some() {}
    });
    Ok(BrowserEntry {
        browser,
        handler_task,
        tab_count: 0,
        created_at: Instant::now(),
    })
}

/// Discover the real WebSocket debugger URL from Chrome's `/json/version` endpoint.
///
/// Converts `ws://host:port` → `http://host:port/json/version`, fetches the JSON,
/// and extracts `webSocketDebuggerUrl` (which includes the per-session browser GUID).
async fn discover_ws_url(ws_url: &str) -> Result<String, String> {
    let http_url = ws_url
        .replace("ws://", "http://")
        .replace("wss://", "https://");
    let version_url = format!("{http_url}/json/version");

    // Chrome DevTools rejects Host headers that aren't IP/localhost.
    // Override to "127.0.0.1:port" for Docker networking compatibility.
    let port = ws_url.rsplit(':').next().unwrap_or("9222");
    let resp = wreq::get(&version_url)
        .header("Host", format!("127.0.0.1:{port}"))
        .send()
        .await
        .map_err(|e| format!("CDP version endpoint {version_url}: {e}"))?;
    let text = resp
        .text()
        .await
        .map_err(|e| format!("CDP version read body: {e}"))?;
    let body: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("CDP version JSON parse: {e}"))?;

    body["webSocketDebuggerUrl"]
        .as_str()
        .map(|url: &str| {
            // Replace 127.0.0.1 with original host (container networking).
            let original_host = ws_url
                .trim_start_matches("ws://")
                .trim_start_matches("wss://")
                .split(':')
                .next()
                .unwrap_or("127.0.0.1");
            url.replace("127.0.0.1", original_host)
                .replace("0.0.0.0", original_host)
        })
        .ok_or_else(|| "webSocketDebuggerUrl not found in /json/version".into())
}

/// Create isolated BrowserContext + Page in an existing Browser.
pub(super) async fn create_tab(
    browser: &Browser,
    chrome_path: &Option<String>,
    context_proxy: Option<&str>,
) -> Result<(BrowserContextId, Page, Vec<JoinHandle<()>>), String> {
    let mut ctx_builder = CreateBrowserContextParams::builder()
        .dispose_on_detach(true);
    if let Some(proxy) = context_proxy {
        tracing::info!(proxy = %proxy, "setting per-context proxy");
        ctx_builder = ctx_builder.proxy_server(proxy);
    }
    let ctx_params = ctx_builder.build();
    let context_id = browser
        .create_browser_context(ctx_params)
        .await
        .map_err(|e| format!("create context: {e}"))?;

    let mut target_params = CreateTargetParams::new("about:blank");
    target_params.browser_context_id = Some(context_id.clone());
    let page = browser
        .new_page(target_params)
        .await
        .map_err(|e| format!("new page: {e}"))?;

    page.evaluate_on_new_document(stealth_js(chrome_path))
        .await
        .map_err(|e| format!("stealth inject: {e}"))?;

    let ua = stealth_ua(chrome_path);
    if !ua.is_empty() {
        page.set_user_agent(ua)
            .await
            .map_err(|e| format!("set UA: {e}"))?;
    }

    let dialog_handle = setup_dialog_handler(&page);

    Ok((context_id, page, vec![dialog_handle]))
}

/// Spawn a background task that auto-dismisses JS dialogs on a page.
fn setup_dialog_handler(page: &Page) -> JoinHandle<()> {
    let page_clone = page.clone();
    tokio::spawn(async move {
        if let Ok(mut events) = page_clone
            .event_listener::<chromiumoxide::cdp::browser_protocol::page::EventJavascriptDialogOpening>()
            .await
        {
            while let Some(_ev) = events.next().await {
                let params = chromiumoxide::cdp::browser_protocol::page::HandleJavaScriptDialogParams::builder()
                    .accept(true)
                    .build();
                if let Ok(p) = params {
                    let _ = page_clone.execute(p).await;
                }
            }
        }
    })
}

fn build_browser_config(
    config: &ChromeLoginConfig,
    proxy: Option<&str>,
) -> Result<BrowserConfig, String> {
    let mut builder = BrowserConfig::builder()
        .no_sandbox()
        .new_headless_mode()
        .arg("--disable-gpu")
        .arg("--disable-dev-shm-usage")
        .arg("--no-first-run")
        .arg("--disable-setuid-sandbox")
        .arg("--disable-extensions")
        .arg("--disable-background-timer-throttling")
        .arg("--disable-renderer-backgrounding")
        .arg("--disable-features=BackForwardCache")
        .arg("--disable-blink-features=AutomationControlled")
        .arg("--window-size=1920,1080")
        .arg("--lang=en-US,en")
        .arg("--remote-debugging-port=0")
        .arg("--js-flags=--max-old-space-size=512");

    if let Some(ref path) = config.chrome_path {
        builder = builder.chrome_executable(path);
        // CloakBrowser needs fingerprint flags to activate C++ patches.
        // Note: args with spaces/commas must be avoided (chromiumoxide splits on whitespace).
        if path.contains("cloakbrowser") {
            tracing::info!("CloakBrowser detected, adding fingerprint flags");
            builder = builder
                .arg("--fingerprint=79849")
                .arg("--fingerprint-platform=windows");
        }
    }
    if let Some(proxy) = proxy {
        builder = builder.arg(format!("--proxy-server={proxy}"));
    }

    // Debug: log all Chrome args for troubleshooting fingerprint issues.
    tracing::debug!(
        chrome_path = ?config.chrome_path,
        proxy = ?proxy,
        "building Chrome config for local launch"
    );

    builder.build().map_err(|e| format!("chrome config: {e}"))
}
