//! Chrome launch helper for headless login flows.

use std::path::PathBuf;

use chromiumoxide::browser::BrowserConfig;
use chromiumoxide::{Browser, Page};
use futures::StreamExt;
use tokio::task::JoinHandle;

/// Select stealth profile based on whether we're using CloakBrowser.
/// CloakBrowser has C++ patches — only need lite JS patches to complement.
pub(crate) fn stealth_js(chrome_path: &Option<String>) -> &'static str {
    if chrome_path.as_ref().is_some_and(|p| p.contains("cloakbrowser")) {
        crate::stealth::STEALTH_JS_LITE
    } else {
        crate::stealth::STEALTH_JS
    }
}

/// Select UA — CloakBrowser sets its own UA via C++, no override needed.
pub fn stealth_ua(chrome_path: &Option<String>) -> &'static str {
    if chrome_path.as_ref().is_some_and(|p| p.contains("cloakbrowser")) {
        crate::stealth::STEALTH_UA_NONE
    } else {
        crate::stealth::STEALTH_UA
    }
}

/// Configuration for launching Chrome for login.
#[derive(Debug, Clone)]
pub struct ChromeLoginConfig {
    pub proxy_url: Option<String>,
    pub chrome_path: Option<String>,
    pub screenshot_dir: PathBuf,
    pub screenshot_on_error: bool,
    /// Launch Chrome in incognito mode for ephemeral sessions (no cookie persistence).
    pub incognito: bool,
}

impl Default for ChromeLoginConfig {
    fn default() -> Self {
        Self {
            proxy_url: None,
            chrome_path: None,
            screenshot_dir: PathBuf::from("/tmp/ox-browser/twitter-login"),
            screenshot_on_error: true,
            incognito: true,
        }
    }
}

/// Active browser session — handles cleanup on drop.
pub struct ChromeSession {
    pub browser: Browser,
    pub handler_task: JoinHandle<()>,
    /// Spawned CDP listener tasks (dialog auto-dismiss, log listeners).
    /// Aborted during `shutdown()` to prevent memory leaks.
    pub listener_tasks: Vec<JoinHandle<()>>,
    /// Unique temp data dir for this session — cleaned up on shutdown.
    pub data_dir: Option<PathBuf>,
}

impl ChromeSession {
    /// Launch headless Chrome with stealth.js pre-injected.
    pub async fn launch(config: &ChromeLoginConfig) -> Result<(Self, Page), String> {
        let data_dir = PathBuf::from(format!("/tmp/ox-chrome-{:016x}", rand::random::<u64>()));
        let mut builder = BrowserConfig::builder()
            .no_sandbox()
            .new_headless_mode()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--no-first-run")
            .arg("--disable-blink-features=AutomationControlled")
            .arg("--window-size=1920,1080")
            .arg("--lang=en-US,en")
            .arg(format!("--user-data-dir={}", data_dir.display()));

        if config.incognito {
            builder = builder.arg("--incognito");
        }

        if let Some(ref path) = config.chrome_path {
            builder = builder.chrome_executable(path);
            if path.contains("cloakbrowser") {
                builder = builder
                    .arg("--fingerprint=79849")
                    .arg("--fingerprint-platform=windows")
                    .arg("--fingerprint-gpu-vendor=Google Inc. (NVIDIA)")
                    .arg("--fingerprint-gpu-renderer=ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 (0x00002484) Direct3D11 vs_5_0 ps_5_0, D3D11)");
            }
        }
        if let Some(ref proxy) = config.proxy_url {
            builder = builder.arg(format!("--proxy-server={proxy}"));
        }

        let browser_config = builder.build().map_err(|e| format!("chrome config: {e}"))?;
        let (browser, mut handler) = Browser::launch(browser_config)
            .await
            .map_err(|e| format!("chrome launch: {e}"))?;

        let handler_task = tokio::spawn(async move {
            loop {
                if handler.next().await.is_none() {
                    break;
                }
            }
        });

        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| format!("new_page: {e}"))?;

        page.evaluate_on_new_document(stealth_js(&config.chrome_path))
            .await
            .map_err(|e| format!("stealth inject: {e}"))?;

        let ua = stealth_ua(&config.chrome_path);
        if !ua.is_empty() {
            page.set_user_agent(ua)
                .await
                .map_err(|e| format!("set_user_agent: {e}"))?;
        }

        // Auto-dismiss JS dialogs to prevent session freeze
        let mut listener_tasks = Vec::new();
        if let Ok(mut events) = page
            .event_listener::<chromiumoxide::cdp::browser_protocol::page::EventJavascriptDialogOpening>()
            .await
        {
            let page_for_dialog = page.clone();
            let handle = tokio::spawn(async move {
                while let Some(_event) = futures::StreamExt::next(&mut events).await {
                    let params =
                        chromiumoxide::cdp::browser_protocol::page::HandleJavaScriptDialogParams::builder()
                            .accept(true)
                            .build();
                    if let Ok(p) = params {
                        let _ = page_for_dialog.execute(p).await;
                    }
                }
            });
            listener_tasks.push(handle);
        }

        let session = Self {
            browser,
            handler_task,
            listener_tasks,
            data_dir: Some(data_dir),
        };
        Ok((session, page))
    }

    /// Take a screenshot and save to the configured directory.
    pub async fn screenshot(page: &Page, dir: &PathBuf, label: &str) -> Option<PathBuf> {
        let _ = tokio::fs::create_dir_all(dir).await;
        let ts = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S");
        let path = dir.join(format!("{ts}-{label}.png"));

        match page
            .screenshot(
                chromiumoxide::page::ScreenshotParams::builder().build(),
            )
            .await
        {
            Ok(bytes) => {
                if tokio::fs::write(&path, &bytes).await.is_ok() {
                    tracing::debug!(path = %path.display(), "screenshot saved");
                    Some(path)
                } else {
                    None
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "screenshot failed");
                None
            }
        }
    }

    /// Evaluate JS in an isolated world (avoids `Runtime.enable` detection).
    ///
    /// Creates a fresh isolated execution context via `Page.createIsolatedWorld`,
    /// then runs `Runtime.evaluate` scoped to that context. Anti-bot systems
    /// (DataDome, PerimeterX) detect `Runtime.enable` in the main world — this
    /// sidesteps it entirely.
    pub async fn evaluate_isolated(
        page: &Page,
        expression: &str,
    ) -> Result<chromiumoxide::cdp::js_protocol::runtime::RemoteObject, String> {
        use chromiumoxide::cdp::browser_protocol::page::{
            CreateIsolatedWorldParams, GetFrameTreeParams,
        };
        use chromiumoxide::cdp::js_protocol::runtime::EvaluateParams;

        // 1. Get main frame ID.
        let tree = page
            .execute(GetFrameTreeParams {})
            .await
            .map_err(|e| format!("GetFrameTree: {e}"))?;
        let frame_id = tree.result.frame_tree.frame.id;

        // 2. Create isolated world (random UUID — avoids detection by Castle.io).
        let mut params = CreateIsolatedWorldParams::new(frame_id);
        params.world_name = Some(uuid::Uuid::new_v4().to_string());
        params.grant_univeral_access = Some(true);

        let world = page
            .execute(params)
            .await
            .map_err(|e| format!("CreateIsolatedWorld: {e}"))?;

        // 3. Evaluate JS in isolated context.
        let mut eval = EvaluateParams::new(expression);
        eval.context_id = Some(world.result.execution_context_id);
        eval.return_by_value = Some(true);

        let result = page
            .execute(eval)
            .await
            .map_err(|e| format!("Evaluate (isolated): {e}"))?;

        if let Some(ref exc) = result.result.exception_details {
            return Err(format!("JS exception: {exc:?}"));
        }

        Ok(result.result.result)
    }

    /// Attach network + console CDP listeners to a page, feeding into `SessionLogs`.
    ///
    /// Returns `JoinHandle`s for the spawned listener tasks so the caller can
    /// abort them during shutdown (prevents leaked tasks / unbounded memory).
    pub async fn attach_log_listeners(
        page: &Page,
        logs: &crate::chrome_interact::SessionLogs,
    ) -> Result<Vec<JoinHandle<()>>, String> {
        use chromiumoxide::cdp::browser_protocol::network::{
            EnableParams as NetEnableParams, EventLoadingFailed, EventResponseReceived,
        };
        use chromiumoxide::cdp::js_protocol::runtime::{
            EnableParams as RtEnableParams, EventConsoleApiCalled,
        };
        use crate::chrome_interact::logs::{ConsoleEntry, NetworkEntry};

        // Enable network domain
        page.execute(NetEnableParams::default())
            .await
            .map_err(|e| format!("network.enable: {e}"))?;

        // Enable runtime domain (needed for console events)
        page.execute(RtEnableParams::default())
            .await
            .map_err(|e| format!("runtime.enable: {e}"))?;

        let mut handles = Vec::with_capacity(3);

        // Response listener
        let logs_r = logs.clone();
        let page_r = page.clone();
        handles.push(tokio::spawn(async move {
            if let Ok(mut events) = page_r.event_listener::<EventResponseReceived>().await {
                while let Some(ev) = futures::StreamExt::next(&mut events).await {
                    logs_r
                        .push_network(NetworkEntry {
                            method: String::new(),
                            url: ev.response.url.clone(),
                            status: Some(ev.response.status),
                            error: None,
                        })
                        .await;
                }
            }
        }));

        // Loading failure listener
        let logs_f = logs.clone();
        let page_f = page.clone();
        handles.push(tokio::spawn(async move {
            if let Ok(mut events) = page_f.event_listener::<EventLoadingFailed>().await {
                while let Some(ev) = futures::StreamExt::next(&mut events).await {
                    logs_f
                        .push_network(NetworkEntry {
                            method: String::new(),
                            url: ev.request_id.inner().to_string(),
                            status: None,
                            error: Some(ev.error_text.clone()),
                        })
                        .await;
                }
            }
        }));

        // Console listener
        let logs_c = logs.clone();
        let page_c = page.clone();
        handles.push(tokio::spawn(async move {
            if let Ok(mut events) = page_c.event_listener::<EventConsoleApiCalled>().await {
                while let Some(ev) = futures::StreamExt::next(&mut events).await {
                    let text = ev
                        .args
                        .iter()
                        .filter_map(|a| a.value.as_ref().map(|v| v.to_string()))
                        .collect::<Vec<_>>()
                        .join(" ");
                    logs_c
                        .push_console(ConsoleEntry {
                            level: ev.r#type.as_ref().to_string(),
                            text,
                        })
                        .await;
                }
            }
        }));

        Ok(handles)
    }

    /// Shut down browser and all spawned tasks.
    pub async fn shutdown(mut self) {
        for task in &self.listener_tasks {
            task.abort();
        }
        let _ = self.browser.close().await;
        self.handler_task.abort();
        // Clean up unique data dir to prevent disk leak
        if let Some(ref dir) = self.data_dir {
            let _ = tokio::fs::remove_dir_all(dir).await;
        }
    }
}
