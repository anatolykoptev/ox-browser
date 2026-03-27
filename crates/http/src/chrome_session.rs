//! Chrome launch helper for headless login flows.

use std::path::PathBuf;

use chromiumoxide::browser::BrowserConfig;
use chromiumoxide::{Browser, Page};
use futures::StreamExt;
use tokio::task::JoinHandle;

/// Stealth bootstrap script (shared with CF solver).
const STEALTH_JS: &str = include_str!("stealth.js");

/// User-Agent matching the stealth script's Client Hints.
pub const STEALTH_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";

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
}

impl ChromeSession {
    /// Launch headless Chrome with stealth.js pre-injected.
    pub async fn launch(config: &ChromeLoginConfig) -> Result<(Self, Page), String> {
        let mut builder = BrowserConfig::builder()
            .no_sandbox()
            .new_headless_mode()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--no-first-run")
            .arg("--disable-blink-features=AutomationControlled")
            .arg("--window-size=1920,1080")
            .arg("--lang=en-US,en");

        if config.incognito {
            builder = builder.arg("--incognito");
        }

        if let Some(ref path) = config.chrome_path {
            builder = builder.chrome_executable(path);
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

        page.evaluate_on_new_document(STEALTH_JS)
            .await
            .map_err(|e| format!("stealth inject: {e}"))?;

        page.set_user_agent(STEALTH_UA)
            .await
            .map_err(|e| format!("set_user_agent: {e}"))?;

        // Auto-dismiss JS dialogs to prevent session freeze
        if let Ok(mut events) = page
            .event_listener::<chromiumoxide::cdp::browser_protocol::page::EventJavascriptDialogOpening>()
            .await
        {
            let page_for_dialog = page.clone();
            tokio::spawn(async move {
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
        }

        let session = Self {
            browser,
            handler_task,
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

        // 2. Create isolated world (name "utility" — not "__playwright__").
        let mut params = CreateIsolatedWorldParams::new(frame_id);
        params.world_name = Some("utility".into());
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

    /// Shut down browser and handler task.
    pub async fn shutdown(mut self) {
        let _ = self.browser.close().await;
        self.handler_task.abort();
    }
}
