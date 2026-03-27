//! Pool of shared Chrome browsers grouped by proxy.
//! Tab creation and Chrome launch: [`crate::browser_pool_tab`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chromiumoxide::cdp::browser_protocol::browser::BrowserContextId;
use chromiumoxide::cdp::browser_protocol::target::DisposeBrowserContextParams;
use chromiumoxide::Page;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::browser_pool_tab::{self, BrowserEntry};
use crate::ChromeLoginConfig;

const DEFAULT_TTL_SECS: u64 = 300;
const REAPER_INTERVAL_SECS: u64 = 30;

/// Key for grouping browsers by proxy.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub(crate) enum ProxyKey {
    None,
    Proxy(String),
}

/// A single session: BrowserContext + Page within a shared Browser.
pub(crate) struct TabEntry {
    pub page: Page,
    pub context_id: BrowserContextId,
    pub listener_tasks: Vec<JoinHandle<()>>,
    pub last_used: Instant,
    pub ttl: Duration,
    pub(crate) proxy_key: ProxyKey,
}

impl TabEntry {
    fn is_expired(&self) -> bool {
        self.last_used.elapsed() > self.ttl
    }
}

/// Pool of shared Chrome browsers. Clone shares the same pool (Arc).
#[derive(Clone)]
pub struct BrowserPool {
    browsers: Arc<RwLock<HashMap<ProxyKey, BrowserEntry>>>,
    sessions: Arc<RwLock<HashMap<String, TabEntry>>>,
    config: ChromeLoginConfig,
}

impl BrowserPool {
    /// Create an empty pool with the given Chrome config.
    pub fn new(config: ChromeLoginConfig) -> Self {
        Self {
            browsers: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a new session: get/launch browser for proxy, create context + page.
    ///
    /// Holds the browsers write lock through launch + tab creation to prevent
    /// TOCTOU race with the reaper closing an empty browser before tab_count
    /// is incremented.
    pub async fn create(&self, proxy: Option<&str>) -> Result<(String, Page), String> {
        let key = proxy.map_or(ProxyKey::None, |p| ProxyKey::Proxy(p.to_owned()));

        let (context_id, page, listener_tasks) = {
            let mut bmap = self.browsers.write().await;
            if !bmap.contains_key(&key) {
                let e = browser_pool_tab::launch_browser(&self.config, proxy).await?;
                bmap.insert(key.clone(), e);
            }
            let entry = bmap.get(&key).ok_or("browser disappeared")?;
            let result = browser_pool_tab::create_tab(&entry.browser, &self.config.chrome_path).await?;
            bmap.get_mut(&key).unwrap().tab_count += 1;
            result
        };

        let id = new_session_id();
        let tab = TabEntry {
            page: page.clone(),
            context_id,
            listener_tasks,
            last_used: Instant::now(),
            ttl: Duration::from_secs(DEFAULT_TTL_SECS),
            proxy_key: key,
        };
        self.sessions.write().await.insert(id.clone(), tab);
        tracing::info!(session_id = %id, "browser pool: session created");
        Ok((id, page))
    }

    /// Get Page for existing session, refresh TTL. Returns None if expired.
    pub async fn get(&self, id: &str) -> Option<Page> {
        let mut sessions = self.sessions.write().await;
        match sessions.get_mut(id) {
            None => None,
            Some(tab) if tab.is_expired() => {
                let expired = sessions.remove(id).unwrap();
                drop(sessions);
                self.cleanup_tab(expired).await;
                tracing::info!(session_id = %id, "browser pool: session expired");
                None
            }
            Some(tab) => {
                tab.last_used = Instant::now();
                Some(tab.page.clone())
            }
        }
    }

    /// Destroy a session. Returns `true` if it existed.
    pub async fn destroy(&self, id: &str) -> bool {
        let removed = self.sessions.write().await.remove(id);
        if let Some(tab) = removed {
            self.cleanup_tab(tab).await;
            tracing::info!(session_id = %id, "browser pool: session destroyed");
            true
        } else {
            false
        }
    }

    /// Remove expired sessions. Close browsers with no remaining sessions.
    pub async fn reap_expired(&self) {
        let expired_ids: Vec<String> = {
            let map = self.sessions.read().await;
            map.iter()
                .filter(|(_, t)| t.is_expired())
                .map(|(k, _)| k.clone())
                .collect()
        };
        for id in expired_ids {
            if let Some(tab) = self.sessions.write().await.remove(&id) {
                self.cleanup_tab(tab).await;
                tracing::info!(session_id = %id, "browser pool: session reaped");
            }
        }
        self.close_empty_browsers().await;
    }

    /// Number of active sessions.
    pub async fn len(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Spawn background reaper task (every 30s).
    pub fn start_reaper(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(REAPER_INTERVAL_SECS));
            loop {
                interval.tick().await;
                self.reap_expired().await;
            }
        })
    }

    async fn cleanup_tab(&self, tab: TabEntry) {
        tab.listener_tasks.iter().for_each(|t| t.abort());
        {   let bmap = self.browsers.read().await;
            if let Some(e) = bmap.get(&tab.proxy_key) {
                let _ = e.browser.execute(
                    DisposeBrowserContextParams::new(tab.context_id),
                ).await;
            }
        }
        let mut bmap = self.browsers.write().await;
        if let Some(e) = bmap.get_mut(&tab.proxy_key) {
            e.tab_count = e.tab_count.saturating_sub(1);
        }
    }

    async fn close_empty_browsers(&self) {
        // Single write lock to atomically find and remove empty browsers,
        // preventing TOCTOU race with concurrent create().
        let empty: Vec<(ProxyKey, BrowserEntry)> = {
            let mut m = self.browsers.write().await;
            let keys: Vec<ProxyKey> = m
                .iter()
                .filter(|(_, e)| e.tab_count == 0)
                .map(|(k, _)| k.clone())
                .collect();
            keys.into_iter()
                .filter_map(|k| m.remove(&k).map(|e| (k, e)))
                .collect()
        };
        for (key, mut e) in empty {
            let _ = e.browser.close().await;
            e.handler_task.abort();
            tracing::info!(?key, "browser pool: empty browser closed");
        }
    }
}

/// Generate a random 32-hex-char session ID.
fn new_session_id() -> String {
    format!(
        "{:016x}{:016x}",
        rand::random::<u64>(),
        rand::random::<u64>()
    )
}
