//! Persistent Chrome session pool — thin wrapper around [`BrowserPool`].
//!
//! `SessionPool` delegates all Chrome process management to `BrowserPool`
//! and exposes the same public API as before.

use chromiumoxide::Page;
use tokio::task::JoinHandle;

use crate::browser_pool::BrowserPool;
use crate::ChromeLoginConfig;

/// Pool of named Chrome sessions backed by [`BrowserPool`].
///
/// Internally reference-counted — `clone()` shares the same pool.
#[derive(Clone)]
pub struct SessionPool {
    pool: BrowserPool,
}

impl SessionPool {
    /// Create a new pool with the given default Chrome config.
    pub fn new(config: ChromeLoginConfig) -> Self {
        Self {
            pool: BrowserPool::new(config),
        }
    }

    /// Launch a new Chrome session (optionally overriding proxy), store it, and
    /// return the generated session ID.
    pub async fn create(&self, proxy: Option<&str>) -> Result<String, String> {
        let (id, _page) = self.pool.create(proxy).await?;
        Ok(id)
    }

    /// Get the active `Page` for a session, refreshing its TTL.
    ///
    /// Returns `None` if the session does not exist or has expired.
    pub async fn get(&self, id: &str) -> Option<Page> {
        self.pool.get(id).await
    }

    /// Destroy a session by ID. Returns `true` if it existed.
    pub async fn destroy(&self, id: &str) -> bool {
        self.pool.destroy(id).await
    }

    /// Remove all entries whose TTL has elapsed.
    pub async fn reap_expired(&self) {
        self.pool.reap_expired().await
    }

    /// Number of active sessions in the pool.
    pub async fn len(&self) -> usize {
        self.pool.len().await
    }

    /// Spawn a background task that calls `reap_expired` every 30 seconds.
    pub fn start_reaper(self) -> JoinHandle<()> {
        self.pool.start_reaper()
    }

    /// Access the inner [`BrowserPool`] for ephemeral tab creation.
    pub fn browser_pool(&self) -> &BrowserPool {
        &self.pool
    }
}
