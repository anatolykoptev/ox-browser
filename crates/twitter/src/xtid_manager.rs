//! XtidManager — async manager for ClientTransaction lifecycle.
//! Fetches x.com HTML + ondemand.s JS, builds ClientTransaction,
//! caches it with 30min TTL, and provides generate_id().

use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::xtid::ClientTransaction;
use crate::xtid_parser::parse_ondemand_url;

const REFRESH_INTERVAL: Duration = Duration::from_secs(30 * 60);
const X_COM_URL: &str = "https://x.com";

struct ManagerState {
    ct: Option<ClientTransaction>,
    last_refresh: Instant,
}

pub(crate) struct XtidManager {
    state: RwLock<ManagerState>,
}

impl XtidManager {
    pub(crate) fn new() -> Self {
        Self {
            state: RwLock::new(ManagerState {
                ct: None,
                last_refresh: Instant::now() - REFRESH_INTERVAL - Duration::from_secs(1),
            }),
        }
    }

    pub(crate) async fn generate_id(&self, method: &str, path: &str) -> Result<String, String> {
        let needs_refresh = {
            let state = self.state.read().await;
            state.ct.is_none() || state.last_refresh.elapsed() > REFRESH_INTERVAL
        };

        if needs_refresh && let Err(e) = self.initialize().await {
            let has_stale = self.state.read().await.ct.is_some();
            if has_stale {
                tracing::warn!("xtid: refresh failed, using stale keys: {e}");
            } else {
                return Err(e);
            }
        }

        let state = self.state.read().await;
        match &state.ct {
            Some(ct) => Ok(ct.generate_id(method, path)),
            None => Err("xtid not initialized".to_string()),
        }
    }

    async fn initialize(&self) -> Result<(), String> {
        tracing::info!("xtid: fetching x.com HTML");
        let html = self
            .fetch_url(X_COM_URL)
            .await
            .map_err(|e| format!("fetch x.com: {e}"))?;
        let ondemand_url = parse_ondemand_url(&html)?;
        tracing::info!("xtid: fetching ondemand.s from {ondemand_url}");
        let js = self
            .fetch_url(&ondemand_url)
            .await
            .map_err(|e| format!("fetch ondemand.s: {e}"))?;

        let ct = ClientTransaction::new(&html, &js)?;
        tracing::info!("xtid: ClientTransaction built successfully");

        let mut state = self.state.write().await;
        state.ct = Some(ct);
        state.last_refresh = Instant::now();
        Ok(())
    }

    async fn fetch_url(&self, url: &str) -> Result<String, String> {
        let resp = crate::tw_http::twitter_http()
            .get_with_headers(
                url,
                &[
                    ("user-agent", crate::TWITTER_USER_AGENT),
                    (
                        "accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    ),
                    ("accept-language", "en-US,en;q=0.9"),
                ],
            )
            .await
            .map_err(|e| format!("request error: {e}"))?;

        Ok(resp.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_starts_expired() {
        let mgr = XtidManager::new();
        // Verify initial state: last_refresh is in the past (beyond REFRESH_INTERVAL)
        let state = mgr.state.try_read().unwrap();
        assert!(state.ct.is_none());
        assert!(state.last_refresh.elapsed() > REFRESH_INTERVAL);
    }
}
