//! Network and console log accumulators for chrome_interact sessions.

use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct NetworkEntry {
    pub method: String,
    pub url: String,
    pub status: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConsoleEntry {
    pub level: String,
    pub text: String,
}

#[derive(Clone)]
pub struct SessionLogs {
    network: Arc<Mutex<Vec<NetworkEntry>>>,
    console: Arc<Mutex<Vec<ConsoleEntry>>>,
}

impl SessionLogs {
    pub fn new() -> Self {
        Self {
            network: Arc::new(Mutex::new(Vec::new())),
            console: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn push_network(&self, entry: NetworkEntry) {
        self.network.lock().await.push(entry);
    }

    pub async fn push_console(&self, entry: ConsoleEntry) {
        self.console.lock().await.push(entry);
    }

    /// Drain and return all network entries.
    pub async fn take_network(&self) -> Vec<NetworkEntry> {
        std::mem::take(&mut *self.network.lock().await)
    }

    /// Drain and return all console entries.
    pub async fn take_console(&self) -> Vec<ConsoleEntry> {
        std::mem::take(&mut *self.console.lock().await)
    }
}
