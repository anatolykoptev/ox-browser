//! Per-domain render mode cache — remembers which domains need Chrome.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Render mode for a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderMode {
    /// Standard HTTP fetch works fine.
    Http,
    /// Needs Chrome/JS rendering (CF challenge, JS-only SPA).
    Chrome,
}

struct Entry {
    mode: RenderMode,
    expires_at: Instant,
}

/// Thread-safe cache mapping domains to their render mode.
pub struct RenderModeCache {
    entries: RwLock<HashMap<String, Entry>>,
    ttl: Duration,
}

impl RenderModeCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Get cached render mode for a domain. Returns None if not cached or expired.
    pub fn get(&self, domain: &str) -> Option<RenderMode> {
        let entries = self.entries.read().expect("lock poisoned");
        let entry = entries.get(domain)?;
        if Instant::now() < entry.expires_at {
            Some(entry.mode)
        } else {
            None
        }
    }

    /// Mark a domain as needing a specific render mode.
    pub fn set(&self, domain: &str, mode: RenderMode) {
        let mut entries = self.entries.write().expect("lock poisoned");
        entries.insert(
            domain.to_owned(),
            Entry {
                mode,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}

impl Default for RenderModeCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(3600))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn set_and_get() {
        let cache = RenderModeCache::new(Duration::from_secs(60));
        cache.set("bitcoinmagazine.com", RenderMode::Chrome);
        assert_eq!(cache.get("bitcoinmagazine.com"), Some(RenderMode::Chrome));
    }

    #[test]
    fn miss_on_unknown() {
        let cache = RenderModeCache::new(Duration::from_secs(60));
        assert_eq!(cache.get("unknown.com"), None);
    }

    #[test]
    fn expires() {
        let cache = RenderModeCache::new(Duration::from_millis(0));
        cache.set("example.com", RenderMode::Chrome);
        thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.get("example.com"), None);
    }

    #[test]
    fn overwrite() {
        let cache = RenderModeCache::new(Duration::from_secs(60));
        cache.set("example.com", RenderMode::Http);
        cache.set("example.com", RenderMode::Chrome);
        assert_eq!(cache.get("example.com"), Some(RenderMode::Chrome));
    }
}
