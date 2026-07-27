//! Per-domain render mode cache — remembers which domains need Chrome.
//!
//! # Unbounded-growth guard (issue #18)
//!
//! Before this fix, [`RenderModeCache`] had no [`evict_expired`](Self::evict_expired)
//! method and nothing swept expired entries on a schedule, and there was no cap on
//! the number of tracked domains. A crawler hitting many distinct domains
//! accumulated one entry per domain forever — unbounded memory growth. This module
//! now mirrors [`crate::cookie_cache`] in two ways:
//!
//! 1. A `max_size` cap with LRU-style eldest-first eviction on [`set`](Self::set).
//! 2. A [`spawn_eviction_task`] that periodically drops expired entries.
//!
//! The live entry count is published to the `oxbrowser_render_cache_entries`
//! gauge (see [`crate::metrics`]) so operators can alert on cache pressure.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::metrics::{self, RENDER_CACHE_ENTRIES};

/// Default maximum number of distinct domains tracked before eldest eviction.
pub const DEFAULT_MAX_SIZE: usize = 4096;

/// Render mode for a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderMode {
    /// Standard HTTP fetch works fine.
    Http,
    /// Needs Chrome/JS rendering (CF challenge, JS-only SPA).
    Chrome,
    /// Solver gave up on this domain (negcache cooldown); fast-fail immediately
    /// without paying for another doomed 15-25 s solve attempt.
    GiveUp,
}

struct Entry {
    mode: RenderMode,
    expires_at: Instant,
    /// Monotonic insert/refresh sequence number — used to find the eldest
    /// entry for LRU-style capacity eviction. Bumped on every `set`.
    seq: u64,
}

/// Thread-safe cache mapping domains to their render mode.
pub struct RenderModeCache {
    entries: RwLock<HashMap<String, Entry>>,
    ttl: Duration,
    max_size: usize,
    /// Monotonic counter assigning each entry a freshness sequence number.
    next_seq: RwLock<u64>,
}

impl RenderModeCache {
    /// Creates a new cache with the given TTL for entries.
    pub fn new(ttl: Duration) -> Self {
        Self::with_max_size(ttl, DEFAULT_MAX_SIZE)
    }

    /// Creates a new cache with an explicit TTL and maximum entry count.
    /// When `set` would exceed `max_size`, the eldest entry is evicted.
    pub fn with_max_size(ttl: Duration, max_size: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
            max_size: max_size.max(1),
            next_seq: RwLock::new(0),
        }
    }

    /// Returns the configured maximum number of entries.
    pub fn max_size(&self) -> usize {
        self.max_size
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
    ///
    /// If inserting a *new* domain would push the cache over [`max_size`](Self::max_size),
    /// the eldest entry (lowest freshness sequence) is evicted first. Refreshing an
    /// existing domain does not grow the cache and bumps that entry's sequence
    /// so it is treated as recently used.
    pub fn set(&self, domain: &str, mode: RenderMode) {
        let mut entries = self.entries.write().expect("lock poisoned");
        let mut seq_guard = self.next_seq.write().expect("lock poisoned");
        let seq = *seq_guard;
        *seq_guard = seq.wrapping_add(1);
        drop(seq_guard);

        let is_new = !entries.contains_key(domain);
        if is_new && entries.len() >= self.max_size {
            // Eldest-first (LRU-style) capacity eviction: drop the entry with
            // the smallest sequence number.
            let eldest_key = entries
                .iter()
                .min_by_key(|(_, e)| e.seq)
                .map(|(k, _)| k.clone());
            if let Some(key) = eldest_key {
                tracing::warn!(
                    domain = %key,
                    max_size = self.max_size,
                    metric = "oxbrowser_render_cache_entries",
                    "render cache at capacity — evicting eldest entry"
                );
                entries.remove(&key);
            }
        }

        entries.insert(
            domain.to_owned(),
            Entry {
                mode,
                expires_at: Instant::now() + self.ttl,
                seq,
            },
        );
        drop(entries);
        self.publish_gauge();
    }

    /// Remove the cached mode for a domain.
    ///
    /// Used when a GiveUp entry must be evicted because the negcache cooldown
    /// has lifted: the next request should fall through to a normal fetch instead
    /// of fast-failing on a stale GiveUp.
    pub fn remove(&self, domain: &str) {
        let mut entries = self.entries.write().expect("lock poisoned");
        entries.remove(domain);
        drop(entries);
        self.publish_gauge();
    }

    /// Removes all expired entries from the cache.
    pub fn evict_expired(&self) {
        let mut entries = self.entries.write().expect("lock poisoned");
        let now = Instant::now();
        entries.retain(|_, entry| entry.expires_at > now);
        drop(entries);
        self.publish_gauge();
    }

    /// Snapshot the current entry count into the
    /// `oxbrowser_render_cache_entries` gauge.
    fn publish_gauge(&self) {
        let len = self.len();
        metrics::set_gauge(&RENDER_CACHE_ENTRIES, len as u64);
    }

    /// Returns the number of entries (including expired ones not yet evicted).
    pub fn len(&self) -> usize {
        self.entries.read().expect("lock poisoned").len()
    }

    /// Returns true if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.read().expect("lock poisoned").is_empty()
    }
}

impl Default for RenderModeCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(3600))
    }
}

/// Spawn a background task that periodically evicts expired entries.
///
/// Mirrors [`crate::cookie_cache::spawn_eviction_task`]. Call once at server
/// startup, passing the same `Arc<RenderModeCache>` that is wired into
/// `HttpConfig` and the read path.
pub fn spawn_eviction_task(cache: Arc<RenderModeCache>, interval: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            cache.evict_expired();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::thread;

    /// The gauge-publishing tests all read/write the shared process-global
    /// `RENDER_CACHE_ENTRIES` static. When run in parallel they race on that
    /// atomic, producing flaky assertions. This mutex serializes them so the
    /// gauge value is deterministic within each test.
    static GAUGE_TEST_LOCK: Mutex<()> = Mutex::new(());

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

    #[test]
    fn remove_clears_entry() {
        let cache = RenderModeCache::new(Duration::from_secs(60));
        cache.set("example.com", RenderMode::GiveUp);
        assert_eq!(cache.get("example.com"), Some(RenderMode::GiveUp));
        cache.remove("example.com");
        assert_eq!(cache.get("example.com"), None);
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let cache = RenderModeCache::new(Duration::from_secs(60));
        // Must not panic.
        cache.remove("never.set.com");
        assert_eq!(cache.get("never.set.com"), None);
    }

    #[test]
    fn evict_expired_removes_expired_entries() {
        let cache = RenderModeCache::new(Duration::from_millis(0));
        cache.set("a.com", RenderMode::Chrome);
        cache.set("b.com", RenderMode::Http);
        thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.len(), 2, "entries still present before eviction");
        cache.evict_expired();
        assert_eq!(
            cache.len(),
            0,
            "evict_expired must drop all expired entries"
        );
    }

    #[test]
    fn evict_expired_keeps_unexpired_entries() {
        let cache = RenderModeCache::new(Duration::from_secs(60));
        cache.set("a.com", RenderMode::Chrome);
        cache.set("b.com", RenderMode::Http);
        cache.evict_expired();
        assert_eq!(cache.len(), 2, "unexpired entries must survive eviction");
    }

    #[test]
    fn max_size_caps_entries_and_evicts_eldest() {
        let cache = RenderModeCache::with_max_size(Duration::from_secs(60), 3);
        cache.set("a.com", RenderMode::Http);
        cache.set("b.com", RenderMode::Chrome);
        cache.set("c.com", RenderMode::GiveUp);
        assert_eq!(cache.len(), 3);

        // Inserting a 4th distinct domain must evict the eldest (a.com).
        cache.set("d.com", RenderMode::Http);
        assert_eq!(
            cache.len(),
            3,
            "cache must stay bounded at max_size after insert"
        );
        assert!(
            cache.get("a.com").is_none(),
            "eldest entry (a.com) should have been evicted"
        );
        assert!(cache.get("b.com").is_some());
        assert!(cache.get("c.com").is_some());
        assert!(cache.get("d.com").is_some());
    }

    #[test]
    fn refresh_does_not_grow_cache_or_evict() {
        let cache = RenderModeCache::with_max_size(Duration::from_secs(60), 2);
        cache.set("a.com", RenderMode::Http);
        cache.set("b.com", RenderMode::Chrome);

        // Refreshing an existing domain must not evict anything.
        cache.set("a.com", RenderMode::Chrome);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("a.com"), Some(RenderMode::Chrome));
    }

    #[test]
    fn lru_bumps_seq_on_refresh() {
        // a.com inserted first (eldest). After refreshing it, b.com becomes
        // the eldest and should be the one evicted on overflow.
        let cache = RenderModeCache::with_max_size(Duration::from_secs(60), 2);
        cache.set("a.com", RenderMode::Http);
        cache.set("b.com", RenderMode::Chrome);
        // Refresh a.com → it is now the most-recently-used.
        cache.set("a.com", RenderMode::Chrome);
        // Insert c.com → b.com (eldest) should be evicted, not a.com.
        cache.set("c.com", RenderMode::GiveUp);
        assert_eq!(cache.len(), 2);
        assert!(
            cache.get("a.com").is_some(),
            "a.com was refreshed, should survive"
        );
        assert!(
            cache.get("b.com").is_none(),
            "b.com is eldest, should be evicted"
        );
        assert!(cache.get("c.com").is_some());
    }

    #[test]
    fn set_publishes_gauge() {
        let _guard = GAUGE_TEST_LOCK.lock().unwrap();
        RENDER_CACHE_ENTRIES.store(0, std::sync::atomic::Ordering::Relaxed);
        let cache = RenderModeCache::with_max_size(Duration::from_secs(60), 10);
        cache.set("a.com", RenderMode::Http);
        cache.set("b.com", RenderMode::Chrome);
        assert_eq!(
            RENDER_CACHE_ENTRIES.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "gauge should reflect live entry count after sets"
        );
    }

    #[test]
    fn evict_expired_publishes_gauge() {
        let _guard = GAUGE_TEST_LOCK.lock().unwrap();
        RENDER_CACHE_ENTRIES.store(0, std::sync::atomic::Ordering::Relaxed);
        let cache = RenderModeCache::with_max_size(Duration::from_millis(0), 10);
        cache.set("a.com", RenderMode::Http);
        cache.set("b.com", RenderMode::Chrome);
        thread::sleep(Duration::from_millis(5));
        assert_eq!(
            RENDER_CACHE_ENTRIES.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        cache.evict_expired();
        assert_eq!(
            RENDER_CACHE_ENTRIES.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "gauge should drop to 0 after eviction"
        );
    }

    #[test]
    fn remove_publishes_gauge() {
        let _guard = GAUGE_TEST_LOCK.lock().unwrap();
        RENDER_CACHE_ENTRIES.store(0, std::sync::atomic::Ordering::Relaxed);
        let cache = RenderModeCache::with_max_size(Duration::from_secs(60), 10);
        cache.set("a.com", RenderMode::Http);
        cache.set("b.com", RenderMode::Chrome);
        assert_eq!(
            RENDER_CACHE_ENTRIES.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        cache.remove("a.com");
        assert_eq!(
            RENDER_CACHE_ENTRIES.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "gauge should drop to 1 after remove"
        );
    }

    #[tokio::test]
    async fn spawn_eviction_task_drops_expired_after_ttl() {
        let cache = Arc::new(RenderModeCache::with_max_size(
            Duration::from_millis(0),
            100,
        ));
        cache.set("a.com", RenderMode::Http);
        cache.set("b.com", RenderMode::Chrome);
        assert_eq!(cache.len(), 2);

        // Spawn with a short interval; entries have TTL=0 so the first tick
        // (after they expire) must evict them.
        spawn_eviction_task(Arc::clone(&cache), Duration::from_millis(10));

        // Poll until the background task has run at least once.
        for _ in 0..50 {
            if cache.len() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            cache.len(),
            0,
            "background eviction task did not drop expired entries"
        );
    }
}
