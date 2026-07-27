//! Per-domain cookie cache with TTL-based expiration and bounded size.
//!
//! # Unbounded-growth guard (issue #17)
//!
//! Before this fix, [`CookieCache::evict_expired`] existed but nothing called
//! it on a schedule, and there was no cap on the number of tracked domains.
//! A crawler hitting many distinct domains accumulated one entry per domain
//! forever — unbounded memory growth. This module now mirrors
//! [`crate::solver_negcache`] in two ways:
//!
//! 1. A `max_size` cap with LRU-style eldest-first eviction on [`put`].
//! 2. A [`spawn_eviction_task`] that periodically drops expired entries.
//!
//! The live entry count is published to the `oxbrowser_cookie_cache_entries`
//! gauge (see [`crate::metrics`]) so operators can alert on cache pressure.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::cookie_provider::SolvedChallenge;
use crate::metrics::{self, COOKIE_CACHE_ENTRIES};

/// Default maximum number of distinct domains tracked before eldest eviction.
pub const DEFAULT_MAX_SIZE: usize = 4096;

struct CacheEntry {
    solution: SolvedChallenge,
    expires_at: Instant,
    /// Monotonic insert/refresh sequence number — used to find the eldest
    /// entry for LRU-style capacity eviction. Bumped on every `put`.
    seq: u64,
}

/// Thread-safe cache for solved Cloudflare challenges, keyed by domain.
pub struct CookieCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
    max_size: usize,
    /// Monotonic counter assigning each entry a freshness sequence number.
    next_seq: RwLock<u64>,
}

impl CookieCache {
    /// Creates a new cache with the given TTL for entries.
    pub fn new(ttl: Duration) -> Self {
        Self::with_max_size(ttl, DEFAULT_MAX_SIZE)
    }

    /// Creates a new cache with an explicit TTL and maximum entry count.
    /// When `put` would exceed `max_size`, the eldest entry is evicted.
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

    /// Returns a clone of the cached solution if present and not expired.
    pub fn get(&self, domain: &str) -> Option<SolvedChallenge> {
        let entries = self.entries.read().expect("lock poisoned");
        let entry = entries.get(domain)?;
        if Instant::now() < entry.expires_at {
            Some(entry.solution.clone())
        } else {
            None
        }
    }

    /// Stores a solved challenge for the given domain with the configured TTL.
    ///
    /// If inserting a *new* domain would push the cache over [`max_size`], the
    /// eldest entry (lowest freshness sequence) is evicted first. Refreshing an
    /// existing domain does not grow the cache and bumps that entry's sequence
    /// so it is treated as recently used.
    pub fn put(&self, domain: &str, solution: SolvedChallenge) {
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
                    metric = "oxbrowser_cookie_cache_entries",
                    "cookie cache at capacity — evicting eldest entry"
                );
                entries.remove(&key);
            }
        }

        entries.insert(
            domain.to_owned(),
            CacheEntry {
                solution,
                expires_at: Instant::now() + self.ttl,
                seq,
            },
        );
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
    /// `oxbrowser_cookie_cache_entries` gauge.
    fn publish_gauge(&self) {
        let len = self.len();
        metrics::set_gauge(&COOKIE_CACHE_ENTRIES, len as u64);
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

impl Default for CookieCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(25 * 60))
    }
}

/// Spawn a background task that periodically evicts expired entries.
///
/// Mirrors [`crate::solver_negcache::spawn_eviction_task`]. Call once at server
/// startup, passing the same `Arc<CookieCache>` that is wired into
/// `HttpConfig` and the request path.
pub fn spawn_eviction_task(cache: Arc<CookieCache>, interval: Duration) {
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
    use std::thread;

    fn make_solution(ua: &str) -> SolvedChallenge {
        let mut cookies = HashMap::new();
        cookies.insert("cf_clearance".into(), "tok-123".into());
        SolvedChallenge {
            cookies,
            user_agent: ua.into(),
            body: None,
        }
    }

    #[test]
    fn put_and_get() {
        let cache = CookieCache::new(Duration::from_secs(60));
        cache.put("example.com", make_solution("UA/1.0"));
        let got = cache.get("example.com").expect("should be present");
        assert_eq!(got.user_agent, "UA/1.0");
        assert_eq!(got.cookies.get("cf_clearance").unwrap(), "tok-123");
    }

    #[test]
    fn miss_on_unknown_domain() {
        let cache = CookieCache::new(Duration::from_secs(60));
        assert!(cache.get("unknown.com").is_none());
    }

    #[test]
    fn expired_entry_returns_none() {
        let cache = CookieCache::new(Duration::from_millis(0));
        cache.put("example.com", make_solution("UA/1.0"));
        thread::sleep(Duration::from_millis(5));
        assert!(cache.get("example.com").is_none());
    }

    #[test]
    fn evict_removes_expired() {
        let cache = CookieCache::new(Duration::from_millis(0));
        cache.put("a.com", make_solution("UA/1.0"));
        cache.put("b.com", make_solution("UA/2.0"));
        thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.len(), 2);
        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn overwrite_domain() {
        let cache = CookieCache::new(Duration::from_secs(60));
        cache.put("example.com", make_solution("Old"));
        cache.put("example.com", make_solution("New"));
        let got = cache.get("example.com").unwrap();
        assert_eq!(got.user_agent, "New");
    }

    #[test]
    fn len_and_is_empty() {
        let cache = CookieCache::new(Duration::from_secs(60));
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        cache.put("a.com", make_solution("UA"));
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        cache.put("b.com", make_solution("UA"));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn max_size_caps_entries_and_evicts_eldest() {
        let cache = CookieCache::with_max_size(Duration::from_secs(60), 3);
        cache.put("a.com", make_solution("UA/1"));
        cache.put("b.com", make_solution("UA/2"));
        cache.put("c.com", make_solution("UA/3"));
        assert_eq!(cache.len(), 3);

        // Inserting a 4th distinct domain must evict the eldest (a.com).
        cache.put("d.com", make_solution("UA/4"));
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
        let cache = CookieCache::with_max_size(Duration::from_secs(60), 2);
        cache.put("a.com", make_solution("UA/1"));
        cache.put("b.com", make_solution("UA/2"));

        // Refreshing an existing domain must not evict anything.
        cache.put("a.com", make_solution("UA/1b"));
        assert_eq!(cache.len(), 2);
        let got = cache.get("a.com").unwrap();
        assert_eq!(got.user_agent, "UA/1b");
    }

    #[test]
    fn lru_bumps_seq_on_refresh() {
        // a.com inserted first (eldest). After refreshing it, b.com becomes
        // the eldest and should be the one evicted on overflow.
        let cache = CookieCache::with_max_size(Duration::from_secs(60), 2);
        cache.put("a.com", make_solution("UA/1"));
        cache.put("b.com", make_solution("UA/2"));
        // Refresh a.com → it is now the most-recently-used.
        cache.put("a.com", make_solution("UA/1b"));
        // Insert c.com → b.com (eldest) should be evicted, not a.com.
        cache.put("c.com", make_solution("UA/3"));
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
    fn put_publishes_gauge() {
        COOKIE_CACHE_ENTRIES.store(0, std::sync::atomic::Ordering::Relaxed);
        let cache = CookieCache::with_max_size(Duration::from_secs(60), 10);
        cache.put("a.com", make_solution("UA"));
        cache.put("b.com", make_solution("UA"));
        assert_eq!(
            COOKIE_CACHE_ENTRIES.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "gauge should reflect live entry count after puts"
        );
    }

    #[test]
    fn evict_expired_publishes_gauge() {
        COOKIE_CACHE_ENTRIES.store(0, std::sync::atomic::Ordering::Relaxed);
        let cache = CookieCache::with_max_size(Duration::from_millis(0), 10);
        cache.put("a.com", make_solution("UA"));
        cache.put("b.com", make_solution("UA"));
        thread::sleep(Duration::from_millis(5));
        assert_eq!(
            COOKIE_CACHE_ENTRIES.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        cache.evict_expired();
        assert_eq!(
            COOKIE_CACHE_ENTRIES.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "gauge should drop to 0 after eviction"
        );
    }

    #[tokio::test]
    async fn spawn_eviction_task_drops_expired_after_ttl() {
        let cache = Arc::new(CookieCache::with_max_size(Duration::from_millis(0), 100));
        cache.put("a.com", make_solution("UA"));
        cache.put("b.com", make_solution("UA"));
        assert_eq!(cache.len(), 2);

        // Spawn with a short interval; entries have TTL=0 so the first tick
        // (after they expire) must evict them.
        spawn_eviction_task(Arc::clone(&cache), Duration::from_millis(10));

        // Poll until the background task has run at least once.
        for _ in 0..50 {
            if cache.is_empty() {
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
