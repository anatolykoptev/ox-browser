//! Per-domain cookie cache with TTL-based expiration.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::cookie_provider::SolvedChallenge;

struct CacheEntry {
    solution: SolvedChallenge,
    expires_at: Instant,
}

/// Thread-safe cache for solved Cloudflare challenges, keyed by domain.
pub struct CookieCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl CookieCache {
    /// Creates a new cache with the given TTL for entries.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        }
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
    pub fn put(&self, domain: &str, solution: SolvedChallenge) {
        let mut entries = self.entries.write().expect("lock poisoned");
        entries.insert(
            domain.to_owned(),
            CacheEntry {
                solution,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    /// Removes all expired entries from the cache.
    pub fn evict_expired(&self) {
        let mut entries = self.entries.write().expect("lock poisoned");
        let now = Instant::now();
        entries.retain(|_, entry| entry.expires_at > now);
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
}
