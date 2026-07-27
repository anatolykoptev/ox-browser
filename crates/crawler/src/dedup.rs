//! URL and content deduplication.
//!
//! - [`UrlDedup`] tracks seen URLs via xxHash (xxh3_64).
//! - [`ContentDedup`] tracks seen page bodies via blake3.
//! - [`normalize_url`] canonicalizes URLs for dedup comparison.
//! - [`is_cycle`] detects crawler traps (repeating paths, extreme length).
//!
//! # Unbounded-growth guard (issue #19)
//!
//! Both dedup sets are bounded by `max_capacity` with LRU-style eldest-first
//! eviction (mirroring `ox_http::cookie_cache`). Without a cap, a large crawl
//! over millions of distinct URLs/content hashes grew the sets without bound
//! even though the frontier itself is capped at `max_pages * 10`. Eviction
//! events bump the `oxbrowser_crawler_dedup_evicted_total` counter and emit a
//! `tracing::warn!` so operators can alert on sustained cap pressure.

use std::collections::HashMap;

use ox_http::metrics::record_crawler_dedup_evicted;
use url::Url;
use xxhash_rust::xxh3::xxh3_64;

/// Default capacity when none is specified — large enough that typical crawls
/// never evict, but still bounded so a runaway crawl cannot OOM the process.
pub const DEFAULT_DEDUP_CAPACITY: usize = 100_000;

// ---------------------------------------------------------------------------
// URL dedup
// ---------------------------------------------------------------------------

/// Fast URL deduplication backed by xxHash-64, bounded by `max_capacity` with
/// LRU-style eldest-first eviction.
#[derive(Debug)]
pub struct UrlDedup {
    /// hash → monotonic insert sequence (for eldest eviction).
    seen: HashMap<u64, u64>,
    max_capacity: usize,
    next_seq: u64,
}

impl UrlDedup {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_DEDUP_CAPACITY)
    }

    /// Create a dedup set with an explicit capacity cap.
    pub fn with_capacity(max_capacity: usize) -> Self {
        Self {
            seen: HashMap::new(),
            max_capacity: max_capacity.max(1),
            next_seq: 0,
        }
    }

    /// Insert a **normalized** URL. Returns `true` if it was new.
    ///
    /// If the set is at capacity and the URL is new, the eldest entry (lowest
    /// sequence number) is evicted first.
    pub fn insert(&mut self, normalized_url: &str) -> bool {
        let hash = xxh3_64(normalized_url.as_bytes());
        if self.seen.contains_key(&hash) {
            return false;
        }
        self.evict_if_full();
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.seen.insert(hash, seq);
        true
    }

    pub fn contains(&self, normalized_url: &str) -> bool {
        let hash = xxh3_64(normalized_url.as_bytes());
        self.seen.contains_key(&hash)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Returns the configured maximum number of entries.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// Remove all entries, resetting the set to empty.
    pub fn clear(&mut self) {
        self.seen.clear();
        self.next_seq = 0;
    }

    /// Drop the eldest entry if the set is at capacity. Mirrors the
    /// `CookieCache::put` eviction pattern.
    fn evict_if_full(&mut self) {
        if self.seen.len() < self.max_capacity {
            return;
        }
        let eldest = self
            .seen
            .iter()
            .min_by_key(|(_, seq)| **seq)
            .map(|(k, _)| *k);
        if let Some(key) = eldest {
            tracing::warn!(
                max_capacity = self.max_capacity,
                metric = "oxbrowser_crawler_dedup_entries",
                "url dedup at capacity — evicting eldest hash"
            );
            self.seen.remove(&key);
            record_crawler_dedup_evicted();
        }
    }
}

impl Default for UrlDedup {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Content dedup
// ---------------------------------------------------------------------------

/// Content deduplication backed by blake3, bounded by `max_capacity` with
/// LRU-style eldest-first eviction.
#[derive(Debug)]
pub struct ContentDedup {
    /// hash → monotonic insert sequence (for eldest eviction).
    seen: HashMap<[u8; 32], u64>,
    max_capacity: usize,
    next_seq: u64,
}

impl ContentDedup {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_DEDUP_CAPACITY)
    }

    /// Create a content dedup set with an explicit capacity cap.
    pub fn with_capacity(max_capacity: usize) -> Self {
        Self {
            seen: HashMap::new(),
            max_capacity: max_capacity.max(1),
            next_seq: 0,
        }
    }

    /// Insert content bytes. Returns `true` if the content was new.
    ///
    /// If the set is at capacity and the content is new, the eldest entry is
    /// evicted first.
    pub fn insert(&mut self, content: &[u8]) -> bool {
        let hash = blake3::hash(content);
        let hash_bytes = *hash.as_bytes();
        if self.seen.contains_key(&hash_bytes) {
            return false;
        }
        self.evict_if_full();
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.seen.insert(hash_bytes, seq);
        true
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Returns the configured maximum number of entries.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// Remove all entries, resetting the set to empty.
    pub fn clear(&mut self) {
        self.seen.clear();
        self.next_seq = 0;
    }

    fn evict_if_full(&mut self) {
        if self.seen.len() < self.max_capacity {
            return;
        }
        let eldest = self
            .seen
            .iter()
            .min_by_key(|(_, seq)| **seq)
            .map(|(k, _)| *k);
        if let Some(key) = eldest {
            tracing::warn!(
                max_capacity = self.max_capacity,
                metric = "oxbrowser_crawler_dedup_entries",
                "content dedup at capacity — evicting eldest hash"
            );
            self.seen.remove(&key);
            record_crawler_dedup_evicted();
        }
    }
}

impl Default for ContentDedup {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// URL normalization
// ---------------------------------------------------------------------------

/// Normalize a URL for dedup comparison:
/// - Strip fragment (`#...`).
/// - Sort query parameters alphabetically.
/// - Lowercase scheme and host.
///
/// Returns `None` for unparseable URLs.
pub fn normalize_url(raw: &str) -> Option<String> {
    let mut parsed = Url::parse(raw).ok()?;

    // Strip fragment.
    parsed.set_fragment(None);

    // Sort query params.
    let mut pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    if pairs.is_empty() {
        parsed.set_query(None);
    } else {
        pairs.sort();
        let qs: Vec<String> = pairs
            .iter()
            .map(|(k, v)| {
                if v.is_empty() {
                    k.clone()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect();
        parsed.set_query(Some(&qs.join("&")));
    }

    Some(parsed.to_string())
}

// ---------------------------------------------------------------------------
// Cycle detection
// ---------------------------------------------------------------------------

const MAX_URL_LENGTH: usize = 2048;

/// Detect crawler traps:
/// - URL longer than 2048 bytes.
/// - Repeating path segments (e.g. `/a/b/a/b/a/b`).
pub fn is_cycle(url: &str) -> bool {
    if url.len() > MAX_URL_LENGTH {
        return true;
    }

    let path = match Url::parse(url) {
        Ok(u) => u.path().to_string(),
        Err(_) => return false,
    };

    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.len() < 4 {
        return false;
    }

    // Check for repeating patterns of length 1..=segments.len()/2.
    for pattern_len in 1..=segments.len() / 2 {
        if !segments.len().is_multiple_of(pattern_len) {
            continue;
        }
        let pattern = &segments[..pattern_len];
        let repeats = segments.chunks(pattern_len).all(|chunk| chunk == pattern);
        if repeats && segments.len() / pattern_len >= 2 {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_dedup_inserts_and_detects() {
        let mut d = UrlDedup::new();
        assert!(d.insert("https://example.com/"));
        assert!(!d.insert("https://example.com/"));
        assert!(d.insert("https://example.com/other"));
        assert_eq!(d.len(), 2);
        assert!(d.contains("https://example.com/"));
        assert!(!d.contains("https://never-seen.com/"));
    }

    #[test]
    fn content_dedup_detects_duplicates() {
        let mut d = ContentDedup::new();
        assert!(d.insert(b"hello world"));
        assert!(!d.insert(b"hello world"));
        assert!(d.insert(b"different content"));
    }

    #[test]
    fn normalize_strips_fragment() {
        let n = normalize_url("https://example.com/page#section").unwrap();
        assert_eq!(n, "https://example.com/page");
    }

    #[test]
    fn normalize_sorts_query_params() {
        let n = normalize_url("https://example.com/?z=1&a=2&m=3").unwrap();
        assert_eq!(n, "https://example.com/?a=2&m=3&z=1");
    }

    #[test]
    fn normalize_handles_invalid_url() {
        assert!(normalize_url("not a url at all").is_none());
    }

    #[test]
    fn cycle_detects_repeating_paths() {
        assert!(is_cycle("https://example.com/a/b/a/b"));
        assert!(is_cycle("https://example.com/x/y/z/x/y/z"));
        assert!(!is_cycle("https://example.com/a/b/c/d"));
    }

    #[test]
    fn cycle_detects_long_urls() {
        let long = format!("https://example.com/{}", "a".repeat(2100));
        assert!(is_cycle(&long));
    }

    // -----------------------------------------------------------------------
    // Bounded LRU tests (issue #19)
    // -----------------------------------------------------------------------

    #[test]
    fn url_dedup_caps_at_max_capacity_and_evicts_eldest() {
        let cap = 8;
        let mut d = UrlDedup::with_capacity(cap);

        // Fill to capacity.
        for i in 0..cap {
            let url = format!("https://example.com/p{i}");
            assert!(d.insert(&url), "insert {i} should be new");
        }
        assert_eq!(d.len(), cap);

        // The first URL inserted is the eldest — it must be evicted next.
        let eldest = "https://example.com/p0";
        assert!(d.contains(eldest));

        // Insert one beyond capacity.
        let overflow = "https://example.com/p99";
        assert!(d.insert(overflow));

        assert_eq!(
            d.len(),
            cap,
            "len must stay bounded at max_capacity after overflow insert"
        );
        assert!(
            !d.contains(eldest),
            "eldest entry (p0) should have been evicted"
        );
        assert!(d.contains(overflow));
    }

    #[test]
    fn url_dedup_clear_resets_state() {
        let mut d = UrlDedup::with_capacity(4);
        d.insert("https://example.com/a");
        d.insert("https://example.com/b");
        assert_eq!(d.len(), 2);
        assert!(!d.is_empty());

        d.clear();
        assert_eq!(d.len(), 0);
        assert!(d.is_empty());

        // After clear, previously-seen URLs are new again.
        assert!(d.insert("https://example.com/a"));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn content_dedup_caps_at_max_capacity_and_evicts_eldest() {
        let cap = 4;
        let mut d = ContentDedup::with_capacity(cap);

        for i in 0..cap {
            let body = format!("body-{i}");
            assert!(d.insert(body.as_bytes()));
        }
        assert_eq!(d.len(), cap);

        // Insert beyond capacity — eldest (body-0) evicted.
        assert!(d.insert(b"body-99"));
        assert_eq!(d.len(), cap);
        // body-0 was evicted so it's new again.
        assert!(d.insert(b"body-0"));
        assert_eq!(d.len(), cap);
    }

    #[test]
    fn content_dedup_clear_resets_state() {
        let mut d = ContentDedup::with_capacity(4);
        d.insert(b"alpha");
        d.insert(b"beta");
        assert_eq!(d.len(), 2);

        d.clear();
        assert_eq!(d.len(), 0);
        assert!(d.is_empty());

        assert!(d.insert(b"alpha"), "after clear, alpha should be new");
    }

    #[test]
    fn url_dedup_eviction_increments_counter() {
        use ox_http::metrics::CRAWLER_DEDUP_EVICTED_TOTAL;
        let before = CRAWLER_DEDUP_EVICTED_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
        let mut d = UrlDedup::with_capacity(2);
        d.insert("https://example.com/a");
        d.insert("https://example.com/b");
        // Third insert evicts eldest.
        d.insert("https://example.com/c");
        let after = CRAWLER_DEDUP_EVICTED_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            after,
            before + 1,
            "eviction counter must increment on cap eviction"
        );
    }
}
