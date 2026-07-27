//! Per-domain robots.txt cache.
//!
//! # Unbounded-growth guard (issue #22)
//!
//! Before this fix, [`RobotsCache`] was an unbounded `HashMap` with no cap and
//! no TTL. A crawl hitting many distinct hosts grew the cache without limit
//! relative to `max_pages`, and a stale robots.txt was never refreshed within a
//! single crawl. This module now mirrors [`crate::dedup`] / `ox_http::cookie_cache`:
//!
//! 1. A `max_capacity` cap with LRU-style eldest-first eviction on insert.
//! 2. A per-entry `expires_at` TTL; expired entries are treated as misses by
//!    [`RobotsCache::is_allowed`] / [`RobotsCache::has_host`] /
//!    [`RobotsCache::crawl_delay`], triggering a re-fetch.
//!
//! The cache is constructed per crawl, so no background eviction task is needed
//! — expired entries are simply ignored on read and re-fetched by the caller.
//!
//! # TOCTOU fetch serialization (issue #25)
//!
//! The caller pattern is: lock → `has_host` check → release lock → async HTTP
//! fetch → lock → insert. Holding the lock across the async fetch is not viable
//! (it would serialize *all* hosts behind one fetch). Instead, an
//! `in_flight` set lives under the same `Mutex<RobotsCache>`: the first task
//! that finds a missing host registers it via [`RobotsCache::begin_fetch`] and
//! performs the fetch; concurrent tasks for the same host see it in-flight and
//! wait/retry until the entry appears, then reuse it. This guarantees a single
//! fetch per host under normal concurrency. See
//! [`crate::crawler::ensure_robots_loaded`].

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use texting_robots::Robot;

/// Default TTL for a cached robots.txt entry — 5 minutes. Long enough to avoid
/// re-fetching within a typical crawl, short enough that a stale policy is
/// refreshed mid-crawl.
pub const DEFAULT_ROBOTS_TTL: Duration = Duration::from_secs(300);

/// Default maximum number of distinct hosts tracked before eldest eviction.
pub const DEFAULT_ROBOTS_MAX_CAPACITY: usize = 4096;

/// Cached robots.txt entry for a single host.
struct RobotsEntry {
    /// Successfully parsed robots.txt, or `None` when the host was checked but
    /// robots.txt was unavailable (404, timeout, etc.).
    robot: Option<Robot>,
    /// When this entry expires. Reads past this instant treat the entry as a
    /// miss regardless of `robot`.
    expires_at: Instant,
    /// Monotonic insert/refresh sequence number — used to find the eldest entry
    /// for LRU-style capacity eviction. Bumped on every insert.
    seq: u64,
}

impl RobotsEntry {
    fn new(robot: Option<Robot>, expires_at: Instant, seq: u64) -> Self {
        Self {
            robot,
            expires_at,
            seq,
        }
    }

    /// True if the entry is past its TTL.
    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Per-domain robots.txt cache, bounded by `max_capacity` with LRU-style
/// eldest-first eviction and per-entry TTL.
pub struct RobotsCache {
    user_agent: String,
    entries: HashMap<String, RobotsEntry>,
    /// Hosts for which a robots.txt fetch is currently in progress. Prevents
    /// the TOCTOU double-fetch race (issue #25): only the task that
    /// successfully registers a host here performs the HTTP fetch; concurrent
    /// tasks for the same host wait for the entry to appear.
    in_flight: HashSet<String>,
    max_capacity: usize,
    ttl: Duration,
    next_seq: u64,
}

impl RobotsCache {
    /// Create a new cache with the given crawler user-agent string and the
    /// default capacity / TTL.
    pub fn new(user_agent: &str) -> Self {
        Self::with_limits(user_agent, DEFAULT_ROBOTS_MAX_CAPACITY, DEFAULT_ROBOTS_TTL)
    }

    /// Create a new cache with an explicit capacity cap and TTL.
    ///
    /// When an insert of a *new* host would push the cache over `max_capacity`,
    /// the eldest entry (lowest sequence number) is evicted first. Refreshing
    /// an existing host does not grow the cache and bumps that entry's sequence
    /// so it is treated as recently used.
    pub fn with_limits(user_agent: &str, max_capacity: usize, ttl: Duration) -> Self {
        Self {
            user_agent: user_agent.to_string(),
            entries: HashMap::new(),
            in_flight: HashSet::new(),
            max_capacity: max_capacity.max(1),
            ttl,
            next_seq: 0,
        }
    }

    /// Returns the configured maximum number of entries.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// Returns the configured TTL for entries.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Insert a successfully fetched robots.txt body for a host.
    ///
    /// Parses the body immediately and caches the result. If parsing fails the
    /// entry is stored as `Unavailable`. Refreshing an existing host bumps its
    /// LRU sequence so it is treated as recently used.
    pub fn insert(&mut self, host: &str, robots_txt_body: &[u8]) {
        let robot = match Robot::new(&self.user_agent, robots_txt_body) {
            Ok(robot) => Some(robot),
            Err(_) => None,
        };
        self.put(host, robot);
    }

    /// Mark a host as having no usable robots.txt (e.g. 404, network error).
    pub fn insert_unavailable(&mut self, host: &str) {
        self.put(host, None);
    }

    fn put(&mut self, host: &str, robot: Option<Robot>) {
        let is_new = !self.entries.contains_key(host);
        if is_new {
            self.evict_if_full();
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let entry = RobotsEntry::new(robot, Instant::now() + self.ttl, seq);
        self.entries.insert(host.to_string(), entry);
    }

    /// Drop the eldest entry if the cache is at capacity. Mirrors the
    /// `UrlDedup::evict_if_full` / `CookieCache::put` eviction pattern.
    fn evict_if_full(&mut self) {
        if self.entries.len() < self.max_capacity {
            return;
        }
        let eldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.seq)
            .map(|(k, _)| k.clone());
        if let Some(key) = eldest {
            tracing::warn!(
                host = %key,
                max_capacity = self.max_capacity,
                "robots cache at capacity — evicting eldest entry"
            );
            self.entries.remove(&key);
        }
    }

    /// Look up a live (non-expired) entry for a host.
    fn live_entry(&self, host: &str) -> Option<&RobotsEntry> {
        let now = Instant::now();
        match self.entries.get(host) {
            Some(entry) if !entry.is_expired(now) => Some(entry),
            _ => None,
        }
    }

    /// Check whether the given URL is allowed for crawling.
    ///
    /// Returns `true` if:
    /// - no robots.txt is cached for the host (permissive default),
    /// - the cached entry is expired (treated as a miss → permissive default),
    /// - the cached entry is `Unavailable`, or
    /// - the parsed robots.txt allows the URL.
    pub fn is_allowed(&self, host: &str, url: &str) -> bool {
        match self.live_entry(host) {
            None => true,
            Some(RobotsEntry {
                robot: Some(robot), ..
            }) => robot.allowed(url),
            // Expired entries are already filtered by live_entry; an
            // `Unavailable` (robot == None) entry is permissive.
            Some(RobotsEntry { robot: None, .. }) => true,
        }
    }

    /// Check whether we already have a *live* (non-expired) entry (loaded or
    /// unavailable) for a host. Expired entries return `false` so the caller
    /// re-fetches.
    pub fn has_host(&self, host: &str) -> bool {
        self.live_entry(host).is_some()
    }

    /// Return the crawl-delay (seconds) specified in robots.txt, if any.
    ///
    /// Returns `None` for missing, expired, or `Unavailable` entries.
    pub fn crawl_delay(&self, host: &str) -> Option<f64> {
        match self.live_entry(host)? {
            RobotsEntry {
                robot: Some(robot), ..
            } => robot.delay.map(|d| d as f64),
            _ => None,
        }
    }

    /// Register `host` as having an in-flight robots.txt fetch, returning
    /// `true` if this caller is the fetcher (host was *not* already
    /// in-flight). Returns `false` if another task is already fetching this
    /// host — the caller should wait and re-check [`RobotsCache::has_host`].
    ///
    /// This must be paired with [`RobotsCache::end_fetch`] once the fetch
    /// completes (success or failure) so the host can be re-fetched later if
    /// the entry expires. Callers should *not* hold the enclosing lock across
    /// the async HTTP fetch.
    pub fn begin_fetch(&mut self, host: &str) -> bool {
        if self.in_flight.contains(host) {
            // Defensive observability: a second caller reaching here under the
            // lock means the wait-loop gave up (safety valve) and is about to
            // perform a duplicate fetch.
            tracing::warn!(
                host = %host,
                "robots.txt fetch already in-flight for host — duplicate fetch possible"
            );
            return false;
        }
        self.in_flight.insert(host.to_string());
        true
    }

    /// Returns `true` if a robots.txt fetch for `host` is currently in flight.
    pub fn is_fetching(&self, host: &str) -> bool {
        self.in_flight.contains(host)
    }

    /// Clear the in-flight marker for `host`. Called after the fetcher has
    /// inserted the entry (or marked it unavailable). Safe to call even if the
    /// host was not registered (no-op).
    pub fn end_fetch(&mut self, host: &str) {
        self.in_flight.remove(host);
    }

    /// Returns the number of entries (including expired ones not yet evicted).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Extract `Sitemap:` URLs from a robots.txt body.
pub fn extract_sitemaps(robots_txt: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(robots_txt);
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.len() > 8 && line[..8].eq_ignore_ascii_case("sitemap:") {
                Some(line[8..].trim().to_string())
            } else {
                None
            }
        })
        .filter(|url| !url.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    const UA: &str = "ox-crawler";

    #[test]
    fn allows_when_no_robots() {
        let cache = RobotsCache::new(UA);
        assert!(cache.is_allowed("example.com", "https://example.com/page"));
    }

    #[test]
    fn allows_when_unavailable() {
        let mut cache = RobotsCache::new(UA);
        cache.insert_unavailable("example.com");
        assert!(cache.is_allowed("example.com", "https://example.com/secret"));
    }

    #[test]
    fn blocks_disallowed_path() {
        let mut cache = RobotsCache::new(UA);
        let body = b"User-agent: *\nDisallow: /private/\n";
        cache.insert("example.com", body);
        assert!(!cache.is_allowed("example.com", "https://example.com/private/data"));
        assert!(cache.is_allowed("example.com", "https://example.com/public"));
    }

    #[test]
    fn has_host_tracking() {
        let mut cache = RobotsCache::new(UA);
        assert!(!cache.has_host("example.com"));
        cache.insert("example.com", b"User-agent: *\nAllow: /\n");
        assert!(cache.has_host("example.com"));
    }

    #[test]
    fn parses_crawl_delay() {
        let mut cache = RobotsCache::new(UA);
        let body = b"User-agent: *\nCrawl-delay: 2.5\n";
        cache.insert("example.com", body);
        let delay = cache.crawl_delay("example.com");
        assert!(delay.is_some());
        assert!((delay.unwrap() - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn no_crawl_delay_when_absent() {
        let mut cache = RobotsCache::new(UA);
        let body = b"User-agent: *\nAllow: /\n";
        cache.insert("example.com", body);
        assert!(cache.crawl_delay("example.com").is_none());
    }

    #[test]
    fn extracts_sitemap_urls() {
        let body = b"User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml\nSitemap: https://example.com/sitemap2.xml\n";
        let urls = extract_sitemaps(body);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://example.com/sitemap.xml");
        assert_eq!(urls[1], "https://example.com/sitemap2.xml");
    }

    #[test]
    fn no_sitemaps_in_robots() {
        let body = b"User-agent: *\nDisallow: /private/\n";
        let urls = extract_sitemaps(body);
        assert!(urls.is_empty());
    }

    // -----------------------------------------------------------------------
    // Bounded LRU + TTL tests (issue #22)
    // -----------------------------------------------------------------------

    #[test]
    fn caps_at_max_capacity_and_evicts_eldest() {
        let cap = 4;
        let mut cache = RobotsCache::with_limits(UA, cap, Duration::from_secs(300));

        // Fill to capacity.
        for i in 0..cap {
            let host = format!("host{i}.example");
            cache.insert(&host, b"User-agent: *\nAllow: /\n");
        }
        assert_eq!(cache.len(), cap);

        // The first host inserted is the eldest — it must be evicted next.
        let eldest = "host0.example";
        assert!(cache.has_host(eldest));

        // Insert one beyond capacity.
        cache.insert("host99.example", b"User-agent: *\nAllow: /\n");

        assert_eq!(
            cache.len(),
            cap,
            "len must stay bounded at max_capacity after overflow insert"
        );
        assert!(
            !cache.has_host(eldest),
            "eldest entry ({eldest}) should have been evicted"
        );
        assert!(cache.has_host("host99.example"));
    }

    #[test]
    fn lru_bumps_seq_on_refresh() {
        // host0 inserted first (eldest). After refreshing it, host1 becomes
        // the eldest and should be the one evicted on overflow.
        let cap = 2;
        let mut cache = RobotsCache::with_limits(UA, cap, Duration::from_secs(300));
        cache.insert("host0.example", b"User-agent: *\nAllow: /\n");
        cache.insert("host1.example", b"User-agent: *\nAllow: /\n");
        // Refresh host0 → it is now the most-recently-used.
        cache.insert("host0.example", b"User-agent: *\nDisallow: /private/\n");
        // Insert host2 → host1 (eldest) should be evicted, not host0.
        cache.insert("host2.example", b"User-agent: *\nAllow: /\n");

        assert_eq!(cache.len(), cap);
        assert!(
            cache.has_host("host0.example"),
            "host0 was refreshed, should survive"
        );
        assert!(
            !cache.has_host("host1.example"),
            "host1 is eldest, should be evicted"
        );
        assert!(cache.has_host("host2.example"));
    }

    #[test]
    fn ttl_expired_entry_treated_as_miss() {
        let mut cache = RobotsCache::with_limits(UA, 16, Duration::from_millis(10));
        cache.insert("example.com", b"User-agent: *\nDisallow: /private/\n");
        // Disallow is live right now.
        assert!(!cache.is_allowed("example.com", "https://example.com/private/x"));

        // Let the short-TTL entry expire.
        thread::sleep(Duration::from_millis(20));

        // Expired → treated as a miss → permissive default (allowed).
        assert!(
            cache.is_allowed("example.com", "https://example.com/private/x"),
            "expired entry must be treated as a miss (permissive)"
        );
        assert!(
            !cache.has_host("example.com"),
            "expired entry must not be reported as a known host"
        );
        assert!(
            cache.crawl_delay("example.com").is_none(),
            "expired entry must not yield a crawl-delay"
        );
    }

    #[test]
    fn ttl_expired_unavailable_treated_as_miss() {
        let mut cache = RobotsCache::with_limits(UA, 16, Duration::from_millis(10));
        cache.insert_unavailable("example.com");
        assert!(cache.has_host("example.com"));

        thread::sleep(Duration::from_millis(20));
        assert!(
            !cache.has_host("example.com"),
            "expired unavailable entry must be treated as a miss"
        );
    }

    #[test]
    fn refresh_after_ttl_replaces_entry() {
        let mut cache = RobotsCache::with_limits(UA, 16, Duration::from_millis(10));
        cache.insert("example.com", b"User-agent: *\nDisallow: /private/\n");
        thread::sleep(Duration::from_millis(20));
        assert!(!cache.has_host("example.com"));

        // Re-fetch (refresh) — the entry is live again and enforces the rule.
        cache.insert("example.com", b"User-agent: *\nDisallow: /private/\n");
        assert!(cache.has_host("example.com"));
        assert!(!cache.is_allowed("example.com", "https://example.com/private/x"));
    }

    // -----------------------------------------------------------------------
    // In-flight fetch guard (issue #25 — TOCTOU double-fetch race)
    // -----------------------------------------------------------------------

    #[test]
    fn begin_fetch_registers_first_caller_only() {
        let mut cache = RobotsCache::new(UA);
        // First caller wins the fetcher slot.
        assert!(cache.begin_fetch("example.com"));
        assert!(cache.is_fetching("example.com"));
        // A concurrent caller for the same host must not become a fetcher.
        assert!(!cache.begin_fetch("example.com"));
        // A different host is independent.
        assert!(cache.begin_fetch("other.example"));
        assert!(cache.is_fetching("other.example"));
    }

    #[test]
    fn end_fetch_clears_in_flight_marker() {
        let mut cache = RobotsCache::new(UA);
        assert!(cache.begin_fetch("example.com"));
        assert!(cache.is_fetching("example.com"));
        cache.end_fetch("example.com");
        assert!(!cache.is_fetching("example.com"));
        // After release, a new caller can become the fetcher again (e.g. after
        // TTL expiry).
        assert!(cache.begin_fetch("example.com"));
    }

    #[test]
    fn end_fetch_is_noop_for_unregistered_host() {
        let mut cache = RobotsCache::new(UA);
        // Removing a host that was never registered must not panic.
        cache.end_fetch("never-fetched.example");
        assert!(!cache.is_fetching("never-fetched.example"));
    }
}
