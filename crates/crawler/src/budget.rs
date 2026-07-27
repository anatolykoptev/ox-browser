//! Per-path URL budgets for crawl scope control.

use std::collections::HashMap;

/// Default capacity for the counts map — large enough that typical crawls
/// never evict, but bounded so a crawl over many distinct path prefixes
/// cannot grow the map without bound (issue #23).
pub const DEFAULT_BUDGET_CAPACITY: usize = 100_000;

/// Per-path budget tracker.
///
/// Limits how many URLs can be crawled under each path prefix.
/// A special `"*"` key acts as a global budget applied before any
/// path-specific check.
///
/// # Unbounded-growth guard (issue #23)
///
/// The internal `counts` map is bounded by `max_capacity` with LRU-style
/// eldest-first eviction (mirroring [`crate::dedup`] / `ox_http::cookie_cache`).
/// Without a cap, a crawl over many distinct path prefixes grew the map
/// without bound. Eviction events emit a `tracing::warn!` so operators can
/// alert on sustained cap pressure. Use [`Budget::reset`] at crawl end to
/// release memory immediately.
pub struct Budget {
    limits: HashMap<String, usize>,
    /// path-prefix → (consumed count, monotonic access sequence for LRU).
    counts: HashMap<String, (usize, u64)>,
    max_capacity: usize,
    next_seq: u64,
}

impl Budget {
    /// Create a new budget with the given path-prefix limits.
    ///
    /// Use `"*"` as the key for a global (total) budget.
    /// Other keys are matched by longest prefix against the URL path.
    pub fn new(limits: HashMap<String, usize>) -> Self {
        Self::with_capacity(limits, DEFAULT_BUDGET_CAPACITY)
    }

    /// Create a budget with an explicit capacity cap for the counts map.
    pub fn with_capacity(limits: HashMap<String, usize>, max_capacity: usize) -> Self {
        Self {
            limits,
            counts: HashMap::new(),
            max_capacity: max_capacity.max(1),
            next_seq: 0,
        }
    }

    /// Try to consume one unit of budget for the given URL path.
    ///
    /// Returns `true` if the request is within budget (and increments
    /// counters), `false` if any applicable limit would be exceeded.
    ///
    /// Evaluation order:
    /// 1. Global `"*"` budget (if configured).
    /// 2. Longest matching path prefix (if any).
    ///
    /// If no limits match the path, the request is allowed.
    pub fn try_consume(&mut self, path: &str) -> bool {
        // Check global budget first.
        let global_exceeded = if let Some(&global_limit) = self.limits.get("*") {
            let entry = self.touch("*");
            entry.0 >= global_limit
        } else {
            false
        };
        if global_exceeded {
            return false;
        }

        // Find longest matching prefix.
        let matched_prefix = self
            .limits
            .keys()
            .filter(|k| *k != "*" && path.starts_with(k.as_str()))
            .max_by_key(|k| k.len())
            .cloned();

        // Check path-specific budget.
        let prefix_exceeded = if let Some(ref prefix) = matched_prefix {
            let limit = self.limits[prefix];
            let entry = self.touch(prefix);
            entry.0 >= limit
        } else {
            false
        };
        if prefix_exceeded {
            return false;
        }

        // All checks passed — increment counters.
        if self.limits.contains_key("*") {
            let entry = self.touch("*");
            entry.0 += 1;
        }
        if let Some(prefix) = matched_prefix {
            let entry = self.touch(&prefix);
            entry.0 += 1;
        }

        true
    }

    /// Touch a key: ensure it exists in the counts map and return a mutable
    /// reference to its `(count, seq)` entry, bumping the sequence to mark it
    /// most-recently-used. Evicts the least-recently-used entry if the map is
    /// at capacity and the key is new.
    fn touch(&mut self, key: &str) -> &mut (usize, u64) {
        if !self.counts.contains_key(key) {
            self.evict_if_full();
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.counts.entry(key.to_string()).or_insert((0, seq))
    }

    /// Drop the least-recently-used entry (lowest sequence) if the counts
    /// map is at capacity. Mirrors `UrlDedup::evict_if_full`.
    fn evict_if_full(&mut self) {
        if self.counts.len() < self.max_capacity {
            return;
        }
        let eldest = self
            .counts
            .iter()
            .min_by_key(|(_, (_, seq))| *seq)
            .map(|(k, _)| k.clone());
        if let Some(key) = eldest {
            tracing::warn!(
                max_capacity = self.max_capacity,
                evicted_prefix = %key,
                "budget counts at capacity — evicting least-recently-used prefix"
            );
            self.counts.remove(&key);
        }
    }

    /// Reset all counters to zero, releasing the counts map.
    ///
    /// Called at crawl end to free memory immediately (belt-and-suspenders —
    /// the `Arc` drops at function exit, but explicit reset documents intent).
    pub fn reset(&mut self) {
        self.counts.clear();
        self.next_seq = 0;
    }

    /// Returns the number of tracked path-prefix counters.
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Returns the configured maximum number of counters.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_budget_allows_everything() {
        let mut budget = Budget::new(HashMap::new());
        for _ in 0..100 {
            assert!(budget.try_consume("/any/path"));
        }
    }

    #[test]
    fn global_budget_limits_total() {
        let mut limits = HashMap::new();
        limits.insert("*".to_string(), 3);
        let mut budget = Budget::new(limits);

        assert!(budget.try_consume("/a"));
        assert!(budget.try_consume("/b"));
        assert!(budget.try_consume("/c"));
        assert!(!budget.try_consume("/d"));
    }

    #[test]
    fn path_budget_limits_prefix() {
        let mut limits = HashMap::new();
        limits.insert("/blog".to_string(), 2);
        let mut budget = Budget::new(limits);

        assert!(budget.try_consume("/blog/post-1"));
        assert!(budget.try_consume("/blog/post-2"));
        assert!(!budget.try_consume("/blog/post-3"));
        // Other paths are unaffected.
        assert!(budget.try_consume("/about"));
    }

    #[test]
    fn combined_global_and_path_budget() {
        let mut limits = HashMap::new();
        limits.insert("*".to_string(), 5);
        limits.insert("/api".to_string(), 2);
        let mut budget = Budget::new(limits);

        assert!(budget.try_consume("/api/v1"));
        assert!(budget.try_consume("/api/v2"));
        // Path budget exhausted.
        assert!(!budget.try_consume("/api/v3"));
        // Global budget still has room for other paths.
        assert!(budget.try_consume("/page/1"));
        assert!(budget.try_consume("/page/2"));
        assert!(budget.try_consume("/page/3"));
        // Global budget exhausted (5 total consumed).
        assert!(!budget.try_consume("/page/4"));
    }

    #[test]
    fn longest_prefix_wins() {
        let mut limits = HashMap::new();
        limits.insert("/docs".to_string(), 10);
        limits.insert("/docs/api".to_string(), 2);
        let mut budget = Budget::new(limits);

        // Matches /docs/api (longer prefix), limit=2.
        assert!(budget.try_consume("/docs/api/endpoint-1"));
        assert!(budget.try_consume("/docs/api/endpoint-2"));
        assert!(!budget.try_consume("/docs/api/endpoint-3"));

        // /docs (shorter prefix) still has budget.
        assert!(budget.try_consume("/docs/guide/intro"));
    }

    // -----------------------------------------------------------------------
    // Bounded LRU tests (issue #23)
    // -----------------------------------------------------------------------

    #[test]
    fn counts_bounded_by_max_capacity() {
        let cap = 8;
        let mut limits = HashMap::new();
        // More distinct prefixes than the cap — each with a generous limit.
        for i in 0..(cap + 5) {
            limits.insert(format!("/p{i}"), 1000);
        }
        let mut budget = Budget::with_capacity(limits, cap);

        for i in 0..(cap + 5) {
            let path = format!("/p{i}/page");
            assert!(budget.try_consume(&path));
        }
        assert!(
            budget.len() <= cap,
            "counts.len() = {} must be <= cap = {}",
            budget.len(),
            cap
        );
    }

    #[test]
    fn counts_eviction_keeps_most_recently_used() {
        let cap = 4;
        let mut limits = HashMap::new();
        for i in 0..(cap + 2) {
            limits.insert(format!("/p{i}"), 1000);
        }
        let mut budget = Budget::with_capacity(limits, cap);

        // Fill to capacity — /p0 is the eldest (lowest seq).
        for i in 0..cap {
            budget.try_consume(&format!("/p{i}/x"));
        }
        assert_eq!(budget.len(), cap);

        // Re-touch /p0 so it becomes most-recently-used.
        budget.try_consume("/p0/x");

        // Insert two more — should evict the now-eldest (not /p0).
        budget.try_consume(&format!("/p{cap}/x"));
        budget.try_consume(&format!("/p{}/x", cap + 1));

        assert_eq!(budget.len(), cap);
    }

    #[test]
    fn reset_zeroes_counters() {
        let mut limits = HashMap::new();
        limits.insert("*".to_string(), 3);
        let mut budget = Budget::new(limits);

        assert!(budget.try_consume("/a"));
        assert!(budget.try_consume("/b"));
        assert!(budget.try_consume("/c"));
        assert!(!budget.try_consume("/d"));
        assert_eq!(budget.len(), 1); // only "*" tracked

        budget.reset();
        assert_eq!(budget.len(), 0);

        // After reset, budget is fully replenished.
        assert!(budget.try_consume("/a"));
        assert!(budget.try_consume("/b"));
        assert!(budget.try_consume("/c"));
        assert!(!budget.try_consume("/d"));
    }

    #[test]
    fn reset_releases_all_prefix_counters() {
        let mut limits = HashMap::new();
        limits.insert("/blog".to_string(), 5);
        limits.insert("/api".to_string(), 5);
        let mut budget = Budget::new(limits);

        budget.try_consume("/blog/1");
        budget.try_consume("/api/1");
        assert_eq!(budget.len(), 2);

        budget.reset();
        assert_eq!(budget.len(), 0);

        // Counters replenished after reset.
        assert!(budget.try_consume("/blog/2"));
        assert!(budget.try_consume("/api/2"));
        assert_eq!(budget.len(), 2);
    }
}
