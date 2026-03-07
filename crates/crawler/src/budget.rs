//! Per-path URL budgets for crawl scope control.

use std::collections::HashMap;

/// Per-path budget tracker.
///
/// Limits how many URLs can be crawled under each path prefix.
/// A special `"*"` key acts as a global budget applied before any
/// path-specific check.
pub struct Budget {
    limits: HashMap<String, usize>,
    counts: HashMap<String, usize>,
}

impl Budget {
    /// Create a new budget with the given path-prefix limits.
    ///
    /// Use `"*"` as the key for a global (total) budget.
    /// Other keys are matched by longest prefix against the URL path.
    pub fn new(limits: HashMap<String, usize>) -> Self {
        Self {
            limits,
            counts: HashMap::new(),
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
        if let Some(&global_limit) = self.limits.get("*") {
            let count = self.counts.entry("*".to_string()).or_insert(0);
            if *count >= global_limit {
                return false;
            }
        }

        // Find longest matching prefix.
        let matched_prefix = self
            .limits
            .keys()
            .filter(|k| *k != "*" && path.starts_with(k.as_str()))
            .max_by_key(|k| k.len())
            .cloned();

        // Check path-specific budget.
        if let Some(ref prefix) = matched_prefix {
            let limit = self.limits[prefix];
            let count = self.counts.entry(prefix.clone()).or_insert(0);
            if *count >= limit {
                return false;
            }
        }

        // All checks passed — increment counters.
        if self.limits.contains_key("*") {
            *self.counts.entry("*".to_string()).or_insert(0) += 1;
        }
        if let Some(prefix) = matched_prefix {
            *self.counts.entry(prefix).or_insert(0) += 1;
        }

        true
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
}
