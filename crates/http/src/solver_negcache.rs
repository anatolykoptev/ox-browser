//! Per-domain solver failure negative-cache (retry-storm guard).
//!
//! # The storm
//!
//! The CF solver path runs a 15-25s headless Chrome solve per challenge. The
//! read pipeline treats Chrome as a last resort and falls through to it on every
//! request (`read_pipeline.rs`). For a URL the solver *cannot* solve, nothing
//! remembers the failure: each new `/read` for the same domain re-runs the full
//! solve, so a single unsolvable site can re-trigger the 15-25s solver 20-143×
//! and saturate the solver pool.
//!
//! # The guard
//!
//! This is the negative twin of [`crate::cookie_cache::CookieCache`] (which
//! caches *successes*). It counts *consecutive solve failures* per domain inside
//! a sliding window. After `max_failures` failures, the domain enters a cooldown:
//! [`is_blocked`] returns `true` and the solver middleware short-circuits — it
//! returns the CF error immediately instead of paying for another doomed solve.
//! A success ([`record_success`]) clears the domain and ends the storm.
//!
//! Entries are keyed by `(domain, authenticated)` — the inbound gate's
//! `ok_secret` decision carried on the [`crate::middleware::Request`] — not
//! by domain alone (SEC-CR-017, ox-browser#177). A failure cohort keyed by
//! domain only lets anonymous or bearer-only callers (whose solves carry no
//! credential and, once go-wowa enforces, always fail) put the domain on
//! cooldown for EVERYONE: three anonymous failures would switch off CF
//! solving for authenticated callers fleet-wide. Keeping the guard — rather
//! than skipping `record_failure` for anonymous callers — matters in both
//! directions: anonymous traffic still needs the storm guard (a doomed solve
//! still costs a go-wowa roundtrip), and an anonymous solve succeeding under
//! go-wowa soft mode does not prove the authenticated path works either.
//! Each cohort accrues, blocks and clears independently.
//!
//! All state is in-memory and thread-safe (mirrors `CookieCache`). No new deps.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Number of times the solver was skipped for a domain on cooldown (the
/// retry-storm short-circuit fired). Exposed for operator-visible metrics;
/// the `/metrics` endpoint renders this as `oxbrowser_solver_giveup_total`.
pub static SOLVER_GIVEUP_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Increment the give-up counter and emit a greppable structured warning.
pub fn record_solver_giveup(domain: &str) {
    SOLVER_GIVEUP_TOTAL.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(
        domain = %domain,
        reason = "solver_negcache_cooldown",
        metric = "oxbrowser_solver_giveup_total",
        "solver skipped — domain on failure cooldown (retry-storm guard)"
    );
}

/// Default consecutive failures before a domain is put on cooldown.
pub const DEFAULT_MAX_FAILURES: u32 = 3;

/// Default cooldown after the failure threshold is hit.
pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(5 * 60);

/// Default window in which failures accumulate. A gap longer than this resets
/// the count (the site may have recovered).
pub const DEFAULT_FAILURE_WINDOW: Duration = Duration::from_secs(5 * 60);

struct DomainState {
    failures: u32,
    /// Last time a failure was recorded — used to age out stale counts.
    last_failure: Instant,
    /// When set and in the future, the domain is on cooldown.
    blocked_until: Option<Instant>,
}

/// Thread-safe per-domain solver-failure tracker.
///
/// The map key is `(domain, authenticated)` so the anonymous and
/// authenticated failure cohorts never share state (see module docs).
pub struct SolverNegCache {
    entries: RwLock<HashMap<(String, bool), DomainState>>,
    max_failures: u32,
    cooldown: Duration,
    window: Duration,
}

impl SolverNegCache {
    /// Construct with explicit thresholds.
    pub fn new(max_failures: u32, cooldown: Duration, window: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_failures: max_failures.max(1),
            cooldown,
            window,
        }
    }

    /// `true` if `domain` is currently on cooldown **for this caller's
    /// authentication cohort** and the solver should be skipped. Reading
    /// does not mutate state.
    ///
    /// `authenticated` must be the gate's `ok_secret` decision carried on
    /// the request — passing the OTHER cohort's value (or a constant) leaks
    /// its cooldown across the trust boundary (SEC-CR-017).
    pub fn is_blocked(&self, domain: &str, authenticated: bool) -> bool {
        let entries = self.entries.read().expect("lock poisoned");
        match entries
            .get(&(domain.to_owned(), authenticated))
            .and_then(|s| s.blocked_until)
        {
            Some(until) => Instant::now() < until,
            None => false,
        }
    }

    /// Record a solve failure for `domain` in the caller's authentication
    /// cohort. Returns `true` if this failure pushed that cohort's entry
    /// into (or kept it in) the blocked cooldown state.
    ///
    /// `authenticated` is the same gate decision [`is_blocked`] takes: a
    /// caller's failures must never poison the other cohort's entry — an
    /// anonymous solve storm must not put the domain on cooldown for
    /// authenticated callers (SEC-CR-017).
    pub fn record_failure(&self, domain: &str, authenticated: bool) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.write().expect("lock poisoned");
        let state = entries
            .entry((domain.to_owned(), authenticated))
            .or_insert(DomainState {
                failures: 0,
                last_failure: now,
                blocked_until: None,
            });

        // Age out a stale streak: if the last failure is older than the window,
        // the site may have recovered — start counting fresh.
        if now.duration_since(state.last_failure) > self.window {
            state.failures = 0;
            state.blocked_until = None;
        }

        state.failures = state.failures.saturating_add(1);
        state.last_failure = now;

        if state.failures >= self.max_failures {
            state.blocked_until = Some(now + self.cooldown);
            true
        } else {
            false
        }
    }

    /// Record a solve success for `domain` — clears the caller's cohort's
    /// failure streak and any cooldown (the storm is over for that cohort).
    ///
    /// Only the caller's own cohort clears: an anonymous solve succeeding
    /// (go-wowa soft mode) proves nothing about the credentialed path, and
    /// vice versa.
    pub fn record_success(&self, domain: &str, authenticated: bool) {
        let mut entries = self.entries.write().expect("lock poisoned");
        entries.remove(&(domain.to_owned(), authenticated));
    }

    /// Remove entries whose cooldown has expired and whose failure streak has
    /// aged past the window. Called periodically by `spawn_eviction_task`.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        let mut entries = self.entries.write().expect("lock poisoned");
        entries.retain(|_, s| {
            let blocked = s.blocked_until.is_some_and(|u| u > now);
            let recent = now.duration_since(s.last_failure) <= self.window;
            blocked || recent
        });
    }

    /// Number of tracked domains (test/observability helper).
    pub fn len(&self) -> usize {
        self.entries.read().expect("lock poisoned").len()
    }

    /// True if no domains are tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.read().expect("lock poisoned").is_empty()
    }
}

/// Spawn a background task that periodically evicts expired entries.
///
/// Run with the same interval as `cooldown` (e.g. `DEFAULT_COOLDOWN`).
/// Call once at server startup, passing the same `Arc<SolverNegCache>` that is
/// wired into the solver middleware and `HttpConfig`.
pub fn spawn_eviction_task(negcache: Arc<SolverNegCache>, interval: std::time::Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            negcache.evict_expired();
        }
    });
}

impl Default for SolverNegCache {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_FAILURES,
            DEFAULT_COOLDOWN,
            DEFAULT_FAILURE_WINDOW,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_threshold() {
        let nc = SolverNegCache::new(3, Duration::from_secs(60), Duration::from_secs(60));
        assert!(!nc.is_blocked("cf.example", true));
        assert!(!nc.record_failure("cf.example", true)); // 1
        assert!(!nc.is_blocked("cf.example", true));
        assert!(!nc.record_failure("cf.example", true)); // 2
        assert!(nc.record_failure("cf.example", true)); // 3 → blocked
        assert!(nc.is_blocked("cf.example", true));
    }

    #[test]
    fn success_clears_streak() {
        let nc = SolverNegCache::new(2, Duration::from_secs(60), Duration::from_secs(60));
        nc.record_failure("cf.example", true);
        assert!(nc.record_failure("cf.example", true)); // blocked
        assert!(nc.is_blocked("cf.example", true));
        nc.record_success("cf.example", true);
        assert!(!nc.is_blocked("cf.example", true));
        assert!(nc.is_empty());
    }

    #[test]
    fn cooldown_expires() {
        let nc = SolverNegCache::new(1, Duration::from_millis(10), Duration::from_secs(60));
        assert!(nc.record_failure("cf.example", true)); // blocked immediately
        assert!(nc.is_blocked("cf.example", true));
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            !nc.is_blocked("cf.example", true),
            "cooldown should have expired"
        );
    }

    #[test]
    fn stale_streak_resets_after_window() {
        let nc = SolverNegCache::new(3, Duration::from_secs(60), Duration::from_millis(10));
        nc.record_failure("cf.example", true); // 1
        nc.record_failure("cf.example", true); // 2
        std::thread::sleep(Duration::from_millis(20));
        // Window elapsed → streak resets, so this is failure #1 again, not #3.
        assert!(!nc.record_failure("cf.example", true));
        assert!(!nc.is_blocked("cf.example", true));
    }

    #[test]
    fn evict_drops_expired() {
        let nc = SolverNegCache::new(1, Duration::from_millis(5), Duration::from_millis(5));
        nc.record_failure("a.example", true);
        nc.record_failure("b.example", false);
        assert_eq!(nc.len(), 2);
        std::thread::sleep(Duration::from_millis(15));
        nc.evict_expired();
        assert_eq!(nc.len(), 0);
    }

    #[test]
    fn distinct_domains_independent() {
        let nc = SolverNegCache::new(2, Duration::from_secs(60), Duration::from_secs(60));
        nc.record_failure("a.example", true);
        assert!(nc.record_failure("a.example", true)); // a blocked
        assert!(nc.is_blocked("a.example", true));
        assert!(!nc.is_blocked("b.example", true)); // b untouched
    }

    /// SEC-CR-017 / ox-browser#177: the (domain, authenticated) key keeps the
    /// two failure cohorts disjoint in BOTH directions — anonymous failures
    /// never block authenticated callers, and authenticated failures never
    /// block anonymous ones.
    ///
    /// Mutation: key the map on domain alone (drop `authenticated` from the
    /// `(domain, authenticated)` key in `record_failure`/`is_blocked`) → the
    /// cross-cohort asserts below go RED.
    #[test]
    fn failure_cohorts_are_isolated() {
        let nc = SolverNegCache::new(2, Duration::from_secs(60), Duration::from_secs(60));

        // Anonymous storm hits the threshold…
        nc.record_failure("cf.example", false);
        assert!(nc.record_failure("cf.example", false));
        assert!(nc.is_blocked("cf.example", false));
        // …yet the authenticated cohort is untouched…
        assert!(!nc.is_blocked("cf.example", true));
        // …and vice versa.
        nc.record_failure("cf.example", true);
        assert!(nc.record_failure("cf.example", true));
        assert!(nc.is_blocked("cf.example", true));
        assert!(nc.is_blocked("cf.example", false));

        // A success clears only the caller's own cohort.
        nc.record_success("cf.example", true);
        assert!(!nc.is_blocked("cf.example", true));
        assert!(nc.is_blocked("cf.example", false));
        assert_eq!(nc.len(), 1);
    }
}
