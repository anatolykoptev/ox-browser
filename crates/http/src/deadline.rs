//! Per-call deadline seam — one function every outbound surface calls.
//!
//! Issue #139: `/fetch` accepted a `timeout` field and ignored it; `/read`,
//! both MCP tools, and both CLI subcommands had no such field at all. The
//! consumer (go-search research fan-out) runs against a hard 10-second
//! window, so a black-holed host costing ~83 s (4×20 s connect + backoff,
//! issue #133) blew the whole window, and the abandoned request kept
//! running inside the service after the caller moved on — round after
//! round, that residue accumulates and competes with the next fan-out.
//!
//! The bound is on the WHOLE call, not one attempt: a per-attempt timeout
//! is multiplied by the retry loop, which is the 83-second arithmetic.
//! Wrapping the top-level future bounds the retry loop, the solver
//! escalation, and the rate-limit `wait()` as a unit. On elapsed, the
//! inner future is dropped — cancelling the in-flight request and any
//! pending backoff — which is the mechanism that stops the service
//! accumulating orphaned work after the caller has moved on.
//!
//! Units are seconds everywhere, matching the existing `FetchRequest.timeout`
//! field and the `timeout_secs` key in the chrome-render request body
//! (`read_pipeline::chrome_fallback`). No surface introduces milliseconds.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use tokio::time::Instant;

use crate::metrics::{dec_outbound_inflight, inc_outbound_inflight};

/// Default per-call deadline (seconds). Chosen against go-search's
/// research fan-out, which runs against a hard 10-second window: 8 s
/// leaves ~2 s of headroom for the fan-out scheduler to start the
/// request and consume the response, while bounding a black-holed host
/// (issue #133's 4×20 s connect + backoff ≈ 83 s) to a single round.
/// The previous server default of 20 s was twice the consumer's whole
/// window.
pub const DEFAULT_CALL_TIMEOUT_SECS: u64 = 8;

/// Hard ceiling on the caller-supplied deadline (seconds). The `timeout`
/// field is attacker-influenced (anyone who can reach `/fetch` can set
/// it), so a caller asking for 600 s gets the ceiling, not 600 s. The
/// ceiling is [`SOLVER_CALL_BOUND_SECS`]: a fetch that escalates to a
/// cold solver pass is configured for up to 120 s behind Byparr — a
/// lower ceiling would turn a legitimate cold solve into a guaranteed
/// deadline error. Only an explicit caller `timeout` reaches this high.
///
/// NOTE (issue #156): `/fetch`, `/fetch-smart` and the MCP `fetch` tool
/// resolve `None` → the configured endpoint defaults
/// (`fetch.default_timeout_secs` = 15, `fetch.smart_timeout_secs` = 30),
/// NOT to this constant — a silent consumer relying on the 8 s bound must
/// send an explicit `timeout`. `/read`, MCP `read` and the CLI keep the
/// 8 s default; this constant remains their seam default.
pub const MAX_CALL_TIMEOUT_SECS: u64 = SOLVER_CALL_BOUND_SECS;

/// Resolve a caller-supplied timeout (seconds) into the effective
/// deadline: `None` → [`DEFAULT_CALL_TIMEOUT_SECS`], `Some(s)` → `s`
/// clamped to `[1, MAX_CALL_TIMEOUT_SECS]`. A 0 s deadline would reject
/// every request including a fast one, so it is clamped up to 1.
pub fn resolve_timeout(caller: Option<u64>) -> Duration {
    let secs = match caller {
        None => DEFAULT_CALL_TIMEOUT_SECS,
        Some(s) => s.clamp(1, MAX_CALL_TIMEOUT_SECS),
    };
    Duration::from_secs(secs)
}

/// Pull a caller-supplied `timeout`/`timeout_secs` (seconds) out of a JSON
/// arguments object — shared by the REST router layer and the MCP dispatch
/// bound so every surface honors the same field names without either side
/// knowing the route's input type (issue #147).
///
/// Tolerant by contract: a missing key or a non-u64 value yields `None` →
/// [`resolve_timeout`] applies the default bound. Fail-closed: an
/// unparseable caller hint still bounds the call, just at the default.
pub fn timeout_from_json(args: &serde_json::Map<String, serde_json::Value>) -> Option<u64> {
    // Canonical `timeout` wins only when it parses — a malformed value must
    // not shadow a valid `timeout_secs` spelled alongside it.
    args.get("timeout")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| args.get("timeout_secs").and_then(serde_json::Value::as_u64))
}

/// Per-surface designed bounds used by the REST router layer and the MCP
/// dispatch (issue #147). Each value is sized at least to the surface's
/// own inner designed bound — a bound smaller than the work it wraps
/// turns the surface's slow-but-legitimate path into a guaranteed 504.
///
/// [`resolve_timeout_for`] clamps a caller's `timeout` to `[1, default]`
/// for the matched surface: callers may tighten a call below its designed
/// bound but never extend past it — beyond it the surface's own inner
/// timeout fires first regardless.
/// Sized against the DEPLOYED `byparr_timeout_secs` (120 in the shipped
/// config.toml); raising the solver timeout past ~120 without bumping this
/// constant would invert the outer >= inner invariant.
pub const SOLVER_CALL_BOUND_SECS: u64 = 130;
/// `crates/media`'s DOWNLOAD_TIMEOUT (120 s) + margin.
pub const MEDIA_DOWNLOAD_BOUND_SECS: u64 = 130;
/// `gobrowser_proxy`'s reqwest client timeout (60 s) + margin.
pub const CHROME_PROXY_BOUND_SECS: u64 = 70;
/// MCP `crawl` runs the whole crawl synchronously; 120 s bounds a
/// max_pages=50 crawl generously without pretending the tool is fast.
pub const CRAWL_BOUND_SECS: u64 = 120;

/// Resolve a caller-supplied timeout against a per-surface designed bound
/// (issue #147): `None` → `default_secs`; `Some(s)` → `s` clamped to
/// `[1, default_secs]`.
pub fn resolve_timeout_for(caller: Option<u64>, default_secs: u64) -> Duration {
    debug_assert!(default_secs >= 1, "per-surface bound must be >= 1 s");
    Duration::from_secs(caller.unwrap_or(default_secs).clamp(1, default_secs))
}

/// The outcome of a deadline-bounded call. The caller can distinguish
/// "the bound fired" ([`CallOutcome::DeadlineExceeded`]) from "the site
/// failed" ([`CallOutcome::Ok`] carrying an `Err`), which a plain
/// `tokio::time::timeout` + error string cannot — the typed distinction
/// the metrics classifier and the 504-vs-502 split depend on.
#[derive(Debug)]
pub enum CallOutcome<T> {
    /// The call completed within the deadline. Carries the inner result
    /// (which may itself be an error from the site).
    Ok(T),
    /// The deadline elapsed before the call completed. The inner future
    /// was dropped, cancelling the in-flight request. `secs` is the
    /// effective deadline that fired (after clamping), so the caller can
    /// report which bound applied.
    DeadlineExceeded { secs: u64 },
}

/// Bound a whole call — not one attempt. This is the single seam every
/// outbound surface calls: directly by the fetch surfaces, via
/// [`crate::read_pipeline::read_page`] by the read surfaces, and for the
/// remaining REST routes and MCP tools by the router layer
/// (`crates/js/src/deadline_layer.rs`) / the MCP `call_tool` dispatch
/// (issue #147). It wraps
/// the top-level future with `tokio::time::timeout`; on elapsed the inner
/// future is dropped, cancelling the in-flight request and any pending
/// retry backoff. The in-flight gauge is incremented on entry and
/// decremented on exit (including on elapsed), so a scrape can answer
/// "did the abandoned request stop?".
pub async fn bounded<T, F>(deadline: Duration, fut: F) -> CallOutcome<T>
where
    F: Future<Output = T>,
{
    bounded_phased(deadline, fut).await.0
}

/// Which stage of a bounded call was running when the bound fired. Lets a
/// 504 body say "the limiter held the call" instead of blaming the site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Anything that is not a rate-limit wait: connect, upstream, solver, retry.
    Upstream,
    /// The per-domain rate limiter was sleeping for a permit.
    RateLimit,
}

impl Phase {
    /// Stable label for error bodies.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::RateLimit => "limiter",
        }
    }
}

const PHASE_UPSTREAM: u8 = 0;
const PHASE_RATELIMIT: u8 = 1;

/// Per-call context: the absolute deadline and the sticky phase marker.
/// Scoped as a task-local by [`bounded_phased`], so every layer beneath it
/// (the rate-limit middleware in particular) can see the remaining budget
/// without a signature change. A `tokio::spawn`ed child does not inherit it;
/// consumers treat "no context" as "no known budget".
#[derive(Clone)]
struct CallCtx {
    deadline: Instant,
    phase: Arc<AtomicU8>,
}

tokio::task_local! {
    static CALL_CTX: CallCtx;
}

/// Absolute deadline of the enclosing [`bounded`] call, if any.
pub fn call_deadline() -> Option<Instant> {
    CALL_CTX.try_with(|c| c.deadline).ok()
}

/// Mark the enclosing call as sitting in the rate limiter (`true`) or past
/// it (`false`). The marker is sticky on purpose: when the bound fires the
/// limiter future is dropped, so a guard-style reset would erase the very
/// evidence [`bounded_phased`] reads.
pub fn set_in_limiter(in_limiter: bool) {
    let _ = CALL_CTX.try_with(|c| {
        c.phase.store(
            if in_limiter {
                PHASE_RATELIMIT
            } else {
                PHASE_UPSTREAM
            },
            Ordering::Relaxed,
        );
    });
}

/// [`bounded`] that also reports the [`Phase`] the call was in when the
/// bound fired (always [`Phase::Upstream`] when it completed in time).
/// Nested calls share the outer phase marker and take the earlier deadline.
pub async fn bounded_phased<T, F>(deadline: Duration, fut: F) -> (CallOutcome<T>, Phase)
where
    F: Future<Output = T>,
{
    let _guard = OutboundGuard::new();
    let mine = Instant::now() + deadline;
    let ctx = match CALL_CTX.try_with(Clone::clone) {
        Ok(outer) => CallCtx {
            deadline: outer.deadline.min(mine),
            phase: outer.phase,
        },
        Err(_) => CallCtx {
            deadline: mine,
            phase: Arc::new(AtomicU8::new(PHASE_UPSTREAM)),
        },
    };
    let marker = Arc::clone(&ctx.phase);
    let res = CALL_CTX
        .scope(ctx, tokio::time::timeout(deadline, fut))
        .await;
    match res {
        Ok(v) => (CallOutcome::Ok(v), Phase::Upstream),
        Err(_) => {
            let phase = if marker.load(Ordering::Relaxed) == PHASE_RATELIMIT {
                Phase::RateLimit
            } else {
                Phase::Upstream
            };
            (
                CallOutcome::DeadlineExceeded {
                    secs: deadline.as_secs(),
                },
                phase,
            )
        }
    }
}

/// RAII guard for the outbound in-flight gauge. Inc on create, dec on
/// drop. Constructed only by [`bounded`], so the gauge moves only with
/// the seam — a surface that forgets the seam cannot forget the gauge.
struct OutboundGuard;

impl OutboundGuard {
    fn new() -> Self {
        inc_outbound_inflight();
        Self
    }
}

impl Drop for OutboundGuard {
    fn drop(&mut self) {
        dec_outbound_inflight();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_timeout_none_uses_default() {
        assert_eq!(
            resolve_timeout(None),
            Duration::from_secs(DEFAULT_CALL_TIMEOUT_SECS)
        );
    }

    #[test]
    fn resolve_timeout_some_uses_value() {
        assert_eq!(resolve_timeout(Some(3)), Duration::from_secs(3));
    }

    #[test]
    fn resolve_timeout_clamps_to_ceiling() {
        // A caller asking for 600 s gets the ceiling, not 600 s — the
        // field is attacker-influenced.
        assert_eq!(
            resolve_timeout(Some(600)),
            Duration::from_secs(MAX_CALL_TIMEOUT_SECS)
        );
        assert_eq!(
            resolve_timeout(Some(MAX_CALL_TIMEOUT_SECS)),
            Duration::from_secs(MAX_CALL_TIMEOUT_SECS)
        );
    }

    #[test]
    fn resolve_timeout_clamps_zero_up_to_one() {
        // A 0 s deadline would reject every request including a fast one.
        assert_eq!(resolve_timeout(Some(0)), Duration::from_secs(1));
    }

    /// The 504 body names where the time went: a call that dies while the
    /// limiter holds it reports `limiter`, one that dies elsewhere `upstream`.
    #[tokio::test(start_paused = true)]
    async fn bounded_phased_reports_limiter_phase_when_bound_fires_in_limiter() {
        let _gauge = crate::metrics::GAUGE_TEST_LOCK.lock().await;
        let (outcome, phase) = bounded_phased(Duration::from_secs(1), async {
            set_in_limiter(true);
            tokio::time::sleep(Duration::from_secs(60)).await;
        })
        .await;
        assert!(matches!(outcome, CallOutcome::DeadlineExceeded { .. }));
        assert_eq!(phase, Phase::RateLimit);

        let (outcome, phase) = bounded_phased(Duration::from_secs(1), async {
            set_in_limiter(true);
            set_in_limiter(false); // permit granted, now upstream
            tokio::time::sleep(Duration::from_secs(60)).await;
        })
        .await;
        assert!(matches!(outcome, CallOutcome::DeadlineExceeded { .. }));
        assert_eq!(phase, Phase::Upstream);
    }

    #[tokio::test(start_paused = true)]
    async fn call_deadline_is_visible_inside_bounded_and_nested_takes_earlier() {
        let _gauge = crate::metrics::GAUGE_TEST_LOCK.lock().await;
        assert!(call_deadline().is_none());
        let t0 = Instant::now();
        let outer = bounded(Duration::from_secs(10), async {
            let d = call_deadline().expect("deadline inside bounded");
            let nested = bounded(Duration::from_secs(60), async { call_deadline() }).await;
            (d, nested)
        })
        .await;
        let CallOutcome::Ok((d, CallOutcome::Ok(Some(inner)))) = outer else {
            panic!("unexpected outcome");
        };
        assert_eq!(d, t0 + Duration::from_secs(10));
        assert_eq!(inner, d, "nested bound must not extend the outer deadline");
    }

    #[tokio::test]
    async fn bounded_returns_ok_when_future_completes() {
        let _gauge = crate::metrics::GAUGE_TEST_LOCK.lock().await;
        let outcome: CallOutcome<u32> = bounded(Duration::from_secs(5), async { 42 }).await;
        assert!(matches!(outcome, CallOutcome::Ok(42)));
    }

    #[tokio::test]
    async fn bounded_returns_deadline_exceeded_when_future_slow() {
        let _gauge = crate::metrics::GAUGE_TEST_LOCK.lock().await;
        let outcome: CallOutcome<()> = bounded(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(2)).await;
        })
        .await;
        match outcome {
            CallOutcome::DeadlineExceeded { secs } => assert_eq!(secs, 0),
            other => panic!("expected DeadlineExceeded, got {other:?}"),
        }
    }

    #[test]
    fn timeout_from_json_picks_timeout() {
        let v = serde_json::json!({"timeout": 5});
        assert_eq!(timeout_from_json(v.as_object().unwrap()), Some(5));
    }

    #[test]
    fn timeout_from_json_accepts_timeout_secs_alias() {
        let v = serde_json::json!({"timeout_secs": 7});
        assert_eq!(timeout_from_json(v.as_object().unwrap()), Some(7));
    }

    #[test]
    fn timeout_from_json_ignores_missing_and_non_u64() {
        let missing = serde_json::Map::new();
        assert_eq!(timeout_from_json(&missing), None);
        // Non-integer / negative / float all resolve to the default bound.
        for bad in [
            serde_json::json!({"timeout": "8"}),
            serde_json::json!({"timeout": -1}),
            serde_json::json!({"timeout": 2.5}),
        ] {
            assert_eq!(timeout_from_json(bad.as_object().unwrap()), None);
        }
    }

    /// `timeout` wins over `timeout_secs` only when it parses — a malformed
    /// canonical value must not shadow a valid alias.
    #[test]
    fn timeout_from_json_unparseable_timeout_falls_back_to_alias() {
        let v = serde_json::json!({"timeout": "x", "timeout_secs": 30});
        assert_eq!(timeout_from_json(v.as_object().unwrap()), Some(30));
    }

    #[test]
    fn resolve_timeout_for_defaults_and_caps_at_surface_bound() {
        assert_eq!(
            resolve_timeout_for(None, 130),
            Duration::from_secs(130),
            "no caller timeout -> designed default"
        );
        // Tighten below the bound: allowed.
        assert_eq!(resolve_timeout_for(Some(5), 130), Duration::from_secs(5));
        // Extend past the designed bound: clamped down — the inner work
        // dies at its own timeout first regardless.
        assert_eq!(
            resolve_timeout_for(Some(600), 130),
            Duration::from_secs(130)
        );
    }
}
