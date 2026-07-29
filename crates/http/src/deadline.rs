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
use std::time::Duration;

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
/// it), so a caller asking for 600 s gets the ceiling, not 600 s. 60 s
/// is the largest legitimate single-page read (a slow origin behind a
/// solver escalation); anything beyond that is a misconfiguration or
/// abuse.
pub const MAX_CALL_TIMEOUT_SECS: u64 = 60;

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
/// outbound surface calls (directly by the fetch surfaces, and via
/// [`crate::read_pipeline::read_page`] by the read surfaces). It wraps
/// the top-level future with `tokio::time::timeout`; on elapsed the inner
/// future is dropped, cancelling the in-flight request and any pending
/// retry backoff. The in-flight gauge is incremented on entry and
/// decremented on exit (including on elapsed), so a scrape can answer
/// "did the abandoned request stop?".
pub async fn bounded<T, F>(deadline: Duration, fut: F) -> CallOutcome<T>
where
    F: Future<Output = T>,
{
    let _guard = OutboundGuard::new();
    match tokio::time::timeout(deadline, fut).await {
        Ok(v) => CallOutcome::Ok(v),
        Err(_) => CallOutcome::DeadlineExceeded {
            secs: deadline.as_secs(),
        },
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
        assert_eq!(resolve_timeout(None), Duration::from_secs(DEFAULT_CALL_TIMEOUT_SECS));
    }

    #[test]
    fn resolve_timeout_some_uses_value() {
        assert_eq!(resolve_timeout(Some(3)), Duration::from_secs(3));
    }

    #[test]
    fn resolve_timeout_clamps_to_ceiling() {
        // A caller asking for 600 s gets the ceiling, not 600 s — the
        // field is attacker-influenced.
        assert_eq!(resolve_timeout(Some(600)), Duration::from_secs(MAX_CALL_TIMEOUT_SECS));
        assert_eq!(resolve_timeout(Some(MAX_CALL_TIMEOUT_SECS)), Duration::from_secs(MAX_CALL_TIMEOUT_SECS));
    }

    #[test]
    fn resolve_timeout_clamps_zero_up_to_one() {
        // A 0 s deadline would reject every request including a fast one.
        assert_eq!(resolve_timeout(Some(0)), Duration::from_secs(1));
    }

    #[tokio::test]
    async fn bounded_returns_ok_when_future_completes() {
        let outcome: CallOutcome<u32> = bounded(Duration::from_secs(5), async { 42 }).await;
        assert!(matches!(outcome, CallOutcome::Ok(42)));
    }

    #[tokio::test]
    async fn bounded_returns_deadline_exceeded_when_future_slow() {
        let outcome: CallOutcome<()> =
            bounded(Duration::from_millis(10), async {
                tokio::time::sleep(Duration::from_secs(2)).await;
            })
            .await;
        match outcome {
            CallOutcome::DeadlineExceeded { secs } => assert_eq!(secs, 0),
            other => panic!("expected DeadlineExceeded, got {other:?}"),
        }
    }
}
