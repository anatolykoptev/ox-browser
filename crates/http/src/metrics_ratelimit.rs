//! Rate-limiter metrics, labelled by rule.
//!
//! `metrics.rs` keeps fixed `&'static` counter rows; the limiter's label set
//! is the configured rule list, known only at startup, so these series live
//! in a small registry here and are appended by [`crate::metrics::render`].
//! The `rule` label is the rule's domain pattern (`*.finance.yahoo.com`,
//! `catch_all`) — never the request host — so cardinality is bounded by the
//! number of configured rules, not by traffic.
//!
//! - `oxbrowser_ratelimit_wait_seconds{rule}` — histogram of the time every
//!   admitted request spent waiting for its permit (zero waits included, so
//!   quantiles describe callers, not only the throttled ones).
//! - `oxbrowser_ratelimit_deadline_refusals_total{rule}` — calls refused
//!   because the permit would have arrived after the call's deadline.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::time::Duration;

/// Upper bounds (seconds) of the wait histogram buckets; `+Inf` is implicit.
const BUCKETS: [f64; 11] = [
    0.001, 0.01, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0,
];

#[derive(Default)]
struct RuleStats {
    /// Non-cumulative per-bucket counts; the last slot is `+Inf`.
    buckets: [u64; BUCKETS.len() + 1],
    count: u64,
    sum_secs: f64,
    refused: u64,
}

static STATS: Mutex<BTreeMap<String, RuleStats>> = Mutex::new(BTreeMap::new());

/// Label value for a rule's domain pattern (the catch-all pattern is `""`).
pub fn rule_label(pattern: &str) -> &str {
    if pattern.is_empty() {
        "catch_all"
    } else {
        pattern
    }
}

fn with_rule(rule: &str, f: impl FnOnce(&mut RuleStats)) {
    let mut stats = STATS.lock().unwrap_or_else(|e| e.into_inner());
    f(stats.entry(rule.to_string()).or_default());
}

/// Record how long an admitted request waited for its permit.
pub fn record_wait(rule: &str, waited: Duration) {
    let secs = waited.as_secs_f64();
    let slot = BUCKETS
        .iter()
        .position(|&b| secs <= b)
        .unwrap_or(BUCKETS.len());
    with_rule(rule, |s| {
        s.buckets[slot] += 1;
        s.count += 1;
        s.sum_secs += secs;
    });
}

/// Record a call refused because the permit would outlive its deadline.
pub fn record_deadline_refusal(rule: &str) {
    with_rule(rule, |s| s.refused += 1);
}

/// Escape a label value per the Prometheus text format.
fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Append both series to `out` in Prometheus text exposition format.
pub fn render_into(out: &mut String) {
    let stats = STATS.lock().unwrap_or_else(|e| e.into_inner());

    out.push_str(
        "# HELP oxbrowser_ratelimit_wait_seconds Time admitted requests spent waiting for a rate-limit permit, by rule (the rule's domain pattern; catch_all for the default rule). Zero waits are included.\n# TYPE oxbrowser_ratelimit_wait_seconds histogram\n",
    );
    for (rule, s) in stats.iter() {
        let rule = escape(rule);
        let mut cumulative = 0;
        for (i, bound) in BUCKETS.iter().enumerate() {
            cumulative += s.buckets[i];
            let _ = writeln!(
                out,
                "oxbrowser_ratelimit_wait_seconds_bucket{{rule=\"{rule}\",le=\"{bound}\"}} {cumulative}"
            );
        }
        let _ = writeln!(
            out,
            "oxbrowser_ratelimit_wait_seconds_bucket{{rule=\"{rule}\",le=\"+Inf\"}} {}",
            s.count
        );
        let _ = writeln!(
            out,
            "oxbrowser_ratelimit_wait_seconds_sum{{rule=\"{rule}\"}} {}",
            s.sum_secs
        );
        let _ = writeln!(
            out,
            "oxbrowser_ratelimit_wait_seconds_count{{rule=\"{rule}\"}} {}",
            s.count
        );
    }

    out.push_str(
        "# HELP oxbrowser_ratelimit_deadline_refusals_total Calls refused with 429 because the rate-limit wait would have outlived the call's deadline, by rule.\n# TYPE oxbrowser_ratelimit_deadline_refusals_total counter\n",
    );
    for (rule, s) in stats.iter() {
        let _ = writeln!(
            out,
            "oxbrowser_ratelimit_deadline_refusals_total{{rule=\"{}\"}} {}",
            escape(rule),
            s.refused
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_value(body: &str, prefix: &str) -> Option<f64> {
        body.lines()
            .find(|l| l.starts_with(prefix))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
    }

    #[test]
    fn wait_histogram_is_cumulative_and_labelled_by_rule() {
        let rule = "test-hist.example";
        record_wait(rule, Duration::ZERO);
        record_wait(rule, Duration::from_millis(300));
        record_wait(rule, Duration::from_secs(200));
        let mut body = String::new();
        render_into(&mut body);
        let b = |le: &str| {
            line_value(
                &body,
                &format!("oxbrowser_ratelimit_wait_seconds_bucket{{rule=\"{rule}\",le=\"{le}\"}}"),
            )
        };
        assert_eq!(b("0.001"), Some(1.0));
        assert_eq!(b("0.5"), Some(2.0));
        assert_eq!(b("120"), Some(2.0));
        assert_eq!(b("+Inf"), Some(3.0));
        assert_eq!(
            line_value(
                &body,
                &format!("oxbrowser_ratelimit_wait_seconds_count{{rule=\"{rule}\"}}")
            ),
            Some(3.0)
        );
    }

    #[test]
    fn refusals_counted_per_rule() {
        let rule = "test-refuse.example";
        record_deadline_refusal(rule);
        record_deadline_refusal(rule);
        let mut body = String::new();
        render_into(&mut body);
        assert_eq!(
            line_value(
                &body,
                &format!("oxbrowser_ratelimit_deadline_refusals_total{{rule=\"{rule}\"}}")
            ),
            Some(2.0)
        );
    }

    #[test]
    fn catch_all_gets_a_name() {
        assert_eq!(rule_label(""), "catch_all");
        assert_eq!(rule_label("*.x.com"), "*.x.com");
    }
}
