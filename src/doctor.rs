//! `doctor` subcommand — explicit self-check of the running instance, with
//! the fingerprint oracle moved into it (issue #109).
//!
//! The oracle used to be a feature-gated **test** that built its own client
//! from source and measured that — the defect class this repo has spent a
//! week removing: the artifact under test is not the artifact that ships.
//! `doctor` lives inside the binary and measures the client the service
//! builds (`HttpClient::new` via the shared `build_http_client_for_profile`
//! seam), including in the production container.
//!
//! # Three outcomes, not two
//!
//! - **fail** — a real mismatch against the reference, or an invalid config.
//!   Non-zero exit. This is drift.
//! - **warn** — reference older than ~90 days, solver absent, proxy unset.
//!   Zero exit; these are states an operator may have chosen deliberately.
//! - **skip** — an echo service unreachable or returning something
//!   unparseable. Not drift, must never be reported as drift. Zero exit.
//!
//! # Live calls
//!
//! `doctor` makes live calls to third-party echo services (tls.peet.ws,
//! tls.browserleaks.com) and probes configured solver / chrome-render /
//! proxy endpoints. It runs ONLY when invoked explicitly — never from
//! `serve` startup, never from a health check, never implicitly as part of
//! another subcommand.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use ox_http::fingerprint::{
    self, BROWSERLEAKS_ENDPOINT, PEET_ENDPOINT, Reference, classify_for_reference, compare,
    embedded_reference_pairs, extract_browserleaks, extract_peet, merge_observed,
};
use ox_http::{BUILTIN_PROFILES, BrowserProfile, HttpClient};

use crate::cli::build_http_client_for_profile;
use crate::config;

/// Arguments for the `doctor` subcommand, parsed by clap in `main.rs`.
pub struct DoctorArgs {
    /// Override the proxy URL (else taken from config.toml `[proxy]`).
    pub proxy: Option<String>,
    /// Enable debug logging for the measured HTTP requests.
    pub debug: bool,
    /// Emit the structured verdict as JSON on stdout (pipeable to jq).
    pub json: bool,
}

/// Threshold for the reference-age warning (days). Matches the workflow's
/// freshness note.
const REFERENCE_AGE_WARN_DAYS: i64 = 90;

// ── Verdict model ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Skip,
    Fail,
}

impl CheckStatus {
    /// Aggregate a set of statuses into one: fail > warn > skip > pass.
    fn aggregate(statuses: &[CheckStatus]) -> CheckStatus {
        if statuses.contains(&CheckStatus::Fail) {
            CheckStatus::Fail
        } else if statuses.contains(&CheckStatus::Warn) {
            CheckStatus::Warn
        } else if statuses.contains(&CheckStatus::Skip) {
            CheckStatus::Skip
        } else {
            CheckStatus::Pass
        }
    }
}

#[derive(Debug, Serialize)]
struct CheckReport {
    name: &'static str,
    status: CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    profiles: Vec<ProfileReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_age_days: Option<i64>,
}

#[derive(Debug, Serialize)]
struct ProfileReport {
    major: String,
    status: CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ja4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_ja4: Option<String>,
    /// Full browser version from the embedded reference (e.g. "148.0.7778.178").
    #[serde(skip_serializing_if = "Option::is_none")]
    browser_version: Option<String>,
    /// ISO-8601 capture timestamp from the embedded reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    capture_time: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hard_failures: Vec<FieldReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    gap_closed: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_age_days: Option<i64>,
}

#[derive(Debug, Serialize)]
struct FieldReport {
    field: String,
    expected: String,
    observed: String,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    verdict: CheckStatus,
    checks: Vec<CheckReport>,
}

// ── Run ────────────────────────────────────────────────────────────────

/// Run the `doctor` subcommand.
///
/// Output contract (mirrors `fetch`/`read`):
/// - default (human): per-check status + details → stdout, metadata → stderr;
/// - `--json`: the full `DoctorReport` JSON → stdout (pipeable to jq);
/// - exit non-zero ONLY on `fail`.
pub async fn run(args: DoctorArgs) -> anyhow::Result<()> {
    let mut checks: Vec<CheckReport> = Vec::new();

    // 1 — config validity.
    let server_config = check_config(&mut checks);

    // 2 — fingerprint against the embedded references.
    let proxy = args
        .proxy
        .clone()
        .or_else(|| server_config.as_ref().and_then(|c| c.proxy.url.clone()));
    check_fingerprint(&mut checks, proxy.as_deref(), args.debug).await;

    // 3 — reference age.
    check_reference_age(&mut checks);

    // 4 — solver reachability (byparr / gobrowser).
    check_solver(&mut checks, server_config.as_ref()).await;

    // 5 — chrome-render reachability (GO_BROWSER_URL).
    check_chrome_render(&mut checks).await;

    // 6 — proxy configured and reachable.
    check_proxy(&mut checks, proxy.as_deref()).await;

    let verdict = CheckStatus::aggregate(&checks.iter().map(|c| c.status).collect::<Vec<_>>());
    let report = DoctorReport { verdict, checks };

    if args.json {
        let json = serde_json::to_string_pretty(&report)
            .map_err(|e| anyhow::anyhow!("serialize doctor report: {e}"))?;
        println!("{json}");
    } else {
        emit_human(&report);
    }

    if verdict == CheckStatus::Fail {
        // A non-zero exit lets the workflow (and an operator's shell) tell
        // fail from warn/skip without parsing JSON.
        return Err(anyhow::anyhow!("doctor: one or more checks failed"));
    }
    Ok(())
}

// ── Check 1: config validity ───────────────────────────────────────────

fn check_config(checks: &mut Vec<CheckReport>) -> Option<config::ServerConfig> {
    let path = std::env::var("OX_BROWSER_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("config.toml"));
    match config::ServerConfig::load(&path) {
        Ok(cfg) => {
            checks.push(CheckReport {
                name: "config",
                status: CheckStatus::Pass,
                detail: Some(format!("loaded {}", path.display())),
                profiles: Vec::new(),
                max_age_days: None,
            });
            Some(cfg)
        }
        Err(e) => {
            checks.push(CheckReport {
                name: "config",
                status: CheckStatus::Fail,
                detail: Some(format!("load {}: {e}", path.display())),
                profiles: Vec::new(),
                max_age_days: None,
            });
            None
        }
    }
}

// ── Check 2: fingerprint against the embedded references ───────────────

/// Chrome/linux profiles deduplicated by major version — the same selection
/// the live oracle uses. The TLS/HTTP2 fingerprint is per-major, not per-OS.
fn chrome_linux_profiles() -> Vec<&'static BrowserProfile> {
    let mut seen: Vec<String> = Vec::new();
    let mut result = Vec::new();
    for p in BUILTIN_PROFILES {
        if p.browser != "chrome" || p.os != "linux" {
            continue;
        }
        let major = fingerprint::extract_major_version(p.user_agent);
        if seen.contains(&major) {
            continue;
        }
        seen.push(major);
        result.push(p);
    }
    result
}

async fn check_fingerprint(checks: &mut Vec<CheckReport>, proxy: Option<&str>, debug: bool) {
    let embedded = embedded_reference_pairs();
    let embedded_majors: Vec<String> = embedded.iter().map(|(m, _)| m.clone()).collect();
    let profiles = chrome_linux_profiles();

    let mut profile_reports: Vec<ProfileReport> = Vec::new();
    for &profile in &profiles {
        let major = fingerprint::extract_major_version(profile.user_agent);
        // Only measure profiles that have an embedded reference — a profile
        // without a reference has no ground truth and cannot be judged.
        if !embedded_majors.contains(&major) {
            continue;
        }
        let Some(reference) = fingerprint::embedded_reference(&major) else {
            continue;
        };
        let r = measure_profile(profile, &major, &reference, proxy, debug).await;
        profile_reports.push(r);
    }

    let status =
        CheckStatus::aggregate(&profile_reports.iter().map(|p| p.status).collect::<Vec<_>>());
    checks.push(CheckReport {
        name: "fingerprint",
        status,
        detail: None,
        profiles: profile_reports,
        max_age_days: None,
    });
}

/// Measure one profile against its reference. Builds the client through the
/// shared `build_http_client_for_profile` seam (the SAME `HttpClient::new`
/// path the service uses), captures from both echo endpoints, compares, and
/// classifies. Never panics — an unreachable/unparseable echo service is
/// reported as `skip`, a mismatch as `fail`.
async fn measure_profile(
    profile: &'static BrowserProfile,
    major: &str,
    reference: &Reference,
    proxy: Option<&str>,
    debug: bool,
) -> ProfileReport {
    let client =
        match build_http_client_for_profile(Some(profile), proxy.map(str::to_string), debug) {
            Ok(c) => c,
            Err(e) => {
                return ProfileReport {
                    major: major.to_string(),
                    status: CheckStatus::Skip,
                    detail: Some(format!("build client: {e}")),
                    ja4: None,
                    reference_ja4: None,
                    browser_version: Some(reference.browser_version.clone()),
                    capture_time: Some(reference.capture_time.clone()),
                    hard_failures: Vec::new(),
                    gap_closed: Vec::new(),
                    reference_age_days: None,
                };
            }
        };

    let observed = match capture(&client).await {
        Ok(o) => o,
        Err(reason) => {
            // skip: an echo service unreachable or returning something
            // unparseable is NOT drift.
            return ProfileReport {
                major: major.to_string(),
                status: CheckStatus::Skip,
                detail: Some(reason),
                ja4: None,
                reference_ja4: None,
                browser_version: Some(reference.browser_version.clone()),
                capture_time: Some(reference.capture_time.clone()),
                hard_failures: Vec::new(),
                gap_closed: Vec::new(),
                reference_age_days: None,
            };
        }
    };

    let (diffs, _skipped) = compare(&observed, reference);
    let diff_tuples: Vec<(String, String, String)> = diffs
        .iter()
        .map(|d| (d.field.clone(), d.expected.clone(), d.observed.clone()))
        .collect();
    let verdict = classify_for_reference(reference, &diff_tuples);

    let reference_age_days = capture_time_age_days(&reference.capture_time);

    if verdict.is_ok() {
        ProfileReport {
            major: major.to_string(),
            status: CheckStatus::Pass,
            detail: None,
            ja4: Some(observed.tls.ja4.clone()),
            reference_ja4: Some(reference.tls.ja4.clone()),
            browser_version: Some(reference.browser_version.clone()),
            capture_time: Some(reference.capture_time.clone()),
            hard_failures: Vec::new(),
            gap_closed: Vec::new(),
            reference_age_days,
        }
    } else {
        ProfileReport {
            major: major.to_string(),
            status: CheckStatus::Fail,
            detail: None,
            ja4: Some(observed.tls.ja4.clone()),
            reference_ja4: Some(reference.tls.ja4.clone()),
            browser_version: Some(reference.browser_version.clone()),
            capture_time: Some(reference.capture_time.clone()),
            hard_failures: verdict
                .hard_failures
                .iter()
                .map(|(f, exp, obs)| FieldReport {
                    field: f.clone(),
                    expected: exp.clone(),
                    observed: obs.clone(),
                })
                .collect(),
            gap_closed: verdict.gap_closed.clone(),
            reference_age_days,
        }
    }
}

/// Capture the observed fingerprint from both echo endpoints using a client
/// built with the given profile. Returns an error string (the skip reason)
/// on any unreachable / non-200 / unparseable / partial response — never
/// panics. Mirrors the live oracle's `capture_with_client` + `fetch_json`
/// without the test-only asserts.
async fn capture(client: &HttpClient) -> Result<fingerprint::Observed, String> {
    let peet_raw = fetch_json(client, PEET_ENDPOINT, "peet").await?;
    let peet_obs = extract_peet(&peet_raw);

    let bl_raw = fetch_json(client, BROWSERLEAKS_ENDPOINT, "browserleaks").await?;
    let bl_obs = extract_browserleaks(&bl_raw);

    let obs = merge_observed(peet_obs, bl_obs);

    // Sanity: confirm the request actually went out as h2 with a JA4, so a
    // silent downgrade (e.g. http/1.1 with no akamai fingerprint) doesn't
    // pass as "all fields matched because none were extracted". A partial
    // 200 missing these is a skip (unparseable), not a pass and not drift.
    if obs.http2_akamai_fingerprint.is_empty() {
        return Err("no HTTP/2 akamai fingerprint in merged response".to_string());
    }
    if obs.tls.ja4.is_empty() {
        return Err("no JA4 in browserleaks response".to_string());
    }
    Ok(obs)
}

/// Fetch JSON from an echo endpoint. Returns the parsed JSON on 200, or an
/// error string naming the failure class (unreachable / non-200 / unparseable)
/// — the workflow distinguishes skip from fail by the structured verdict, not
/// by grepping these strings.
async fn fetch_json(
    client: &HttpClient,
    endpoint: &str,
    label: &str,
) -> Result<serde_json::Value, String> {
    let resp = client
        .get(endpoint)
        .await
        .map_err(|e| format!("{label} endpoint unreachable: {e}"))?;
    if resp.status != 200 {
        return Err(format!(
            "{label} returned status {} (expected 200)",
            resp.status
        ));
    }
    serde_json::from_str(&resp.body).map_err(|e| format!("parse {label} response: {e}"))
}

// ── Check 3: reference age ─────────────────────────────────────────────

fn check_reference_age(checks: &mut Vec<CheckReport>) {
    let pairs = embedded_reference_pairs();
    let mut max_age: Option<i64> = None;
    for (_, r) in &pairs {
        if let Some(age) = capture_time_age_days(&r.capture_time)
            && max_age.is_none_or(|m| age > m)
        {
            max_age = Some(age);
        }
    }
    let (status, detail) = match max_age {
        Some(age) if age > REFERENCE_AGE_WARN_DAYS => (
            CheckStatus::Warn,
            Some(format!(
                "newest reference is {age} days old (>{REFERENCE_AGE_WARN_DAYS}); drift may indicate a stale reference rather than an ox-browser regression"
            )),
        ),
        Some(age) => (
            CheckStatus::Pass,
            Some(format!(
                "newest reference is {age} days old (within freshness window)"
            )),
        ),
        None => (
            CheckStatus::Skip,
            Some("no embedded reference has a parseable capture_time".to_string()),
        ),
    };
    checks.push(CheckReport {
        name: "reference_age",
        status,
        detail,
        profiles: Vec::new(),
        max_age_days: max_age,
    });
}

// ── Check 4: solver reachability (byparr / gobrowser) ──────────────────

async fn check_solver(checks: &mut Vec<CheckReport>, config: Option<&config::ServerConfig>) {
    // Priority mirrors `build_cookie_provider`: go_browser_url → byparr.
    let go_browser_url = config
        .and_then(|c| c.solver.go_browser_url.clone())
        .or_else(|| std::env::var("GO_BROWSER_URL").ok())
        .filter(|u| !u.is_empty());
    let byparr_url = config.and_then(|c| c.solver.byparr_url.clone());

    let (url, kind) = if let Some(u) = go_browser_url {
        (u, "gobrowser")
    } else if let Some(u) = byparr_url {
        (u, "byparr")
    } else {
        // No solver configured — a state an operator may have chosen
        // deliberately (no CF challenges in scope). Warn, do not fail.
        checks.push(CheckReport {
            name: "solver",
            status: CheckStatus::Warn,
            detail: Some(
                "no solver configured (GO_BROWSER_URL unset and byparr_url empty)".to_string(),
            ),
            profiles: Vec::new(),
            max_age_days: None,
        });
        return;
    };

    let (status, detail) = match probe_reachable(&url).await {
        Ok(()) => (CheckStatus::Pass, format!("{kind} at {url} reachable")),
        Err(reason) => (
            CheckStatus::Skip,
            format!("{kind} at {url} unreachable: {reason}"),
        ),
    };
    checks.push(CheckReport {
        name: "solver",
        status,
        detail: Some(detail),
        profiles: Vec::new(),
        max_age_days: None,
    });
}

// ── Check 5: chrome-render reachability (GO_BROWSER_URL) ───────────────

async fn check_chrome_render(checks: &mut Vec<CheckReport>) {
    let url = std::env::var("GO_BROWSER_URL")
        .ok()
        .filter(|u| !u.is_empty());
    let Some(url) = url else {
        // Unset — operator may not use JS-heavy render escalation. Warn.
        checks.push(CheckReport {
            name: "chrome_render",
            status: CheckStatus::Warn,
            detail: Some("GO_BROWSER_URL unset — chrome-render escalation disabled".to_string()),
            profiles: Vec::new(),
            max_age_days: None,
        });
        return;
    };
    let (status, detail) = match probe_reachable(&url).await {
        Ok(()) => (CheckStatus::Pass, format!("GO_BROWSER_URL={url} reachable")),
        Err(reason) => (
            CheckStatus::Skip,
            format!("GO_BROWSER_URL={url} unreachable: {reason}"),
        ),
    };
    checks.push(CheckReport {
        name: "chrome_render",
        status,
        detail: Some(detail),
        profiles: Vec::new(),
        max_age_days: None,
    });
}

// ── Check 6: proxy configured and reachable ────────────────────────────

async fn check_proxy(checks: &mut Vec<CheckReport>, proxy: Option<&str>) {
    if config::proxy_disabled() {
        checks.push(CheckReport {
            name: "proxy",
            status: CheckStatus::Warn,
            detail: Some("PROXY_DISABLED set — outbound proxy disabled by operator".to_string()),
            profiles: Vec::new(),
            max_age_days: None,
        });
        return;
    }
    let Some(proxy_url) = proxy else {
        // Unset — operator may run without a proxy. Warn.
        checks.push(CheckReport {
            name: "proxy",
            status: CheckStatus::Warn,
            detail: Some(
                "no proxy configured (config.toml [proxy] url unset and --proxy not given)"
                    .to_string(),
            ),
            profiles: Vec::new(),
            max_age_days: None,
        });
        return;
    };
    let (status, detail) = match probe_proxy_reachable(proxy_url).await {
        Ok(()) => (CheckStatus::Pass, format!("proxy {proxy_url} reachable")),
        Err(reason) => (
            CheckStatus::Skip,
            format!("proxy {proxy_url} unreachable: {reason}"),
        ),
    };
    checks.push(CheckReport {
        name: "proxy",
        status,
        detail: Some(detail),
        profiles: Vec::new(),
        max_age_days: None,
    });
}

// ── Reachability probes ────────────────────────────────────────────────
//
// Probes ask "does this service answer", not "does the root path exist".
// Any HTTP response — 200, 404, 500 — proves the service is up; only a
// connection failure, DNS failure, or timeout means unreachable.
//
// # Why a bare `wreq::Client`, not `HttpClient`
//
// `HttpClient::new` always wires BOTH SSRF tiers: the pre-resolve
// `ssrf_middleware` (outermost in the chain, `client.rs:103`) and the
// connect-time `SsrfGuardedResolver` + `ssrf_redirect_policy` baked into
// the wreq client (`client.rs:317-321`). That is correct for user-supplied
// URLs — the entire request path (`/fetch`, `/read`, MCP tools) goes
// through `HttpClient` and must never reach a private address.
//
// But the endpoints probed here (`GO_BROWSER_URL`, `solver.byparr_url`,
// the configured proxy) come from OUR OWN configuration, not from a
// fetched page or an API caller. They live on a private Docker network by
// design (e.g. `go-wowa` → `172.19.0.14`). A probe that carries the SSRF
// guard reports a healthy dependency as down — a diagnostic worse than no
// diagnostic.
//
// The distinguishing property is **provenance**: a URL we configured is not
// attacker-supplied. The relaxation is enforced by **code locality**: the
// unguarded client is built inline in these three probe functions only.
// `HttpClient::new` (the request-path entry point) is unchanged and still
// mandates both SSRF tiers for every other caller. There is no shared
// constructor, no config flag, and no `HttpConfig` field that the request
// path could accidentally pick up — the bare `wreq::Client` is constructed
// with `wreq::Client::builder()` directly, bypassing `wreq_transport_core`
// (which always installs the guarded resolver).

/// Probe an endpoint. Returns `Ok(())` if the service answered with any HTTP
/// response (any status code), or `Err(reason)` with what was actually
/// observed — a connection error, a timeout, a DNS failure — never a
/// conclusion like "unreachable" that was not measured.
async fn probe_reachable(url: &str) -> Result<(), String> {
    let client = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        // Clear wreq's `auto_sys_proxy` default so an ambient `HTTP_PROXY`
        // cannot reroute a probe to our own sidecar through an unrelated
        // proxy (mirrors the invariant in `client.rs` `build_wreq_client`).
        .no_proxy()
        .build()
        .map_err(|e| format!("build probe client: {e}"))?;
    match client.get(url).send().await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{e}")),
    }
}

/// Probe the proxy by routing a lightweight fetch through it. Returns
/// `Ok(())` if any HTTP response came back (the proxy is up and forwarding),
/// or `Err(reason)` with the observed error.
async fn probe_proxy_reachable(proxy_url: &str) -> Result<(), String> {
    let proxy = wreq::Proxy::all(proxy_url).map_err(|e| format!("parse proxy URL: {e}"))?;
    let client = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .proxy(proxy)
        .build()
        .map_err(|e| format!("build probe client: {e}"))?;
    match client.get("https://example.com").send().await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{e}")),
    }
}

// ── Date helpers (no chrono dep — self-contained civil-days calc) ───────

/// Days from 1970-01-01 for a (y, m, d) civil date (Howard Hinnant's
/// `days_from_civil`). Returns `None` on a parse failure.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse an ISO-8601 `capture_time` (`YYYY-MM-DDTHH:MM:SS(.frac)?Z`) into
/// days since 1970-01-01. Only the date part is used — age-in-days does not
/// need sub-day precision.
fn capture_time_to_epoch_days(s: &str) -> Option<i64> {
    let date_part = s.trim().split('T').next()?;
    let mut parts = date_part.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    Some(days_from_civil(y, m, d))
}

/// Age of a capture_time in days relative to now. `None` if unparseable.
fn capture_time_age_days(capture_time: &str) -> Option<i64> {
    let capture_days = capture_time_to_epoch_days(capture_time)?;
    let now_days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86400) as i64)
        .ok()?;
    Some(now_days - capture_days)
}

// ── Human-readable output ──────────────────────────────────────────────

fn emit_human(report: &DoctorReport) {
    eprintln!(
        "ox-browser doctor — verdict: {}",
        status_word(report.verdict)
    );
    eprintln!();
    for check in &report.checks {
        eprintln!("[{}] {}", status_word(check.status), check.name);
        if let Some(detail) = &check.detail {
            eprintln!("    {detail}");
        }
        for p in &check.profiles {
            eprintln!("    Chrome {}: {}", p.major, status_word(p.status));
            if let Some(d) = &p.detail {
                eprintln!("        {d}");
            }
            if let Some(age) = p.reference_age_days {
                eprintln!("        reference age: {age} days");
            }
            for f in &p.hard_failures {
                eprintln!(
                    "        FIELD {}\n            expected: {}\n            observed: {}",
                    f.field, f.expected, f.observed
                );
            }
            for g in &p.gap_closed {
                eprintln!("        GAP-CLOSED {g}");
            }
        }
    }
    // The verdict line on stdout so a human can still pipe it.
    println!("{}", status_word(report.verdict));
}

fn status_word(s: CheckStatus) -> &'static str {
    match s {
        CheckStatus::Pass => "pass",
        CheckStatus::Warn => "warn",
        CheckStatus::Skip => "skip",
        CheckStatus::Fail => "fail",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_fail_dominates() {
        assert_eq!(
            CheckStatus::aggregate(&[CheckStatus::Pass, CheckStatus::Warn, CheckStatus::Fail]),
            CheckStatus::Fail
        );
    }

    #[test]
    fn aggregate_warn_over_skip() {
        assert_eq!(
            CheckStatus::aggregate(&[CheckStatus::Pass, CheckStatus::Skip, CheckStatus::Warn]),
            CheckStatus::Warn
        );
    }

    #[test]
    fn aggregate_skip_over_pass() {
        assert_eq!(
            CheckStatus::aggregate(&[CheckStatus::Pass, CheckStatus::Skip, CheckStatus::Pass]),
            CheckStatus::Skip
        );
    }

    #[test]
    fn aggregate_all_pass() {
        assert_eq!(
            CheckStatus::aggregate(&[CheckStatus::Pass, CheckStatus::Pass]),
            CheckStatus::Pass
        );
    }

    #[test]
    fn days_from_civil_epoch() {
        // 1970-01-01 → 0
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        // 2000-01-01 → 10957 (a well-known anchor).
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
        // 2026-07-28 — the Chrome 148 reference capture day. Computed by the
        // same algorithm the workflow's python used to derive age_days.
        assert_eq!(days_from_civil(2026, 7, 28), 20662);
    }

    #[test]
    fn capture_time_parse_handles_z_and_fraction() {
        // The Chrome 148 reference uses this exact shape.
        assert_eq!(
            capture_time_to_epoch_days("2026-07-28T07:00:13.684930Z"),
            Some(20662)
        );
        // No fraction, no Z — still parses the date part.
        assert_eq!(
            capture_time_to_epoch_days("2026-07-28T07:00:13"),
            Some(20662)
        );
    }

    #[test]
    fn capture_time_parse_rejects_garbage() {
        assert_eq!(capture_time_to_epoch_days("not a date"), None);
        assert_eq!(capture_time_to_epoch_days(""), None);
    }

    #[test]
    fn reference_age_warn_threshold_is_90() {
        assert_eq!(REFERENCE_AGE_WARN_DAYS, 90);
    }

    #[test]
    fn embedded_references_are_present_and_parse() {
        // doctor cannot function without embedded references — the whole
        // point of issue #109 is that the shipped binary carries the ground
        // truth. If this is empty, doctor silently measures nothing.
        let pairs = embedded_reference_pairs();
        assert!(
            !pairs.is_empty(),
            "no embedded references — doctor has no ground truth"
        );
        for (major, r) in &pairs {
            assert!(!major.is_empty());
            assert_eq!(r.major, *major, "embedded reference major field mismatch");
            assert!(
                !r.tls.ja4.is_empty(),
                "embedded reference {major} has no ja4"
            );
            assert!(
                !r.capture_time.is_empty(),
                "embedded reference {major} has no capture_time"
            );
        }
    }

    #[test]
    fn measured_majors_are_the_intersection_of_shipped_and_referenced() {
        // doctor measures a Chrome major ONLY when it has BOTH a builtin
        // Chrome/linux profile (what ships) AND an embedded reference (ground
        // truth). References for 131/133/144/146 are kept for the offline F3
        // comparability tests but ox-browser ships only Chrome 148, so doctor
        // measures exactly {148}. A reference without a shipped profile is
        // not stale — it is exercised by the offline tests, not by doctor.
        let profiles = chrome_linux_profiles();
        let profile_majors: Vec<String> = profiles
            .iter()
            .map(|p| fingerprint::extract_major_version(p.user_agent))
            .collect();
        let embedded_majors: Vec<String> = embedded_reference_pairs()
            .iter()
            .map(|(m, _)| m.clone())
            .collect();
        let measured: Vec<String> = embedded_majors
            .iter()
            .filter(|m| profile_majors.contains(m))
            .cloned()
            .collect();
        assert!(
            measured.contains(&"148".to_string()),
            "Chrome 148 must be measured (it ships and has a reference): measured={measured:?}"
        );
        // 131 has a reference but no shipped profile — it must NOT be measured.
        assert!(
            !measured.contains(&"131".to_string()),
            "Chrome 131 has no shipped profile — doctor must not measure it"
        );
    }

    // ── Probe reachability tests ──────────────────────────────────────
    //
    // These exercise the fix for the 0.8.5 false-negative: probes must
    // reach private addresses (our own configured services on a Docker
    // network) while the user-facing request path must NOT.

    /// A probe against a private address (127.0.0.1 = loopback) succeeds
    /// when the endpoint answers — even with a 404. This is exactly the
    /// blocked case: the SSRF guard would refuse 127.0.0.1, but the probe
    /// bypasses it because the URL's provenance is our own config.
    #[tokio::test]
    async fn probe_reachable_succeeds_for_private_address_that_answers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/");

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = sock.read(&mut [0u8; 1024]).await;
            sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let result = probe_reachable(&url).await;
        assert!(
            result.is_ok(),
            "probe to a private address that answers must succeed, got: {result:?}"
        );
    }

    /// A probe against a closed port reports unreachable with an observed
    /// error string (connection refused), not a bare "unreachable".
    #[tokio::test]
    async fn probe_reachable_reports_unreachable_for_closed_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = format!("http://127.0.0.1:{port}/");

        let result = probe_reachable(&url).await;
        assert!(
            result.is_err(),
            "probe to a closed port must report unreachable"
        );
        // The error must describe what was observed, not just "unreachable".
        let reason = result.unwrap_err();
        assert!(!reason.is_empty(), "error reason must not be empty");
    }

    /// THE load-bearing test: a user-facing fetch of a private address is
    /// still blocked by the SSRF guard. Proves the relaxation was scoped to
    /// probes only — `HttpClient::new` (the request-path entry point) is
    /// unchanged and still mandates both SSRF tiers.
    #[tokio::test]
    async fn user_facing_fetch_of_private_address_is_still_blocked() {
        let client = HttpClient::new(ox_http::HttpConfig {
            timeout: std::time::Duration::from_secs(5),
            ..ox_http::HttpConfig::default()
        })
        .expect("build HttpClient with default config");

        let result = client.get("http://127.0.0.1:1/").await;
        assert!(
            result.is_err(),
            "user-facing fetch of a private address must be blocked"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("SSRF blocked"),
            "error must say SSRF blocked, got: {msg}"
        );
    }
}
