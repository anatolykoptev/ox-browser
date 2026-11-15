//! `Host` allowlist for every route (DNS-rebinding guard, RUSTSEC-2026-0189).
//!
//! A web page the operator visits can point its own domain at this service's
//! address and drive it from the browser; the browser then sends that domain
//! as `Host`. One middleware wraps the whole served router (`serve.rs`
//! `build_app`), so REST routes, `/mcp`, `/health`, `/metrics` and unmatched
//! paths all answer 403 to a foreign `Host` before auth or any handler runs.
//!
//! Matching rules:
//! - loopback (`localhost`, `127.0.0.1`, `::1`) is always admitted on any port;
//! - operator entries are ADDED to loopback, never substituted for it. An empty
//!   list therefore means loopback only (fail closed), never "allow all";
//! - an entry without a port admits that host on any port, an entry with a
//!   port admits exactly that port (a `Host` with no port does not match it:
//!   list the bare name as well for default-port callers);
//! - names compare case-insensitively, a trailing dot is ignored, IP literals
//!   compare as addresses (`[0:0:0:0:0:0:0:1]` is `::1`), IPv6 uses brackets;
//! - a missing, repeated, non-ASCII or unparsable `Host` is 403. HTTP/2
//!   `:authority` reaches us as the request-URI authority and is checked too;
//!   when both are present, both must be admitted;
//! - no wildcards: an entry that is not a plain host or `host:port` is dropped
//!   at startup with a warning.
//!
//! `OX_HOST_GUARD_MODE=report` is the rollout aid: a disallowed `Host` is
//! counted and logged (first sighting per distinct value, capped, never in a
//! metric label) but the request is let through. Default and any other value:
//! enforce.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, LazyLock, Mutex};

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// `Host` names and addresses always admitted, on any port. The single source
/// for [`is_loopback`] and the startup log.
pub const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// Body of the 403 this guard answers with; tests use it to tell a guard
/// rejection from a handler's or the auth gate's own 403.
pub const REJECTION_BODY: &str = "forbidden: Host not allowed";

/// Env var selecting [`Mode`].
pub const MODE_ENV: &str = "OX_HOST_GUARD_MODE";

/// Most distinct rejected `Host` values logged individually; after that one
/// "cap reached" line is logged and the counter keeps counting.
const MAX_LOGGED_HOSTS: usize = 64;

/// Longest rejected `Host` value kept for a log line.
const MAX_LOGGED_HOST_LEN: usize = 80;

/// What the guard does with a disallowed `Host`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Answer 403 (default; any unknown value also enforces).
    #[default]
    Enforce,
    /// Rollout aid: count and log the disallowed `Host`, then let the
    /// request through.
    Report,
}

impl Mode {
    /// Parse the raw env value; only `report` (any case) selects report mode.
    pub fn from_env_value(raw: Option<&str>) -> Self {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("report") => Self::Report,
            _ => Self::Enforce,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Report => "report",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostKey {
    Ip(IpAddr),
    Name(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Authority {
    host: HostKey,
    port: Option<u16>,
}

fn parse_port(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Parse `host`, `host:port`, `[v6]` or `[v6]:port`. Bare IPv6 is rejected
/// here (a `Host` header must bracket it); [`parse_entry`] is more lenient.
fn parse_authority(raw: &str) -> Option<Authority> {
    if raw.is_empty() {
        return None;
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        let ip: Ipv6Addr = inner.parse().ok()?;
        let port = if after.is_empty() {
            None
        } else {
            Some(parse_port(after.strip_prefix(':')?)?)
        };
        return Some(Authority {
            host: HostKey::Ip(IpAddr::V6(ip)),
            port,
        });
    }
    let (host, port) = match raw.rsplit_once(':') {
        Some((h, p)) => (h, Some(parse_port(p)?)),
        None => (raw, None),
    };
    let host = if let Ok(v4) = host.parse::<Ipv4Addr>() {
        HostKey::Ip(IpAddr::V4(v4))
    } else {
        let name = host.strip_suffix('.').unwrap_or(host);
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if !valid {
            return None;
        }
        HostKey::Name(name.to_ascii_lowercase())
    };
    Some(Authority { host, port })
}

/// An operator entry: [`parse_authority`] plus a bare IPv6 literal (`::1`).
fn parse_entry(raw: &str) -> Option<Authority> {
    if let Ok(v6) = raw.parse::<Ipv6Addr>() {
        return Some(Authority {
            host: HostKey::Ip(IpAddr::V6(v6)),
            port: None,
        });
    }
    parse_authority(raw)
}

static LOOPBACK: LazyLock<Vec<HostKey>> = LazyLock::new(|| {
    LOOPBACK_HOSTS
        .iter()
        .map(|h| parse_entry(h).expect("LOOPBACK_HOSTS entry parses").host)
        .collect()
});

fn is_loopback(host: &HostKey) -> bool {
    LOOPBACK.contains(host)
}

/// The effective `Host` allowlist: loopback plus operator-supplied entries.
#[derive(Debug, Clone, Default)]
pub struct HostAllowlist {
    extra: Vec<(String, Authority)>,
    mode: Mode,
}

impl HostAllowlist {
    /// Build from operator entries. Blank entries are ignored; entries that
    /// are not a plain `host` / `host:port` are dropped with a warning.
    pub fn new(extra: &[String]) -> Self {
        let mut out: Vec<(String, Authority)> = Vec::new();
        for raw in extra {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            match parse_entry(raw) {
                Some(a) => out.push((raw.to_owned(), a)),
                None => tracing::warn!(
                    entry = raw,
                    "Host allowlist: ignoring entry that is not a plain host or host:port"
                ),
            }
        }
        Self {
            extra: out,
            mode: Mode::Enforce,
        }
    }

    /// The same allowlist with `mode` (default [`Mode::Enforce`]).
    #[must_use]
    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// The configured mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Operator entries as written (loopback is implicit).
    pub fn extra_entries(&self) -> Vec<&str> {
        self.extra.iter().map(|(raw, _)| raw.as_str()).collect()
    }

    /// Log the effective allowlist and mode once at startup: WARN when only
    /// loopback is admitted or the guard is in report mode (it is not
    /// protecting yet), INFO otherwise.
    pub fn log_effective(&self) {
        let extra = self.extra_entries();
        let allowed = if extra.is_empty() {
            LOOPBACK_HOSTS.join(",")
        } else {
            format!("{},{}", LOOPBACK_HOSTS.join(","), extra.join(","))
        };
        let mode = self.mode.as_str();
        if self.mode == Mode::Report {
            tracing::warn!(
                allowed = %allowed, mode,
                "Host guard is in REPORT mode: disallowed Hosts are logged and counted but \
                 NOT rejected; set OX_HOST_GUARD_MODE=enforce once the log is clean"
            );
        } else if extra.is_empty() {
            tracing::warn!(
                allowed = %allowed, mode,
                "Host allowlist is loopback only: requests addressed to any other Host get 403; \
                 set OX_ALLOWED_HOSTS for callers that reach this service by name or address"
            );
        } else {
            tracing::info!(allowed = %allowed, mode, "Host allowlist");
        }
    }

    fn admits(&self, a: &Authority) -> bool {
        is_loopback(&a.host)
            || self
                .extra
                .iter()
                .any(|(_, e)| e.host == a.host && (e.port.is_none() || e.port == a.port))
    }

    /// Whether a raw `Host` / authority value is admitted.
    pub fn admits_raw(&self, raw: &str) -> bool {
        parse_authority(raw).is_some_and(|a| self.admits(&a))
    }

    /// Whether the request addresses an admitted host: the `Host` header (at
    /// most one) and the request-URI authority (HTTP/2 `:authority`,
    /// absolute-form) must each be admitted when present, and at least one
    /// must be present.
    fn admits_request(&self, req: &Request) -> bool {
        let mut hosts = req.headers().get_all(header::HOST).iter();
        let header_val = hosts.next();
        if hosts.next().is_some() {
            return false;
        }
        let mut seen = false;
        if let Some(v) = header_val {
            seen = true;
            if !v.to_str().is_ok_and(|s| self.admits_raw(s)) {
                return false;
            }
        }
        if let Some(a) = req.uri().authority() {
            seen = true;
            if !self.admits_raw(a.as_str()) {
                return false;
            }
        }
        seen
    }
}

/// Distinct rejected `Host` values seen so far, bounded so a flood of random
/// names cannot grow memory or the log.
#[derive(Debug, Default)]
struct Sightings {
    seen: Mutex<HashSet<String>>,
}

#[derive(Debug, PartialEq, Eq)]
enum Sighting {
    /// First time this value is seen: log it.
    New,
    /// The cap was just reached by this value: log once that logging stops.
    CapReached,
    /// Already logged, or past the cap.
    Quiet,
}

impl Sightings {
    fn note(&self, host: &str) -> Sighting {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.len() > MAX_LOGGED_HOSTS {
            return Sighting::Quiet;
        }
        if seen.contains(host) {
            return Sighting::Quiet;
        }
        if seen.len() == MAX_LOGGED_HOSTS {
            // Sentinel keeps the "cap reached" line to one.
            seen.insert("\0cap".to_owned());
            return Sighting::CapReached;
        }
        seen.insert(host.to_owned());
        Sighting::New
    }
}

/// The `Host` value(s) of a request for a log line: escaped and truncated
/// (it is attacker-controlled), `<missing>` / `<repeated>` for the odd shapes.
fn describe_host(req: &Request) -> String {
    let mut it = req.headers().get_all(header::HOST).iter();
    let raw = match (it.next(), it.next()) {
        (Some(_), Some(_)) => "<repeated>".to_owned(),
        (Some(v), None) => v
            .to_str()
            .map_or_else(|_| "<non-ascii>".to_owned(), str::to_owned),
        (None, _) => req
            .uri()
            .authority()
            .map_or_else(|| "<missing>".to_owned(), |a| a.as_str().to_owned()),
    };
    raw.chars()
        .take(MAX_LOGGED_HOST_LEN)
        .flat_map(char::escape_debug)
        .collect::<String>()
        .to_ascii_lowercase()
}

#[derive(Debug)]
struct Guard {
    allow: HostAllowlist,
    sightings: Sightings,
}

/// axum middleware: `from_fn_with_state(Arc<Guard>, host_guard::middleware)`
/// (built by [`protect_hosts`]).
async fn middleware(State(guard): State<Arc<Guard>>, req: Request, next: Next) -> Response {
    if guard.allow.admits_request(&req) {
        return next.run(req).await;
    }
    let route = crate::inbound_auth::route_class(req.uri().path());
    ox_http::metrics::record_host_rejected(route);
    let mode = guard.allow.mode.as_str();
    let shown = describe_host(&req);
    match guard.sightings.note(&shown) {
        Sighting::New => tracing::warn!(
            host = %shown, route, mode,
            "host_guard: disallowed Host (first sighting; add it to OX_ALLOWED_HOSTS if it is a real caller)"
        ),
        Sighting::CapReached => tracing::warn!(
            mode,
            "host_guard: {MAX_LOGGED_HOSTS} distinct disallowed Hosts logged; further ones are only counted"
        ),
        Sighting::Quiet => {}
    }
    if guard.allow.mode == Mode::Report {
        return next.run(req).await;
    }
    (StatusCode::FORBIDDEN, REJECTION_BODY).into_response()
}

/// Wrap `router` with the guard. Like `inbound_auth::protect` it wraps the
/// whole router service, so it also covers unmatched paths and merged routers.
pub fn protect_hosts(router: axum::Router, allow: HostAllowlist) -> axum::Router {
    let guard = Arc::new(Guard {
        allow,
        sightings: Sightings::default(),
    });
    router.layer(axum::middleware::from_fn_with_state(guard, middleware))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(extra: &[&str]) -> HostAllowlist {
        HostAllowlist::new(&extra.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn loopback_any_port_and_nothing_else_by_default() {
        let a = list(&[]);
        for ok in [
            "localhost",
            "localhost:8901",
            "127.0.0.1",
            "127.0.0.1:1",
            "[::1]",
            "[::1]:8901",
            "[0:0:0:0:0:0:0:1]:80",
            "LOCALHOST:8901",
            "localhost.",
        ] {
            assert!(a.admits_raw(ok), "{ok}");
        }
        for bad in [
            "",
            "attacker.test",
            "attacker.test:8901",
            "127.0.0.2",
            "127.1",
            "0.0.0.0",
            "::1",
            "[::1",
            "[::1]x",
            "localhost:",
            "localhost:99999",
            "localhost:80:80",
            "user@localhost",
            "localhost/",
            "local host",
            "[::2]",
        ] {
            assert!(!a.admits_raw(bad), "{bad:?}");
        }
    }

    #[test]
    fn extras_are_added_case_insensitive_and_port_aware() {
        let a = list(&[
            "Mesh.Test",
            "pinned.test:8901",
            "192.0.2.7:8901",
            "::1",
            " ",
        ]);
        assert!(a.admits_raw("mesh.test"));
        assert!(a.admits_raw("MESH.TEST:1234"));
        assert!(a.admits_raw("pinned.test:8901"));
        assert!(a.admits_raw("PINNED.test:8901"));
        assert!(!a.admits_raw("pinned.test:9999"));
        assert!(!a.admits_raw("pinned.test"));
        assert!(a.admits_raw("192.0.2.7:8901"));
        assert!(!a.admits_raw("192.0.2.7"));
        assert!(a.admits_raw("localhost"));
        assert!(!a.admits_raw("other.test"));
        assert_eq!(a.extra_entries().len(), 4);
    }

    #[test]
    fn unparsable_entries_are_dropped_not_wildcards() {
        let a = list(&["*", "*.test", "a b", "http://x.test", "x.test:notaport"]);
        assert!(a.extra_entries().is_empty());
        assert!(!a.admits_raw("anything.test"));
    }

    #[test]
    fn every_loopback_host_is_admitted_on_any_port() {
        let a = list(&[]);
        for h in LOOPBACK_HOSTS {
            let bracketed = if h.contains(':') {
                format!("[{h}]")
            } else {
                h.to_owned()
            };
            for form in [bracketed.clone(), format!("{bracketed}:8901")] {
                assert!(a.admits_raw(&form), "{form}");
            }
        }
        assert_eq!(LOOPBACK.len(), LOOPBACK_HOSTS.len());
    }

    #[test]
    fn mode_defaults_to_enforce_and_only_report_relaxes() {
        assert_eq!(Mode::from_env_value(None), Mode::Enforce);
        assert_eq!(Mode::from_env_value(Some("")), Mode::Enforce);
        assert_eq!(Mode::from_env_value(Some("enforce")), Mode::Enforce);
        assert_eq!(Mode::from_env_value(Some("reprot")), Mode::Enforce);
        assert_eq!(Mode::from_env_value(Some(" Report ")), Mode::Report);
        assert_eq!(HostAllowlist::default().mode(), Mode::Enforce);
    }

    #[test]
    fn sightings_log_each_value_once_and_stop_at_the_cap() {
        let s = Sightings::default();
        assert_eq!(s.note("a.test"), Sighting::New);
        assert_eq!(s.note("a.test"), Sighting::Quiet);
        for i in 1..MAX_LOGGED_HOSTS {
            assert_eq!(s.note(&format!("h{i}.test")), Sighting::New, "{i}");
        }
        assert_eq!(s.note("over.test"), Sighting::CapReached);
        assert_eq!(s.note("over2.test"), Sighting::Quiet);
        assert_eq!(s.note("over.test"), Sighting::Quiet);
        assert_eq!(s.note("a.test"), Sighting::Quiet);
    }
}
