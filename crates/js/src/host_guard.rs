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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// `Host` names and addresses always admitted, on any port.
pub const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

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

fn is_loopback(host: &HostKey) -> bool {
    match host {
        HostKey::Ip(ip) => {
            *ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || *ip == IpAddr::V6(Ipv6Addr::LOCALHOST)
        }
        HostKey::Name(n) => n == "localhost",
    }
}

/// The effective `Host` allowlist: loopback plus operator-supplied entries.
#[derive(Debug, Clone, Default)]
pub struct HostAllowlist {
    extra: Vec<(String, Authority)>,
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
        Self { extra: out }
    }

    /// Operator entries as written (loopback is implicit).
    pub fn extra_entries(&self) -> Vec<&str> {
        self.extra.iter().map(|(raw, _)| raw.as_str()).collect()
    }

    /// Log the effective allowlist once at startup: WARN when only loopback
    /// is admitted (callers on another address are rejected), INFO otherwise.
    pub fn log_effective(&self) {
        let extra = self.extra_entries();
        if extra.is_empty() {
            tracing::warn!(
                allowed = %LOOPBACK_HOSTS.join(","),
                "Host allowlist is loopback only: requests addressed to any other Host get 403; \
                 set OX_ALLOWED_HOSTS for callers that reach this service by name or address"
            );
        } else {
            tracing::info!(
                allowed = %format!("{},{}", LOOPBACK_HOSTS.join(","), extra.join(",")),
                "Host allowlist"
            );
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

/// axum middleware: `from_fn_with_state(Arc<HostAllowlist>, host_guard::middleware)`.
pub async fn middleware(
    State(allow): State<Arc<HostAllowlist>>,
    req: Request,
    next: Next,
) -> Response {
    if allow.admits_request(&req) {
        return next.run(req).await;
    }
    let route = crate::inbound_auth::route_class(req.uri().path());
    ox_http::metrics::record_host_rejected(route);
    tracing::debug!(route, "host_guard: rejected request with a disallowed Host");
    (StatusCode::FORBIDDEN, "forbidden: Host not allowed").into_response()
}

/// Wrap `router` with the guard. Like `inbound_auth::protect` it wraps the
/// whole router service, so it also covers unmatched paths and merged routers.
pub fn protect_hosts(router: axum::Router, allow: HostAllowlist) -> axum::Router {
    router.layer(axum::middleware::from_fn_with_state(
        Arc::new(allow),
        middleware,
    ))
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
        let a = list(&["Mesh.Test", "pinned.test:8901", "192.0.2.7:8901", "::1", " "]);
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
}
