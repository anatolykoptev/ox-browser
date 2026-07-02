//! Connect-time + redirect-hop SSRF guard for wreq clients.
//!
//! The pre-resolve tier ([`crate::middleware_ssrf`]) validates the initial
//! request URL before it enters the middleware chain, but it cannot see:
//!
//!  1. A redirect — wreq follows redirects INSIDE `Client::execute`,
//!     invisible to our `Handler` chain, so a `302 Location:
//!     http://169.254.169.254/` sails straight through unless each hop is
//!     re-checked.
//!  2. A DNS-rebind — the pre-resolve check does its OWN `to_socket_addrs()`
//!     lookup; wreq's terminal handler does a SEPARATE lookup at actual
//!     connect time. An attacker's authoritative DNS server can return a
//!     public IP for lookup #1 and a private IP for lookup #2.
//!
//! This module closes both gaps using two wreq extension points:
//!
//!  - [`SsrfGuardedResolver`] implements `wreq::dns::Resolve` and is wired
//!    via `ClientBuilder::dns_resolver`. It performs the SAME DNS
//!    resolution wreq is about to dial and filters blocked IPs out of the
//!    result — the check runs on the literal address about to be
//!    connect()'d, with zero window between resolve and dial. This is the
//!    wreq-idiomatic equivalent of `go-kit/httputil.GuardedDialContext`'s
//!    `net.Dialer.Control` hook, which checks the ALREADY-RESOLVED address
//!    immediately before the `connect(2)` syscall: wreq's `HttpConnector`
//!    hands the resolver's returned addresses directly to
//!    `ConnectingTcp::connect()` with no further resolution step in
//!    between (see `wreq::client::conn::http::HttpConnector::call_async`),
//!    so filtering here has the identical rebind-defeating property.
//!
//!    Every redirect hop that targets a HOSTNAME goes through this same
//!    resolver — a redirect to a new host requires a new connection, which
//!    requires a fresh resolve — so hostname-based redirect targets are
//!    covered by this alone, no extra wiring needed.
//!
//!  - [`ssrf_redirect_policy`] closes the ONE gap the resolver cannot: a
//!    redirect target that is already a literal IP
//!    (`302 Location: http://169.254.169.254/...`). wreq's `HttpConnector`
//!    special-cases this: "if the host is already an IP addr, skip
//!    resolving the dns and start connecting right away" — so a literal-IP
//!    hop NEVER calls the resolver at all, regardless of which `Resolve`
//!    impl is wired in. A custom `redirect::Policy` sees the hop's URI
//!    directly (no I/O needed for a literal IP) and can refuse it
//!    synchronously before wreq ever attempts to connect.
//!
//! Both share [`crate::middleware_ssrf::is_private_ip`] — one block
//! predicate for the whole crate, so there is exactly one place that
//! defines "blocked".

use std::net::{IpAddr, SocketAddr};

use wreq::dns::{Addrs, Name, Resolve, Resolving};
use wreq::redirect::{Action, Attempt, Policy};

use crate::middleware_ssrf::{is_allowlisted, is_private_ip};

/// Error returned when a connect-time or redirect-hop check refuses a
/// target. Wraps every rejection from this module, mirroring
/// `go-kit/httputil.ErrSSRFBlocked`.
#[derive(Debug, thiserror::Error)]
#[error("SSRF blocked: {0}")]
pub struct SsrfBlockedError(pub String);

/// A `wreq::dns::Resolve` that filters DNS resolution results, refusing to
/// hand back any address [`is_private_ip`] blocks. See the module doc for
/// why this is the connect-time, rebind-resistant tier.
#[derive(Debug, Clone, Copy, Default)]
pub struct SsrfGuardedResolver;

impl Resolve for SsrfGuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| SsrfBlockedError(format!("resolve {host}: {e}")))?
                .collect();
            let allowed = filter_allowed(resolved.into_iter());
            if allowed.is_empty() {
                return Err(SsrfBlockedError(format!(
                    "{host} resolved to no allowed addresses (all candidates blocked)"
                ))
                .into());
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

/// Filters `addrs`, dropping every [`is_private_ip`]-blocked address.
/// Pure function, split out for direct unit testing without real DNS I/O —
/// this is what makes the resolver's rebind-defeating behavior verifiable
/// without needing an actual DNS-rebind race in the test.
fn filter_allowed(addrs: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    addrs.filter(|a| !is_private_ip(&a.ip())).collect()
}

/// Redirect policy that enforces a max-hop count (mirrors
/// `wreq::redirect::Policy::limited`) AND refuses a hop whose target is
/// already a literal IP that [`is_private_ip`] blocks. See the module doc
/// for why literal-IP hops need this separate check (they never reach
/// [`SsrfGuardedResolver`] — wreq's connector skips DNS resolution
/// entirely for a host that already parses as an IP).
///
/// Hostname-based hops are NOT re-checked here — they are covered by
/// [`SsrfGuardedResolver`] at actual connect time, which is the stronger,
/// rebind-resistant guarantee. Duplicating a pre-resolve check here would
/// only add a second, WEAKER window.
pub fn ssrf_redirect_policy(max_redirects: usize) -> Policy {
    Policy::custom(move |attempt: Attempt<'_>| -> Action {
        if attempt.previous.len() > max_redirects {
            return attempt.error(SsrfBlockedError("too many redirects".into()));
        }

        let Some(host) = attempt.uri.host() else {
            return attempt.follow();
        };

        // Defensive: strip brackets if present (IPv6 literal authority).
        let bare_host = host.trim_start_matches('[').trim_end_matches(']');

        if let Ok(ip) = bare_host.parse::<IpAddr>() {
            let port = attempt.uri.port_u16().unwrap_or_else(|| {
                if attempt.uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                }
            });
            if is_allowlisted(bare_host, port) {
                return attempt.follow();
            }
            if is_private_ip(&ip) {
                return attempt.error(SsrfBlockedError(format!(
                    "redirect hop refused: {ip} is a private/reserved address"
                )));
            }
        }

        attempt.follow()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn filter_allowed_drops_private_keeps_public() {
        let addrs = vec![
            SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 443)),
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 80)),
            SocketAddr::from((Ipv4Addr::new(169, 254, 169, 254), 80)),
            SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443)),
        ];
        let allowed = filter_allowed(addrs.into_iter());
        assert_eq!(allowed.len(), 2);
        assert!(allowed.iter().all(|a| !is_private_ip(&a.ip())));
    }

    #[test]
    fn filter_allowed_rebind_scenario_drops_the_private_answer() {
        // Simulates a DNS-rebind response set: the SAME lookup returning
        // both a public decoy and the real (private) target. A resolver
        // that trusted the FIRST answer would be rebind-vulnerable; this
        // asserts the filter drops every private candidate regardless of
        // position in the result set.
        let addrs = vec![
            SocketAddr::from((Ipv4Addr::new(93, 184, 215, 14), 443)),
            SocketAddr::from((Ipv4Addr::new(169, 254, 169, 254), 80)),
        ];
        let allowed = filter_allowed(addrs.into_iter());
        assert_eq!(
            allowed,
            vec![SocketAddr::from((Ipv4Addr::new(93, 184, 215, 14), 443))]
        );
    }

    #[test]
    fn filter_allowed_all_blocked_is_empty() {
        let addrs = vec![
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 80)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 80)),
        ];
        assert!(filter_allowed(addrs.into_iter()).is_empty());
    }

    #[tokio::test]
    async fn resolver_rejects_localhost() {
        // Real DNS resolution (via tokio::net::lookup_host) for a hostname
        // that resolves only to loopback addresses on essentially every
        // system. Exercises the actual resolve() path end-to-end, not just
        // the pure filter helper above.
        let resolver = SsrfGuardedResolver;
        let result = resolver.resolve(Name::from("localhost")).await;
        assert!(
            result.is_err(),
            "localhost resolves only to loopback addresses and must be refused"
        );
    }

    #[tokio::test]
    async fn resolver_allows_a_real_public_host() {
        let resolver = SsrfGuardedResolver;
        let result = resolver.resolve(Name::from("one.one.one.one")).await;
        match result {
            Ok(mut addrs) => assert!(addrs.next().is_some(), "expected at least one address"),
            Err(e) => panic!("expected a well-known public host to resolve, got: {e}"),
        }
    }
}
