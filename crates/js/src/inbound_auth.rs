//! Inbound authentication for ox-browser's HTTP surface (REST + MCP).
//!
//! One axum middleware wraps the whole merged router (`serve.rs`), so it runs
//! for every route — REST, `/mcp`, `/metrics` and any path added later — and
//! for unmatched paths. A request is authenticated by EITHER credential:
//!
//! - `X-Internal-Secret: $INTERNAL_SERVICE_SECRET` — fleet service-to-service;
//! - `Authorization: Bearer $OX_MCP_TOKEN` — MCP clients.
//!
//! Only `GET`/`HEAD /health` is exempt.
//!
//! Modes (`OX_AUTH_MODE`):
//! - `enforce` (default; unknown values also enforce): no valid credential → 401;
//! - `soft` (rollout aid): a request with NO usable credential is allowed,
//!   counted and logged once per caller, so callers can be found before the
//!   flip. A credential that is wrong — or sent with an empty value — is 401
//!   in both modes.
//!
//! Fail closed: with neither credential configured every non-health request is
//! 401, in either mode. `OX_AUTH_ALLOW_INSECURE=true` is the dev opt-out.
//!
//! Any ONE valid credential is enough; the two are alternatives, not a pair.
//!
//! Why this exists: ox-browser forwards `/chrome/interact` (REST and the MCP
//! tool) to go-wowa with the fleet secret attached. Without inbound auth any
//! process that can reach :8901 would use ox-browser as a credentialed relay
//! into go-wowa's Chrome.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Header carrying the shared internal secret.
pub const SECRET_HEADER: &str = "x-internal-secret";

/// Request extension the gate inserts only when the caller presented the
/// shared internal secret (`ok_secret`), i.e. proved possession of
/// `INTERNAL_SERVICE_SECRET` — the very credential ox-browser relays to
/// go-wowa. A valid `OX_MCP_TOKEN` bearer does NOT earn it: an MCP-token
/// holder is not necessarily a fleet service with go-wowa access, so its
/// caller-shaped `chrome_interact` / `/read` must not be relayed with the
/// fleet secret. A request let through by soft mode or the insecure override
/// also lacks it. Reachable from axum handlers via `Option<Extension<_>>`
/// and from MCP tools via the `http::request::Parts` rmcp injects.
#[derive(Debug, Clone, Copy)]
pub struct Authenticated;

/// A request's gate decision, carried downstream as an opaque token.
///
/// `InboundAuth` is built exactly one way — [`Self::from_marker`] reads the
/// [`Authenticated`] extension the gate inserted — so a call site cannot
/// stamp `true` from a literal the way `with_authenticated(true)` could
/// (SEC-CR-018, ox-browser#177). The flag stays private; consumers that must
/// read it ([`HttpClient`](ox_http::HttpClient) stamps, `provider.solve`,
/// `GoBrowserProxy`) get it back via [`Self::is_authenticated`] at the sink
/// only.
///
/// REST handlers receive it as an axum extractor (`auth: InboundAuth` —
/// `FromRequestParts` derives it from the request's extensions). The MCP
/// tools derive it in `tools::chrome_interact::inbound_auth` from the
/// `http::request::Parts` rmcp injects — one construction site per surface.
#[derive(Debug, Clone, Copy)]
pub struct InboundAuth(bool);

impl InboundAuth {
    /// Build the token from the gate marker: `Some` means this inbound
    /// request presented the shared internal secret (`ok_secret`). The ONLY
    /// constructor — there is deliberately no `InboundAuth(true)`.
    pub fn from_marker(marker: Option<&Authenticated>) -> Self {
        Self(marker.is_some())
    }

    /// `true` iff the inbound request was authenticated by the gate's
    /// shared-secret check. Read only at the sink that consumes the flag.
    pub fn is_authenticated(self) -> bool {
        self.0
    }
}

impl<S> axum::extract::FromRequestParts<S> for InboundAuth
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self::from_marker(parts.extensions.get::<Authenticated>()))
    }
}

const MAX_SIGHTINGS: usize = 512;
/// Max User-Agent length kept, in characters (never splits UTF-8).
const MAX_UA_LEN: usize = 80;
/// Distinct User-Agents tracked per remote IP; further ones share
/// [`OTHER_UA`], so one peer cycling UAs cannot fill the table.
const MAX_UAS_PER_IP: usize = 8;
const OTHER_UA: &str = "<other-ua>";
/// First-sighting entries one remote IP may hold across ALL keys (results ×
/// route classes × UA buckets), so a few IPs cannot fill the table.
const MAX_ENTRIES_PER_IP: usize = 16;

/// Whether a request without a usable credential is rejected or allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Reject requests without a valid credential.
    Enforce,
    /// Allow (and log/count) requests without a usable credential.
    Soft,
}

impl Mode {
    /// Parse `OX_AUTH_MODE`. Empty and unknown values are `Enforce`: a typo
    /// must never open the service.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "soft" => Mode::Soft,
            "" | "enforce" => Mode::Enforce,
            other => {
                tracing::warn!(
                    value = other,
                    "inbound_auth: unknown OX_AUTH_MODE — using enforce"
                );
                Mode::Enforce
            }
        }
    }
}

/// Gate configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Accepted as `X-Internal-Secret`; empty = not configured.
    pub internal_secret: String,
    /// Accepted as `Authorization: Bearer`; empty = not configured.
    pub mcp_token: String,
    /// Enforce or soft.
    pub mode: Mode,
    /// With no credential configured, allow everything (dev only).
    pub allow_insecure: bool,
}

impl AuthConfig {
    /// Read `INTERNAL_SERVICE_SECRET`, `OX_MCP_TOKEN`, `OX_AUTH_MODE` and
    /// `OX_AUTH_ALLOW_INSECURE`.
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).unwrap_or_default();
        Self {
            // Trimmed like the presented values, so a trailing newline from
            // an env file cannot make every correct credential mismatch.
            internal_secret: var("INTERNAL_SERVICE_SECRET").trim().to_owned(),
            mcp_token: var("OX_MCP_TOKEN").trim().to_owned(),
            mode: Mode::parse(&var("OX_AUTH_MODE")),
            allow_insecure: matches!(
                var("OX_AUTH_ALLOW_INSECURE")
                    .trim()
                    .to_ascii_lowercase()
                    .as_str(),
                "1" | "true" | "yes"
            ),
        }
    }

    fn configured(&self) -> bool {
        !self.internal_secret.is_empty() || !self.mcp_token.is_empty()
    }
}

/// The gate; cheap to clone (shared state behind an `Arc`).
#[derive(Clone)]
pub struct Gate {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: AuthConfig,
    sightings: Mutex<Sightings>,
}

/// Bounded first-sighting set keyed by (result, class, IP, UA): at most
/// [`MAX_SIGHTINGS`] entries overall and [`MAX_UAS_PER_IP`] distinct UAs per
/// IP, so neither many addresses nor one address cycling User-Agents can
/// crowd out later callers.
#[derive(Default)]
struct Sightings {
    seen: HashSet<String>,
    uas_per_ip: HashMap<String, HashSet<String>>,
    entries_per_ip: HashMap<String, usize>,
    capped: HashSet<String>,
}

impl Sightings {
    /// Record a sighting. Returns (ua-as-recorded, is-new,
    /// just-hit-the-per-IP-cap). The third flag is true exactly once per IP,
    /// when its cap first binds, so the caller can warn once instead of
    /// dropping further sightings silently.
    fn first(&mut self, prefix: &str, ip: &str, ua: &str) -> (String, bool, bool) {
        let known = self.uas_per_ip.get(ip).is_some_and(|s| s.contains(ua));
        let over = self
            .uas_per_ip
            .get(ip)
            .is_some_and(|s| s.len() >= MAX_UAS_PER_IP);
        let ua = if !known && over { OTHER_UA } else { ua };
        let key = format!("{prefix}|{ip}|{ua}");
        if self.seen.len() >= MAX_SIGHTINGS || self.seen.contains(&key) {
            return (ua.to_owned(), false, false);
        }
        let per_ip = self.entries_per_ip.entry(ip.to_owned()).or_default();
        if *per_ip >= MAX_ENTRIES_PER_IP {
            let just_capped = self.capped.insert(ip.to_owned());
            return (ua.to_owned(), false, just_capped);
        }
        *per_ip += 1;
        self.seen.insert(key);
        if ua != OTHER_UA {
            self.uas_per_ip
                .entry(ip.to_owned())
                .or_default()
                .insert(ua.to_owned());
        }
        (ua.to_owned(), true, false)
    }
}

impl Gate {
    /// Build the gate and log its posture once.
    pub fn new(cfg: AuthConfig) -> Self {
        let enforced = match (cfg.configured(), cfg.allow_insecure, cfg.mode) {
            (false, true, _) => {
                tracing::warn!(
                    "inbound_auth: no credential configured and OX_AUTH_ALLOW_INSECURE=true — every route is OPEN (dev only)"
                );
                false
            }
            (false, false, _) => {
                tracing::error!(
                    "inbound_auth: neither INTERNAL_SERVICE_SECRET nor OX_MCP_TOKEN is set — failing closed, every non-health request gets 401"
                );
                true
            }
            (true, _, Mode::Soft) => {
                tracing::warn!(
                    "inbound_auth: SOFT mode — requests without a credential are allowed and logged; set OX_AUTH_MODE=enforce once callers are migrated"
                );
                false
            }
            (true, _, Mode::Enforce) => {
                tracing::info!("inbound_auth: enforcing");
                true
            }
        };
        ox_http::metrics::set_gauge(&ox_http::metrics::AUTH_ENFORCED, u64::from(enforced));
        Self {
            inner: Arc::new(Inner {
                cfg,
                sightings: Mutex::new(Sightings::default()),
            }),
        }
    }

    /// Decide one request: `(result label, allowed)`.
    fn decide(&self, headers: &HeaderMap) -> (&'static str, bool) {
        let cfg = &self.inner.cfg;
        if !cfg.configured() {
            return if cfg.allow_insecure {
                ("insecure", true)
            } else {
                ("unconfigured", false)
            };
        }
        let secret = headers
            .get(SECRET_HEADER)
            .map(|v| v.to_str().unwrap_or("").trim());
        let bearer = bearer_token(headers);

        if secret.is_some_and(|s| matches(s, &cfg.internal_secret)) {
            return ("ok_secret", true);
        }
        if bearer.is_some_and(|t| matches(t, &cfg.mcp_token)) {
            return ("ok_bearer", true);
        }
        // Sent but empty: a broken caller (unset env, missing token file).
        if secret == Some("") || bearer == Some("") {
            return ("invalid", false);
        }
        // Sent against a configured counterpart and did not verify.
        if (secret.is_some() && !cfg.internal_secret.is_empty())
            || (bearer.is_some() && !cfg.mcp_token.is_empty())
        {
            return ("invalid", false);
        }
        let result = if secret.is_some() || bearer.is_some() {
            "unverifiable"
        } else {
            "missing"
        };
        (result, cfg.mode == Mode::Soft)
    }

    fn note_sighting(&self, class: &str, result: &str, allowed: bool, req: &Request) {
        if result.starts_with("ok_") {
            return;
        }
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip().to_string())
            .unwrap_or_else(|| "unknown".into());
        let ua: String = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .chars()
            .take(MAX_UA_LEN)
            .collect();
        let (ua, first, just_capped) = self
            .inner
            .sightings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .first(&format!("{result}|{class}"), &ip, &ua);
        if first {
            tracing::warn!(
                result,
                allowed,
                route_class = class,
                method = %req.method(),
                path = req.uri().path(),
                remote_ip = %ip,
                user_agent = %ua,
                "inbound_auth: request without a valid credential (first sighting for this caller)"
            );
        } else if just_capped {
            tracing::warn!(
                remote_ip = %ip,
                max_per_ip = MAX_ENTRIES_PER_IP,
                "inbound_auth: per-IP first-sighting cap reached — further new sightings from this IP are counted in oxbrowser_auth_requests_total but not logged"
            );
        }
    }
}

/// Constant-time comparison of SHA-256 digests; both sides must be non-empty.
fn matches(provided: &str, expected: &str) -> bool {
    if provided.is_empty() || expected.is_empty() {
        return false;
    }
    let p = Sha256::digest(provided.as_bytes());
    let e = Sha256::digest(expected.as_bytes());
    bool::from(p.as_slice().ct_eq(e.as_slice()))
}

/// `Some(token)` for an `Authorization: Bearer <token>` header (scheme
/// case-insensitive; the token may be empty), `None` otherwise.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let h = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, rest) = h.split_at(h.len().min(6));
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
        return None; // "Bearerabc" is not the Bearer scheme
    }
    Some(rest.trim())
}

fn is_exempt(method: &Method, path: &str) -> bool {
    (method == Method::GET || method == Method::HEAD) && path == "/health"
}

fn route_class(path: &str) -> &'static str {
    if path == "/mcp" || path.starts_with("/mcp/") {
        "mcp"
    } else if path.starts_with("/chrome/") {
        "chrome"
    } else if path == "/metrics" {
        "metrics"
    } else {
        "rest"
    }
}

/// axum middleware: `from_fn_with_state(gate, inbound_auth::middleware)`.
pub async fn middleware(State(gate): State<Gate>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    if is_exempt(req.method(), &path) {
        return next.run(req).await;
    }
    let class = route_class(&path);
    let (result, allowed) = gate.decide(req.headers());
    ox_http::metrics::record_auth_result(result);
    gate.note_sighting(class, result, allowed, &req);
    if !allowed {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer realm=\"ox-browser\"")],
            "unauthorized: send X-Internal-Secret or Authorization: Bearer",
        )
            .into_response();
    }
    // Only the shared internal secret earns the relay marker (see its docs);
    // a valid bearer passes the gate but is not relayed with the fleet secret.
    if result == "ok_secret" {
        req.extensions_mut().insert(Authenticated);
    }
    next.run(req).await
}

/// Wrap `router` with the gate. The gate wraps the whole router service, so
/// it also covers unmatched paths and the MCP routes merged into it.
pub fn protect(router: axum::Router, gate: Gate) -> axum::Router {
    router.layer(axum::middleware::from_fn_with_state(gate, middleware))
}

#[cfg(test)]
#[path = "inbound_auth_tests.rs"]
mod tests;
