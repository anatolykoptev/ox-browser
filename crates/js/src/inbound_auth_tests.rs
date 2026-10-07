use super::*;
use axum::body::Body;
use std::sync::atomic::Ordering;
use tower::ServiceExt;

const SECRET: &str = "test-secret";
const TOKEN: &str = "test-token";

fn cfg(mode: Mode) -> AuthConfig {
    AuthConfig {
        internal_secret: SECRET.into(),
        mcp_token: TOKEN.into(),
        mode,
        allow_insecure: false,
    }
}

/// The production REST router wrapped exactly as serve.rs does it.
fn app(c: AuthConfig) -> axum::Router {
    protect(crate::router(crate::tests::test_state()), Gate::new(c))
}

/// Every route class, plus paths the router does not serve: a 401 on those
/// proves the gate runs before routing (and covers the MCP routes serve.rs
/// merges in, which this test router does not have).
const GATED: &[(&str, &str)] = &[
    ("POST", "/fetch"),
    ("POST", "/read"),
    ("POST", "/solve"),
    ("POST", "/crawl"),
    ("POST", "/chrome/interact"),
    ("DELETE", "/chrome/session/abc"),
    ("GET", "/metrics"),
    ("POST", "/mcp"),
    ("POST", "/nope-unregistered"),
    ("GET", "//health"),
    ("GET", "/health/"),
    ("GET", "/HEALTH"),
    ("POST", "/health"),
    ("GET", "/health/%2e%2e/metrics"),
];

async fn status(app: &axum::Router, method: &str, path: &str, hdrs: &[(&str, &str)]) -> StatusCode {
    let mut b = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    for (k, v) in hdrs {
        b = b.header(*k, *v);
    }
    app.clone()
        .oneshot(b.body(Body::from("{}")).unwrap())
        .await
        .unwrap()
        .status()
}

/// Falsification: drop the `.layer(...)` in `protect` (or stop calling it in
/// serve.rs and here) and these rows return the handlers' own statuses.
#[tokio::test]
async fn rejects_without_valid_credential() {
    let a = app(cfg(Mode::Enforce));
    let bad: &[&[(&str, &str)]] = &[
        &[],
        &[(SECRET_HEADER, "wrong")],
        &[("authorization", "Bearer wrong")],
        &[("authorization", "Bearer ")],
        &[(SECRET_HEADER, "")],
        &[("authorization", "Bearer test-secret")], // secret is not a bearer
    ];
    for hdrs in bad {
        for (m, p) in GATED {
            assert_eq!(
                status(&a, m, p, hdrs).await,
                StatusCode::UNAUTHORIZED,
                "{m} {p} {hdrs:?}"
            );
        }
    }
}

#[tokio::test]
async fn accepts_either_credential() {
    let a = app(cfg(Mode::Enforce));
    for hdrs in [
        &[(SECRET_HEADER, SECRET)][..],
        &[("authorization", "Bearer test-token")][..],
        &[("authorization", "bearer test-token")][..],
    ] {
        for (m, p) in [("GET", "/metrics"), ("POST", "/nope-unregistered")] {
            assert_ne!(
                status(&a, m, p, hdrs).await,
                StatusCode::UNAUTHORIZED,
                "{m} {p} {hdrs:?}"
            );
        }
    }
}

#[tokio::test]
async fn health_is_exempt() {
    let a = app(cfg(Mode::Enforce));
    assert_eq!(status(&a, "GET", "/health", &[]).await, StatusCode::OK);
}

/// Falsification: make `decide` allow when nothing is configured → RED.
#[tokio::test]
async fn fails_closed_when_unconfigured() {
    for mode in [Mode::Enforce, Mode::Soft] {
        let a = app(AuthConfig {
            internal_secret: String::new(),
            mcp_token: String::new(),
            mode,
            allow_insecure: false,
        });
        assert_eq!(
            status(&a, "GET", "/metrics", &[(SECRET_HEADER, "x")]).await,
            StatusCode::UNAUTHORIZED,
            "{mode:?}"
        );
        assert_eq!(status(&a, "GET", "/health", &[]).await, StatusCode::OK);
    }
    let a = app(AuthConfig {
        internal_secret: String::new(),
        mcp_token: String::new(),
        mode: Mode::Enforce,
        allow_insecure: true,
    });
    assert_eq!(status(&a, "GET", "/metrics", &[]).await, StatusCode::OK);
}

#[tokio::test]
async fn soft_allows_missing_rejects_wrong_and_empty() {
    let a = app(AuthConfig {
        internal_secret: SECRET.into(),
        mcp_token: String::new(),
        mode: Mode::Soft,
        allow_insecure: false,
    });
    let before = ox_http::metrics::AUTH_MISSING.load(Ordering::Relaxed);
    assert_eq!(status(&a, "GET", "/metrics", &[]).await, StatusCode::OK);
    assert!(
        ox_http::metrics::AUTH_MISSING.load(Ordering::Relaxed) > before,
        "missing not counted"
    );
    // bearer with no configured token: unverifiable, allowed in soft
    assert_eq!(
        status(&a, "GET", "/metrics", &[("authorization", "Bearer x")]).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&a, "GET", "/metrics", &[(SECRET_HEADER, "wrong")]).await,
        StatusCode::UNAUTHORIZED
    );
    // empty credential = broken caller: loud even in soft
    assert_eq!(
        status(&a, "GET", "/metrics", &[("authorization", "Bearer ")]).await,
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn mode_parse_fails_closed() {
    assert_eq!(Mode::parse(""), Mode::Enforce);
    assert_eq!(Mode::parse("soft"), Mode::Soft);
    assert_eq!(Mode::parse(" SOFT "), Mode::Soft);
    assert_eq!(Mode::parse("sotf"), Mode::Enforce);
}

#[test]
fn matches_rejects_empty() {
    assert!(!matches("", ""));
    assert!(!matches("x", ""));
    assert!(!matches("", "x"));
    assert!(!matches("x", "y"));
    assert!(matches("x", "x"));
}

/// Wiring: the env names serve.rs relies on. Falsification: rename or drop
/// a read in `AuthConfig::from_env` → RED. Only this test touches these vars.
#[test]
fn from_env_reads_the_documented_variables() {
    // SAFETY: edition-2024 env mutation; no other test reads these vars.
    unsafe {
        std::env::set_var("INTERNAL_SERVICE_SECRET", "e-secret");
        std::env::set_var("OX_MCP_TOKEN", "e-token");
        std::env::set_var("OX_AUTH_MODE", "soft");
        std::env::set_var("OX_AUTH_ALLOW_INSECURE", "true");
    }
    let c = AuthConfig::from_env();
    unsafe {
        for k in [
            "INTERNAL_SERVICE_SECRET",
            "OX_MCP_TOKEN",
            "OX_AUTH_MODE",
            "OX_AUTH_ALLOW_INSECURE",
        ] {
            std::env::remove_var(k);
        }
    }
    assert_eq!(c.internal_secret, "e-secret");
    assert_eq!(c.mcp_token, "e-token");
    assert_eq!(c.mode, Mode::Soft);
    assert!(c.allow_insecure);
}

/// One peer cycling User-Agents must not fill the table and silence later
/// callers.
///
/// Falsification: drop the MAX_UAS_PER_IP bucket in `Sightings::first`
/// (inbound_auth.rs) and 1000 UAs from one IP fill all 512 slots, so the new
/// IP is not recorded → RED.
#[test]
fn ua_flood_from_one_ip_cannot_silence_others() {
    let mut s = Sightings::default();
    for i in 0..1000 {
        s.first("missing|rest", "10.0.0.66", &format!("flood/{i}"));
    }
    assert!(
        s.seen.len() <= MAX_UAS_PER_IP + 1,
        "one IP produced {} sightings",
        s.seen.len()
    );
    let (_, new) = s.first("missing|rest", "10.0.0.77", "real-caller/1");
    assert!(new, "a new IP after the flood was not recorded");
}

/// The gate marks a request Authenticated only for a valid credential;
/// soft-mode pass-throughs carry no marker, so relays must not attach the
/// fleet secret for them.
///
/// Falsification: insert the marker for every allowed request (drop the
/// `ok_` condition in `middleware`) and the soft-mode row sees it → RED.
#[tokio::test]
async fn authenticated_marker_only_for_valid_credential() {
    use axum::Extension;
    let probe = axum::Router::new().route(
        "/probe",
        axum::routing::get(|m: Option<Extension<Authenticated>>| async move {
            if m.is_some() { "auth" } else { "anon" }
        }),
    );
    let a = protect(
        probe,
        Gate::new(AuthConfig {
            internal_secret: SECRET.into(),
            mcp_token: String::new(),
            mode: Mode::Soft,
            allow_insecure: false,
        }),
    );
    for (hdrs, want) in [(&[(SECRET_HEADER, SECRET)][..], "auth"), (&[][..], "anon")] {
        let mut b = axum::http::Request::builder().uri("/probe");
        for (k, v) in hdrs {
            b = b.header(*k, *v);
        }
        let r = a
            .clone()
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(r.into_body(), 64).await.unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), want, "{hdrs:?}");
    }
}
