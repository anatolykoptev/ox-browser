//! SEC-CR-018 (ox-browser#177): table-driven coverage that EVERY REST route
//! able to reach go-wowa relays ox-browser's internal secret only when the
//! inbound request carried the gate's `ok_secret` marker.
//!
//! Each row is driven through the real gate + router (`protect(router(..))`),
//! so the `InboundAuth` extractor and `AppState::client_for` — the single
//! derivation and stamp points — run for real. The go-wowa side is a capture
//! server: routes that fetch through the shared client hit a mock terminal
//! handler answering a genuine CF challenge, so the solver middleware calls
//! the real `GoBrowserSolver` (POST /solve); `/solve` calls it directly; the
//! `/chrome/*` routes go through `GoBrowserProxy`. Whichever path a row takes,
//! the captured request head is what carries — or must not carry —
//! `x-internal-secret`.
//!
//! Mutation: force the flag at the single derivation point — e.g. make
//! `InboundAuth::from_marker` build `Self(true)` unconditionally — and every
//! anonymous row's captured head carries the secret → RED.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use tower::ServiceExt;

use ox_http::solver_gobrowser::{GoBrowserConfig, GoBrowserSolver};
use ox_http::{
    ChallengeType, CookieCache, CookieProvider, Handler, HttpClient, HttpConfig, HttpError,
    HttpResponse, Request,
};

use crate::inbound_auth::{AuthConfig, Gate, Mode, SECRET_HEADER, protect};
use crate::{AppState, EndpointDefaults, router};

/// What `GoBrowserSolver` expects on POST /solve; also valid JSON for the
/// `GoBrowserProxy` routes (they parse the body as `Value` only).
const WOWA_OK: &str = r#"{"status":"ok","cookies":{"cf_clearance":"t"},"user_agent":"UA"}"#;

/// Terminal handler answering every request with a genuine CF challenge, so
/// the solver middleware calls the provider for every fetch-style route.
struct AlwaysCfHandler;

#[async_trait]
impl Handler for AlwaysCfHandler {
    async fn handle(&self, _req: Request) -> ox_http::Result<HttpResponse> {
        Err(HttpError::Cloudflare(
            ChallengeType::JsChallenge,
            403,
            "ray".into(),
        ))
    }
}

/// The gated app with all three go-wowa surfaces pointed at `wowa` (the
/// capture server), each holding ox-browser's outbound secret "wowa-secret":
/// `state.provider` (what `/solve` calls), the shared client's solver
/// middleware (what the fetch routes reach through `client_for`), and
/// `gobrowser_proxy` (the `/chrome/*` routes).
fn gated_app(wowa: &str) -> axum::Router {
    let provider: Arc<dyn CookieProvider> = Arc::new(GoBrowserSolver::new(GoBrowserConfig {
        base_url: wowa.to_owned(),
        timeout: Duration::from_secs(5),
        internal_secret: "wowa-secret".into(),
    }));
    let http = HttpClient::with_chain(
        Arc::new(AlwaysCfHandler),
        HttpConfig {
            cookie_provider: Some(Arc::clone(&provider)),
            cookie_cache: Some(Arc::new(CookieCache::new(Duration::from_secs(60)))),
            ..HttpConfig::default()
        },
    );
    let state = AppState::new(
        provider,
        Arc::new(CookieCache::new(Duration::from_secs(60))),
        Arc::new(http),
        EndpointDefaults::default(),
        ox_media::MediaConfig::default(),
        Arc::new(crate::gobrowser_proxy::GoBrowserProxy::new(
            wowa.to_owned(),
            "wowa-secret",
        )),
    );
    protect(
        router(state),
        Gate::new(AuthConfig {
            internal_secret: "s".into(),
            mcp_token: String::new(),
            mode: Mode::Soft,
            allow_insecure: false,
        }),
    )
}

/// Every REST route whose handler can cause a credentialed call to go-wowa,
/// as `(method, path, json body)`. Bodies are the cheapest valid shape that
/// reaches the wire: an IP-literal URL passes SSRF and lands on the mock CF
/// handler; the image routes are pinned to a single engine that issues one
/// `client.get`/`get_with_headers` so exactly one /solve is attempted.
const ROUTES: &[(axum::http::Method, &str, &str)] = &[
    (
        axum::http::Method::POST,
        "/fetch",
        r#"{"url":"http://1.1.1.1/p","timeout":5}"#,
    ),
    (
        axum::http::Method::POST,
        "/fetch-smart",
        r#"{"url":"http://1.1.1.1/p","timeout":5}"#,
    ),
    (
        axum::http::Method::POST,
        "/read",
        r#"{"url":"http://1.1.1.1/p","timeout":5}"#,
    ),
    (
        axum::http::Method::POST,
        "/readability",
        r#"{"url":"http://1.1.1.1/p"}"#,
    ),
    (
        axum::http::Method::POST,
        "/analyze",
        r#"{"url":"http://1.1.1.1/p"}"#,
    ),
    (
        axum::http::Method::POST,
        "/security",
        r#"{"url":"http://1.1.1.1/p"}"#,
    ),
    (
        axum::http::Method::POST,
        "/site-audit",
        r#"{"url":"http://1.1.1.1/p"}"#,
    ),
    (
        axum::http::Method::POST,
        "/images/search",
        r#"{"query":"cats","engines":["bing"],"max_results":3}"#,
    ),
    (
        axum::http::Method::POST,
        "/images/reverse",
        r#"{"url":"http://1.1.1.1/i.jpg","engines":["yandex"],"max_results":3}"#,
    ),
    (
        axum::http::Method::POST,
        "/media/download",
        r#"{"url":"http://1.1.1.1/v"}"#,
    ),
    (
        axum::http::Method::POST,
        "/crawl",
        r#"{"url":"http://1.1.1.1/","max_pages":1,"max_depth":0,"timeout":5}"#,
    ),
    (
        axum::http::Method::POST,
        "/solve",
        r#"{"url":"http://1.1.1.1/p","challenge_type":"js_challenge"}"#,
    ),
    (
        axum::http::Method::POST,
        "/chrome/interact",
        r#"{"url":"http://1.1.1.1/","actions":[]}"#,
    ),
    (axum::http::Method::DELETE, "/chrome/session/t1", ""),
];

/// In soft mode every stamping route relays `x-internal-secret: wowa-secret`
/// to go-wowa iff the inbound request carried the gate secret.
///
/// Mutation (SEC-CR-018): force the flag at `InboundAuth::from_marker` →
/// every `inbound=None` row's head contains the secret → RED. Force `false`
/// and the `Some("s")` rows lose it → RED.
#[tokio::test]
async fn rest_routes_relay_secret_only_when_authenticated() {
    for (method, path, body) in ROUTES {
        for (inbound, want_secret) in [(Some("s"), true), (None, false)] {
            let (wowa, captured) = ox_http::wowa_auth::capture_one(WOWA_OK).await;
            let app = gated_app(&wowa);
            let mut b = axum::http::Request::builder()
                .method(method.clone())
                .uri(*path)
                .header("content-type", "application/json");
            if let Some(s) = inbound {
                b = b.header(SECRET_HEADER, s);
            }
            let resp = app
                .oneshot(b.body(Body::from((*body).to_owned())).unwrap())
                .await
                .unwrap();
            // The response status differs per route (200 on the proxy/solve
            // routes, 502 where the fetch errors out) — what is asserted is
            // the head go-wowa received. Read it regardless.
            let head = tokio::time::timeout(Duration::from_secs(10), captured)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "{method} {path} inbound={inbound:?} status={}: go-wowa was never called",
                        resp.status()
                    )
                })
                .expect("capture");
            assert_eq!(
                head.contains("x-internal-secret: wowa-secret"),
                want_secret,
                "{method} {path} inbound={inbound:?}: {head}"
            );
        }
    }
}
