//! `.onion` URLs must never reach a third party (ox-browser#188): the REST
//! endpoints that hand the caller's URL to the CF solver (`/solve`), go-wowa's
//! Chrome (`/chrome/interact`) or a reverse-image engine (`/images/reverse`)
//! refuse an onion URL before any outbound call.
//!
//! Each row drives the real gate + router (`protect(router(..))`). The
//! upstreams are counting stubs that must receive ZERO requests; a clearnet
//! control row per route proves the stub and the counter are live.
//!
//! Mutation: remove the `refuse_onion_for_third_party` /
//! `json_mentions_onion` check in one handler (solve.rs, chrome_interact.rs,
//! reverse_search.rs) and that route's row goes RED (status != 400 and the
//! stub / handler counter moves).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

use ox_http::solver_gobrowser::{GoBrowserConfig, GoBrowserSolver};
use ox_http::{
    CookieCache, CookieProvider, Handler, HttpClient, HttpConfig, HttpResponse, Request,
};

use crate::inbound_auth::{AuthConfig, Gate, Mode, protect};
use crate::{AppState, EndpointDefaults, router};

const WOWA_OK: &str = r#"{"status":"ok","cookies":{"cf_clearance":"t"},"user_agent":"UA"}"#;

/// A stub go-wowa: answers every connection with `WOWA_OK` and counts them.
async fn counting_wowa() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let hits = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{WOWA_OK}",
                    WOWA_OK.len()
                );
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (url, hits)
}

/// Terminal handler of the shared client: counts every request it sees.
struct CountingHandler(Arc<AtomicUsize>);

#[async_trait]
impl Handler for CountingHandler {
    async fn handle(&self, _req: Request) -> ox_http::Result<HttpResponse> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ox_http::HttpError::InvalidUrl("no network in tests".into()))
    }
}

fn app(wowa: &str, client_hits: Arc<AtomicUsize>) -> axum::Router {
    let provider: Arc<dyn CookieProvider> = Arc::new(GoBrowserSolver::new(GoBrowserConfig {
        base_url: wowa.to_owned(),
        timeout: Duration::from_secs(5),
        internal_secret: "wowa-secret".into(),
    }));
    let http = HttpClient::with_chain(
        Arc::new(CountingHandler(client_hits)),
        HttpConfig::default(),
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

async fn post(app: axum::Router, path: &str, body: &str) -> (u16, serde_json::Value) {
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// (route, onion body, clearnet control body, does the route's upstream show
/// up on the wowa stub (true) or on the shared client's terminal handler)
const ROUTES: &[(&str, &str, &str, bool)] = &[
    (
        "/solve",
        r#"{"url":"https://foo.onion/","challenge_type":"js_challenge"}"#,
        r#"{"url":"http://1.1.1.1/p","challenge_type":"js_challenge"}"#,
        true,
    ),
    (
        "/chrome/interact",
        r#"{"url":"https://foo.onion/","actions":[]}"#,
        r#"{"url":"http://1.1.1.1/","actions":[]}"#,
        true,
    ),
    (
        // The onion URL hides in a nested action, not the top-level `url`.
        "/chrome/interact",
        r#"{"url":"https://example.com/","actions":[{"type":"navigate","url":"http://FOO.ONION./"}]}"#,
        r#"{"url":"https://example.com/","actions":[{"type":"navigate","url":"http://1.1.1.1/"}]}"#,
        true,
    ),
    (
        "/images/reverse",
        r#"{"url":"https://foo.onion/i.jpg","engines":["yandex"]}"#,
        r#"{"url":"http://1.1.1.1/i.jpg","engines":["yandex"]}"#,
        false,
    ),
];

#[tokio::test]
async fn third_party_endpoints_refuse_onion_urls_before_any_outbound_call() {
    for &(path, onion, clearnet, via_wowa) in ROUTES {
        // Onion: refused, upstream untouched.
        let (wowa, wowa_hits) = counting_wowa().await;
        let client_hits = Arc::new(AtomicUsize::new(0));
        let (status, body) = post(app(&wowa, Arc::clone(&client_hits)), path, onion).await;
        assert_eq!(status, 400, "{path} {onion}: status, body {body}");
        let err = body["error"].as_str().unwrap_or_default();
        assert!(
            err.starts_with("onion_requires_tor"),
            "{path} {onion}: error was {err:?}"
        );
        assert_eq!(
            wowa_hits.load(Ordering::SeqCst),
            0,
            "{path} {onion}: the go-wowa stub was called"
        );
        assert_eq!(
            client_hits.load(Ordering::SeqCst),
            0,
            "{path} {onion}: the shared client was called"
        );

        // Control: the same route with a clearnet URL DOES reach its upstream.
        let (wowa, wowa_hits) = counting_wowa().await;
        let client_hits = Arc::new(AtomicUsize::new(0));
        let _ = post(app(&wowa, Arc::clone(&client_hits)), path, clearnet).await;
        let reached = if via_wowa {
            wowa_hits.load(Ordering::SeqCst)
        } else {
            client_hits.load(Ordering::SeqCst)
        };
        assert!(reached >= 1, "{path}: control did not reach its upstream");
    }
}

/// Readability's headless fallback calls the solver directly; an onion URL is
/// refused there too, with the solver stub untouched.
///
/// Mutation: remove the check at the top of `headless_fetch` (readability.rs)
/// → the stub is called and the error is not `onion_requires_tor`.
#[tokio::test]
async fn readability_headless_fallback_refuses_onion() {
    let (wowa, wowa_hits) = counting_wowa().await;
    let provider: Arc<dyn CookieProvider> = Arc::new(GoBrowserSolver::new(GoBrowserConfig {
        base_url: wowa.clone(),
        timeout: Duration::from_secs(5),
        internal_secret: "wowa-secret".into(),
    }));
    let state = AppState::new(
        provider,
        Arc::new(CookieCache::new(Duration::from_secs(60))),
        Arc::new(HttpClient::with_chain(
            Arc::new(CountingHandler(Arc::new(AtomicUsize::new(0)))),
            HttpConfig::default(),
        )),
        EndpointDefaults::default(),
        ox_media::MediaConfig::default(),
        Arc::new(crate::gobrowser_proxy::GoBrowserProxy::new(
            wowa,
            "wowa-secret",
        )),
    );
    let err = crate::readability::headless_fetch(
        &state,
        "https://foo.onion/",
        crate::inbound_auth::InboundAuth::from_marker(None),
    )
    .await
    .expect_err("onion must be refused");
    assert!(err.starts_with("onion_requires_tor"), "{err}");
    assert_eq!(wowa_hits.load(Ordering::SeqCst), 0);
}
