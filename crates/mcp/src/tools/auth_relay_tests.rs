//! SEC-CR-018 (ox-browser#177): table-driven coverage that EVERY MCP tool
//! able to reach go-wowa relays ox-browser's internal secret only when the
//! inbound request carried the gate's `ok_secret` marker.
//!
//! Each row calls the tool's `do_*` with the token from
//! `chrome_interact::inbound_auth(&ext)` — the single derivation point the
//! `#[tool]` handlers in `mod.rs` all use — built from a `Parts` extension
//! set exactly as rmcp injects it (with/without the `Authenticated` marker).
//! The go-wowa side is a capture server: the shared client hits a mock
//! terminal handler answering a genuine CF challenge, so fetch-style tools
//! reach the real `GoBrowserSolver` via the solver middleware; `solve_cf`
//! calls it directly; `chrome_interact` goes through `GoBrowserProxy`.
//!
//! Mutation: make `chrome_interact::inbound_auth` build an authenticated
//! token unconditionally and every `marker=false` row's captured head
//! carries the secret → RED.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use ox_http::solver_gobrowser::{GoBrowserConfig, GoBrowserSolver};
use ox_http::{
    ChallengeType, CookieCache, CookieProvider, Handler, HttpClient, HttpConfig, HttpError,
    HttpResponse, Request,
};
use ox_js::gobrowser_proxy::GoBrowserProxy;
use ox_js::inbound_auth::Authenticated;

use super::chrome_interact;
use super::*;

const WOWA_OK: &str = r#"{"status":"ok","cookies":{"cf_clearance":"t"},"user_agent":"UA"}"#;

/// Terminal handler answering every request with a genuine CF challenge.
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

/// An `Extensions` shaped like the rmcp-injected HTTP parts: the gate's
/// `Authenticated` marker present iff `ok_secret`.
fn parts_ext(ok_secret: bool) -> Extensions {
    let (mut parts, ()) = axum::http::Request::new(()).into_parts();
    if ok_secret {
        parts.extensions.insert(Authenticated);
    }
    let mut ext = Extensions::new();
    ext.insert(parts);
    ext
}

/// The server with all go-wowa surfaces pointed at `wowa` (the capture
/// server), each holding ox-browser's outbound secret "wowa-secret":
/// `provider` (`solve_cf` + readability's headless fallback), the shared
/// client's solver middleware (fetch-style tools via `client_for`), and
/// `gobrowser_proxy` (`chrome_interact`).
fn server(wowa: &str) -> OxMcpServer {
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
    OxMcpServer::new(
        provider,
        Arc::new(CookieCache::new(Duration::from_secs(60))),
        Arc::new(http),
        EndpointDefaults::default(),
        ox_media::MediaConfig::default(),
        Arc::new(GoBrowserProxy::new(wowa.to_owned(), "wowa-secret")),
    )
}

/// One row = one tool call, driven as `server.do_<tool>(input, auth)` where
/// `auth` came from the real derivation point. Inputs mirror the REST table
/// — cheap shapes that issue one stamped fetch (or one provider/proxy call).
async fn call_tool(server: &OxMcpServer, tool: &str, args: &str, ok_secret: bool) {
    let auth = chrome_interact::inbound_auth(&parts_ext(ok_secret));
    match tool {
        "fetch" => {
            let _ = server
                .do_fetch(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "fetch_smart" => {
            let _ = server
                .do_fetch_smart(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "read" => {
            let _ = server
                .do_read(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "readability" => {
            let _ = server
                .do_readability(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "analyze" => {
            let _ = server
                .do_analyze(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "security_scan" => {
            let _ = server
                .do_security_scan(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "site_audit" => {
            let _ = server
                .do_site_audit(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "image_search" => {
            let _ = server
                .do_image_search(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "reverse_image_search" => {
            let _ = server
                .do_reverse_search(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "media_download" => {
            let _ = server
                .do_media_download(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "crawl" => {
            let _ = server
                .do_crawl(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "solve_cf" => {
            let _ = server
                .do_solve_cf(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        "chrome_interact" => {
            let _ = server
                .do_chrome_interact(serde_json::from_str(args).unwrap(), auth)
                .await;
        }
        other => panic!("no row for tool {other}"),
    }
}

/// Every MCP tool that can cause a credentialed call to go-wowa, as
/// `(tool name, arguments json)`. A `None`-marker row and an `ok_secret`
/// row run for each.
const TOOLS: &[(&str, &str)] = &[
    ("fetch", r#"{"url":"http://1.1.1.1/p","timeout":5}"#),
    ("fetch_smart", r#"{"url":"http://1.1.1.1/p"}"#),
    ("read", r#"{"url":"http://1.1.1.1/p","timeout":5}"#),
    ("readability", r#"{"url":"http://1.1.1.1/p"}"#),
    ("analyze", r#"{"url":"http://1.1.1.1/p"}"#),
    ("security_scan", r#"{"url":"http://1.1.1.1/p"}"#),
    ("site_audit", r#"{"url":"http://1.1.1.1/p"}"#),
    (
        "image_search",
        r#"{"query":"cats","engines":["bing"],"max_results":3}"#,
    ),
    (
        "reverse_image_search",
        r#"{"url":"http://1.1.1.1/i.jpg","engines":["yandex"],"max_results":3}"#,
    ),
    ("media_download", r#"{"url":"http://1.1.1.1/v"}"#),
    (
        "crawl",
        r#"{"url":"http://1.1.1.1/","max_pages":1,"max_depth":0}"#,
    ),
    (
        "solve_cf",
        r#"{"url":"http://1.1.1.1/p","challenge_type":"js_challenge"}"#,
    ),
    (
        "chrome_interact",
        r#"{"url":"http://1.1.1.1/","actions":[],"timeout_secs":5}"#,
    ),
];

/// `x-internal-secret: wowa-secret` reaches go-wowa iff the request behind
/// the tool call carried the gate's `ok_secret` marker.
///
/// Mutation (SEC-CR-018): make `chrome_interact::inbound_auth` return an
/// authenticated token unconditionally → every `marker=false` row's head
/// contains the secret → RED.
#[tokio::test]
async fn mcp_tools_relay_secret_only_when_authenticated() {
    for &(tool, args) in TOOLS {
        for ok_secret in [true, false] {
            let (wowa, captured) = ox_http::wowa_auth::capture_one(WOWA_OK).await;
            let server = server(&wowa);
            call_tool(&server, tool, args, ok_secret).await;
            let head = tokio::time::timeout(Duration::from_secs(10), captured)
                .await
                .unwrap_or_else(|_| {
                    panic!("{tool} ok_secret={ok_secret}: go-wowa was never called")
                })
                .expect("capture");
            assert_eq!(
                head.contains("x-internal-secret: wowa-secret"),
                ok_secret,
                "{tool} ok_secret={ok_secret}: {head}"
            );
        }
    }
}
