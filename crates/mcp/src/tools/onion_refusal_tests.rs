//! MCP twin of the REST `onion_refusal_tests`: `solve_cf`, `chrome_interact`,
//! `reverse_image_search` and readability's headless fallback refuse an onion
//! URL before any call to a third party. Each call goes through the tool's
//! `do_*` (the production entry the `#[tool]` handlers delegate to) with the
//! upstreams being counting stubs that must see ZERO requests; a clearnet
//! control per tool proves the counters are live.
//!
//! Mutation: remove the `refuse_onion_for_third_party` / `json_mentions_onion`
//! check in one `do_*` (solve.rs, chrome_interact.rs, reverse_search.rs,
//! readability.rs `headless_fetch`) and that tool's row goes RED.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use ox_http::solver_gobrowser::{GoBrowserConfig, GoBrowserSolver};
use ox_http::{
    CookieCache, CookieProvider, Handler, HttpClient, HttpConfig, HttpResponse, Request,
};
use ox_js::gobrowser_proxy::GoBrowserProxy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::chrome_interact;
use super::*;

const WOWA_OK: &str = r#"{"status":"ok","cookies":{"cf_clearance":"t"},"user_agent":"UA"}"#;

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

struct CountingHandler(Arc<AtomicUsize>);

#[async_trait]
impl Handler for CountingHandler {
    async fn handle(&self, _req: Request) -> ox_http::Result<HttpResponse> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ox_http::HttpError::InvalidUrl("no network in tests".into()))
    }
}

fn server(wowa: &str, client_hits: Arc<AtomicUsize>) -> OxMcpServer {
    let provider: Arc<dyn CookieProvider> = Arc::new(GoBrowserSolver::new(GoBrowserConfig {
        base_url: wowa.to_owned(),
        timeout: Duration::from_secs(5),
        internal_secret: "wowa-secret".into(),
    }));
    let http = HttpClient::with_chain(
        Arc::new(CountingHandler(client_hits)),
        HttpConfig::default(),
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

fn auth() -> ox_js::inbound_auth::InboundAuth {
    chrome_interact::inbound_auth(&Extensions::new())
}

/// (tool, onion args, clearnet control args, upstream is the go-wowa stub)
const TOOLS: &[(&str, &str, &str, bool)] = &[
    (
        "solve_cf",
        r#"{"url":"https://foo.onion/","challenge_type":"js_challenge"}"#,
        r#"{"url":"http://1.1.1.1/p","challenge_type":"js_challenge"}"#,
        true,
    ),
    (
        "chrome_interact",
        r#"{"url":"https://FOO.ONION./","actions":[],"timeout_secs":5}"#,
        r#"{"url":"http://1.1.1.1/","actions":[],"timeout_secs":5}"#,
        true,
    ),
    (
        "reverse_image_search",
        r#"{"url":"https://foo.onion/i.jpg","engines":["yandex"]}"#,
        r#"{"url":"http://1.1.1.1/i.jpg","engines":["yandex"]}"#,
        false,
    ),
];

async fn call(server: &OxMcpServer, tool: &str, args: &str) -> CallToolResult {
    match tool {
        "solve_cf" => server
            .do_solve_cf(serde_json::from_str(args).unwrap(), auth())
            .await
            .expect("tool result"),
        "chrome_interact" => server
            .do_chrome_interact(serde_json::from_str(args).unwrap(), auth())
            .await
            .expect("tool result"),
        "reverse_image_search" => server
            .do_reverse_search(serde_json::from_str(args).unwrap(), auth())
            .await
            .expect("tool result"),
        other => panic!("no row for {other}"),
    }
}

#[tokio::test]
async fn mcp_third_party_tools_refuse_onion_urls_before_any_outbound_call() {
    for &(tool, onion, clearnet, via_wowa) in TOOLS {
        let (wowa, wowa_hits) = counting_wowa().await;
        let client_hits = Arc::new(AtomicUsize::new(0));
        let res = call(&server(&wowa, Arc::clone(&client_hits)), tool, onion).await;
        let text = serde_json::to_string(&res).expect("serialize");
        assert_eq!(
            res.is_error,
            Some(true),
            "{tool}: not an error result: {text}"
        );
        assert!(text.contains("onion_requires_tor"), "{tool}: {text}");
        assert_eq!(
            wowa_hits.load(Ordering::SeqCst),
            0,
            "{tool}: go-wowa stub called"
        );
        assert_eq!(
            client_hits.load(Ordering::SeqCst),
            0,
            "{tool}: shared client called"
        );

        // Control: the clearnet twin reaches its upstream.
        let (wowa, wowa_hits) = counting_wowa().await;
        let client_hits = Arc::new(AtomicUsize::new(0));
        let _ = call(&server(&wowa, Arc::clone(&client_hits)), tool, clearnet).await;
        let reached = if via_wowa {
            wowa_hits.load(Ordering::SeqCst)
        } else {
            client_hits.load(Ordering::SeqCst)
        };
        assert!(reached >= 1, "{tool}: control did not reach its upstream");
    }
}

/// Readability's headless fallback calls the solver directly; an onion URL is
/// refused there too, with the solver stub untouched.
#[tokio::test]
async fn mcp_readability_headless_fallback_refuses_onion() {
    let (wowa, wowa_hits) = counting_wowa().await;
    let s = server(&wowa, Arc::new(AtomicUsize::new(0)));
    let err = s
        .headless_fetch("https://foo.onion/", auth())
        .await
        .expect_err("onion must be refused");
    assert!(err.starts_with("onion_requires_tor"), "{err}");
    assert_eq!(wowa_hits.load(Ordering::SeqCst), 0);
}

/// A blank `proxy` means "no proxy" (go-wowa treats `""` as none): it is
/// forwarded, not refused as an unparsable proxy URL.
///
/// Falsification: drop the blank arm in `ox_js::vet_caller_proxy` →
/// `validate_proxy_url("")` refuses → the stub counts 0 → RED.
#[tokio::test]
async fn mcp_chrome_interact_blank_proxy_means_no_proxy() {
    for proxy in ["", "   "] {
        let (wowa, wowa_hits) = counting_wowa().await;
        let s = server(&wowa, Arc::new(AtomicUsize::new(0)));
        let args = format!(
            r#"{{"url":"https://example.com","actions":[],"timeout_secs":5,"proxy":{}}}"#,
            serde_json::to_string(proxy).unwrap()
        );
        let _ = s
            .do_chrome_interact(serde_json::from_str(&args).unwrap(), auth())
            .await
            .expect("tool result");
        assert!(
            wowa_hits.load(Ordering::SeqCst) >= 1,
            "{proxy:?}: a blank proxy was refused instead of forwarded"
        );
    }
}

/// #189: `chrome_interact`'s caller-supplied `proxy` goes through the same
/// validator /fetch applies before go-wowa sees it — a `socks*` scheme or a
/// malformed value is refused, userinfo is never echoed, and the stub is
/// never called.
///
/// Falsification: remove the `validate_proxy_url` call in
/// `chrome_interact::do_chrome_interact` → the bad proxy is forwarded and
/// the wowa stub counts a request → RED.
#[tokio::test]
async fn mcp_chrome_interact_refuses_an_invalid_caller_proxy() {
    for proxy in [
        "socks5://8.8.8.8:1080",
        "http://user7:pw9@exa mple:8080",
        "not a url",
    ] {
        let (wowa, wowa_hits) = counting_wowa().await;
        let s = server(&wowa, Arc::new(AtomicUsize::new(0)));
        let args = format!(
            r#"{{"url":"https://example.com","actions":[],"timeout_secs":5,"proxy":{}}}"#,
            serde_json::to_string(proxy).unwrap()
        );
        let res = s
            .do_chrome_interact(serde_json::from_str(&args).unwrap(), auth())
            .await
            .expect("tool result");
        let text = serde_json::to_string(&res).expect("serialize");
        assert_eq!(
            res.is_error,
            Some(true),
            "{proxy}: not an error result: {text}"
        );
        assert!(
            text.contains("SSRF blocked"),
            "{proxy}: the refusal must carry the validator error: {text}"
        );
        assert!(
            !text.contains("user7") && !text.contains("pw9"),
            "{proxy}: userinfo leaked into the refusal: {text}"
        );
        assert_eq!(
            wowa_hits.load(Ordering::SeqCst),
            0,
            "{proxy}: go-wowa stub called"
        );
    }

    // Control: a valid public proxy is forwarded untouched.
    let (wowa, wowa_hits) = counting_wowa().await;
    let s = server(&wowa, Arc::new(AtomicUsize::new(0)));
    let _ = s
        .do_chrome_interact(
            serde_json::from_str(
                r#"{"url":"https://example.com","actions":[],"timeout_secs":5,"proxy":"http://8.8.8.8:3128"}"#,
            )
            .unwrap(),
            auth(),
        )
        .await
        .expect("tool result");
    assert!(
        wowa_hits.load(Ordering::SeqCst) >= 1,
        "control never reached go-wowa"
    );
}
