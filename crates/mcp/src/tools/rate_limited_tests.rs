//! A local rate-limit refusal (`HttpError::RateLimited`: the next permit is
//! due after the call's deadline) must reach MCP callers as a typed
//! `rate_limited` result with `retry_after_s`, never a bare error string.
//!
//! Each tool is called twice against a 1-permit/600 s limiter: the first call
//! takes the permit, the second must be refused at once (no sleeping: the wait
//! exceeds the call's deadline, or the 120 s ceiling for the one tool that has
//! no deadline of its own). Dropping the typed field in any `do_*` (fetch,
//! fetch_smart, read) turns that row RED.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ox_http::{
    CookieCache, DomainConfig, DomainLimiter, Handler, HttpClient, HttpConfig, HttpResponse,
    Request,
};
use ox_js::gobrowser_proxy::GoBrowserProxy;

use super::chrome_interact;
use super::*;

const WINDOW_SECS: u64 = 600;

struct Origin;

#[async_trait]
impl Handler for Origin {
    async fn handle(&self, req: Request) -> ox_http::Result<HttpResponse> {
        Ok(HttpResponse {
            status: 200,
            url: req.url,
            headers: Default::default(),
            body: "<html><head><title>T</title></head><body><p>body text long enough to count as content for the extractor</p></body></html>".into(),
        })
    }
}

struct NoSolver;

#[async_trait]
impl ox_http::CookieProvider for NoSolver {
    async fn solve(
        &self,
        _url: &str,
        _ct: ox_http::ChallengeType,
        _authenticated: bool,
    ) -> Result<ox_http::SolvedChallenge, String> {
        Err("no solver in tests".into())
    }
}

fn server() -> OxMcpServer {
    let limiter = Arc::new(DomainLimiter::new(vec![DomainConfig {
        domain: String::new(),
        requests_per_window: 1,
        window_duration: Duration::from_secs(WINDOW_SECS),
        min_delay: Duration::ZERO,
        random_delay: Duration::ZERO,
    }]));
    let http = HttpClient::with_chain(
        Arc::new(Origin),
        HttpConfig {
            retry: None,
            cloudflare_detect: false,
            quality_check: false,
            rate_limiter: Some(limiter),
            ..HttpConfig::default()
        },
    );
    let proxy = Arc::new(GoBrowserProxy::new("http://127.0.0.1:1".to_owned(), ""));
    OxMcpServer::new(
        Arc::new(NoSolver),
        Arc::new(CookieCache::new(Duration::from_secs(60))),
        Arc::new(http),
        EndpointDefaults::default(),
        ox_media::MediaConfig::default(),
        proxy,
    )
}

fn auth() -> ox_js::inbound_auth::InboundAuth {
    chrome_interact::inbound_auth(&Extensions::new())
}

fn json_of(res: &CallToolResult) -> serde_json::Value {
    let text = serde_json::to_string(res).expect("serialize");
    let v: serde_json::Value = serde_json::from_str(&text).expect("json");
    let inner = v["content"][0]["text"].as_str().expect("text content");
    serde_json::from_str(inner).expect("tool json")
}

fn assert_refusal(tool: &str, res: &CallToolResult) {
    assert_eq!(res.is_error, Some(true), "{tool}: not an error result");
    let v = json_of(res);
    let secs = v["rate_limited"]["retry_after_s"]
        .as_u64()
        .unwrap_or_else(|| panic!("{tool}: no typed rate_limited.retry_after_s in {v}"));
    assert!(
        (WINDOW_SECS - 1..=WINDOW_SECS).contains(&secs),
        "{tool}: retry_after_s {secs}"
    );
    assert_eq!(v["rate_limited"]["rule"], "catch_all", "{tool}: {v}");
    assert!(
        v["error"].as_str().unwrap_or_default().contains("limiter"),
        "{tool}: error text {v}"
    );
}

#[tokio::test]
async fn mcp_fetch_returns_a_typed_rate_limited_result() {
    let s = server();
    let input = || serde_json::from_str(r#"{"url":"http://1.1.1.1/a"}"#).unwrap();
    let first = s.do_fetch(input(), auth()).await.expect("first");
    assert_eq!(first.is_error, Some(false), "first call takes the permit");
    let second = s.do_fetch(input(), auth()).await.expect("second");
    assert_refusal("fetch", &second);
}

#[tokio::test]
async fn mcp_fetch_smart_returns_a_typed_rate_limited_result() {
    let s = server();
    let input =
        || serde_json::from_str(r#"{"url":"http://1.1.1.1/a","save_to_file":false}"#).unwrap();
    let first = s.do_fetch_smart(input(), auth()).await.expect("first");
    assert_eq!(first.is_error, Some(false), "first call takes the permit");
    let second = s.do_fetch_smart(input(), auth()).await.expect("second");
    assert_refusal("fetch_smart", &second);
}

#[tokio::test]
async fn mcp_read_returns_a_typed_rate_limited_result() {
    let s = server();
    let input = || serde_json::from_str(r#"{"url":"http://1.1.1.1/a","timeout":2}"#).unwrap();
    let first = s.do_read(input(), auth()).await.expect("first");
    assert_eq!(first.is_error, Some(false), "first call takes the permit");
    let second = s.do_read(input(), auth()).await.expect("second");
    assert_refusal("read", &second);
}
