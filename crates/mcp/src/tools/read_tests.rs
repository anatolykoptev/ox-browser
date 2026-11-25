use ox_http::content::{ReadOutput, ReadParams};
use ox_http::deadline::resolve_timeout;
use std::time::Duration;

use super::ReadInput;

#[test]
fn read_params_defaults() {
    let json = r#"{"url": "https://example.com"}"#;
    let p: ReadParams = serde_json::from_str(json).unwrap();
    assert_eq!(p.format, "text");
    assert_eq!(p.max_length, 0);
}

#[test]
fn read_output_skips_none_error() {
    let out = ReadOutput {
        title: "T".into(),
        content: "C".into(),
        author: String::new(),
        excerpt: String::new(),
        url: "https://x.com".into(),
        format: "text".into(),
        length: 1,
        method: "direct".into(),
        elapsed_ms: 50,
        json_ld: Vec::new(),
        og_image: String::new(),
        published_at: String::new(),
        modified_at: String::new(),
        section: String::new(),
        site_name: String::new(),
        tags: Vec::new(),
        language: String::new(),
        error: None,
        extraction_note: None,
        quality: None,
        rate_limited: None,
    };
    let json = serde_json::to_value(&out).unwrap();
    assert!(!json.as_object().unwrap().contains_key("error"));
    assert!(!json.as_object().unwrap().contains_key("json_ld"));
}

#[test]
fn read_output_includes_error() {
    let out = ReadOutput {
        title: String::new(),
        content: String::new(),
        author: String::new(),
        excerpt: String::new(),
        url: "https://fail.com".into(),
        format: "text".into(),
        length: 0,
        method: "direct".into(),
        elapsed_ms: 10,
        json_ld: Vec::new(),
        og_image: String::new(),
        published_at: String::new(),
        modified_at: String::new(),
        section: String::new(),
        site_name: String::new(),
        tags: Vec::new(),
        language: String::new(),
        error: Some("fail".into()),
        extraction_note: None,
        quality: None,
        rate_limited: None,
    };
    let json = serde_json::to_value(&out).unwrap();
    assert_eq!(json["error"], "fail");
}

// ── WIRE-NAME PARITY (issue #139 follow-up) ───────────────────────────────────
//
// The MCP `read` tool's `ReadInput` shares the unified `timeout` field name
// with `/fetch`, `/read`, and the CLI `--timeout` flag, and accepts the
// legacy `timeout_secs` spelling via a serde alias. These assert the RESOLVED
// deadline after the `From<ReadInput> for ReadParams` mapping — not merely
// that deserialization succeeded (an unknown field deserializes fine and is
// dropped, so an Ok(_) assertion would pass on the pre-rename code).

/// MCP `read` accepts the canonical `{"timeout": 5}` and maps it through to
/// a 5 s resolved deadline. RED on the pre-rename code: `timeout` is an
/// unknown field on `ReadInput` (whose field was `timeout_secs`) → dropped
/// → `resolve_timeout(None)` = 8 s ≠ 5 s.
#[test]
fn read_input_timeout_canonical_name_resolves() {
    let input: ReadInput = serde_json::from_str(r#"{"url":"https://x.com","timeout":5}"#).unwrap();
    let params: ReadParams = input.into();
    assert_eq!(
        resolve_timeout(params.timeout),
        Duration::from_secs(5),
        "canonical `timeout` must resolve to 5s, not the 8s default"
    );
}

/// MCP `read` still accepts the legacy `{"timeout_secs": 5}` via the alias
/// and maps it to a 5 s resolved deadline. Regression guard for the alias.
#[test]
fn read_input_timeout_secs_alias_resolves() {
    let input: ReadInput =
        serde_json::from_str(r#"{"url":"https://x.com","timeout_secs":5}"#).unwrap();
    let params: ReadParams = input.into();
    assert_eq!(
        resolve_timeout(params.timeout),
        Duration::from_secs(5),
        "alias `timeout_secs` must resolve to 5s"
    );
}

/// Supplied HTML is HTTP-only: rmcp buffers the whole request before any cap
/// and logs full requests at debug level. An MCP `read` that carries `html` is
/// rejected up front, and the fetch path is never reached (counting handler);
/// the same server fetches for a request without `html` (control).
///
/// Mutation: remove the `input.html.is_some()` rejection in `read.rs` -> the
/// call fetches `url` -> RED.
#[tokio::test]
async fn mcp_read_rejects_html_and_never_fetches() {
    use async_trait::async_trait;
    use ox_http::{CookieCache, CookieProvider, Handler, HttpClient, HttpConfig};
    use ox_http::{HttpResponse, Request};
    use ox_js::gobrowser_proxy::GoBrowserProxy;
    use ox_js::inbound_auth::InboundAuth;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FETCHES: AtomicUsize = AtomicUsize::new(0);

    struct Counting;
    #[async_trait]
    impl Handler for Counting {
        async fn handle(&self, _req: Request) -> ox_http::Result<HttpResponse> {
            FETCHES.fetch_add(1, Ordering::SeqCst);
            Err(ox_http::HttpError::InvalidUrl("no network in tests".into()))
        }
    }
    struct NoSolve;
    #[async_trait]
    impl CookieProvider for NoSolve {
        async fn solve(
            &self,
            _url: &str,
            _ct: ox_http::ChallengeType,
            _authenticated: bool,
        ) -> Result<ox_http::SolvedChallenge, String> {
            Err("no solver in tests".into())
        }
    }

    let server = super::OxMcpServer::new(
        Arc::new(NoSolve),
        Arc::new(CookieCache::new(Duration::from_secs(60))),
        Arc::new(HttpClient::with_chain(
            Arc::new(Counting),
            HttpConfig::default(),
        )),
        ox_js::EndpointDefaults::default(),
        ox_media::MediaConfig::default(),
        Arc::new(GoBrowserProxy::new("http://127.0.0.1:1".to_owned(), "")),
    );
    let auth =
        || -> InboundAuth { crate::tools::chrome_interact::inbound_auth(&Default::default()) };

    let with_html: ReadInput =
        serde_json::from_str(r#"{"url":"http://1.1.1.1/p","html":"<p>hi</p>"}"#).unwrap();
    let err = server.do_read(with_html, auth()).await.unwrap_err();
    assert!(
        err.message.contains("HTTP-only"),
        "unexpected error: {err:?}"
    );
    assert_eq!(FETCHES.load(Ordering::SeqCst), 0, "html request fetched");

    // Control: without html the same server does reach the transport.
    let plain: ReadInput = serde_json::from_str(r#"{"url":"http://1.1.1.1/p"}"#).unwrap();
    let _ = server.do_read(plain, auth()).await;
    assert_eq!(FETCHES.load(Ordering::SeqCst), 1, "control must fetch");
}
