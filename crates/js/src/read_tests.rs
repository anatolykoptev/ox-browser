use ox_http::content::ReadParams;

#[test]
fn read_params_deserializes_with_defaults() {
    let json = r#"{"url": "https://example.com"}"#;
    let p: ReadParams = serde_json::from_str(json).unwrap();
    assert_eq!(p.url, "https://example.com");
    assert_eq!(p.format, "text");
    assert_eq!(p.max_length, 0);
}

#[test]
fn read_params_with_markdown() {
    let json = r#"{"url": "https://x.com", "format": "markdown", "max_length": 1000}"#;
    let p: ReadParams = serde_json::from_str(json).unwrap();
    assert_eq!(p.format, "markdown");
    assert_eq!(p.max_length, 1000);
}

#[test]
fn read_params_with_llm_format() {
    let json = r#"{"url": "https://x.com", "format": "llm"}"#;
    let p: ReadParams = serde_json::from_str(json).unwrap();
    assert_eq!(p.format, "llm");
}

/// `/read` reports a `quality` verdict next to the unchanged fields, and the
/// verdict does not alter `content`.
#[tokio::test]
async fn read_reports_quality_additively() {
    use async_trait::async_trait;
    use ox_http::{Handler, HttpClient, HttpConfig, HttpResponse, Request, read_pipeline};
    use std::sync::Arc;

    struct DeniedStub;
    #[async_trait]
    impl Handler for DeniedStub {
        async fn handle(&self, req: Request) -> ox_http::Result<HttpResponse> {
            Ok(HttpResponse {
                status: 200,
                url: req.url,
                headers: Default::default(),
                body: "<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1><p>You don't have permission to access this page.</p></body></html>".into(),
            })
        }
    }
    let http = HttpClient::with_chain(
        Arc::new(DeniedStub),
        HttpConfig {
            quality_check: true,
            cloudflare_detect: false,
            ..HttpConfig::default()
        },
    );
    let params: ReadParams =
        serde_json::from_str(r#"{"url":"http://1.1.1.1/x","format":"markdown"}"#).unwrap();
    let out = read_pipeline::read_page(&http, &params, &[]).await;
    assert!(out.error.is_none(), "{:?}", out.error);
    assert!(out.content.contains("permission"), "content unchanged");
    let v = serde_json::to_value(&out).unwrap();
    assert_eq!(v["quality"]["verdict"], "access_denied", "{v}");
    for k in [
        "title",
        "content",
        "url",
        "format",
        "length",
        "method",
        "elapsed_ms",
    ] {
        assert!(v.get(k).is_some(), "existing field {k} must stay");
    }
}

/// Supplied HTML through the REAL router: no transport call of any kind. The
/// terminal handler, the site handlers and the CF provider all count their
/// calls; a control request without `html` proves the counters are live.
///
/// Mutation: in `read.rs` route a supplied request through `read_page` (drop
/// the `params.html.is_some()` branch and the read_page guard) -> the origin
/// counter is nonzero -> RED.
#[tokio::test]
async fn supplied_html_makes_no_outbound_call_through_the_router() {
    use async_trait::async_trait;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use ox_http::{
        ChallengeType, CookieCache, CookieProvider, Handler, HttpClient, HttpConfig, HttpResponse,
        Request, SolvedChallenge,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    static ORIGIN_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SITE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SOLVER_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct Origin;
    #[async_trait]
    impl Handler for Origin {
        async fn handle(&self, req: Request) -> ox_http::Result<HttpResponse> {
            ORIGIN_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(HttpResponse {
                status: 200,
                url: req.url,
                headers: Default::default(),
                body: "<html><head><title>Fetched</title></head><body><p>fetched body text that is long enough to count as content for the extractor</p></body></html>".into(),
            })
        }
    }
    struct Provider;
    #[async_trait]
    impl CookieProvider for Provider {
        async fn solve(
            &self,
            _url: &str,
            _ct: ChallengeType,
            _authenticated: bool,
        ) -> Result<SolvedChallenge, String> {
            SOLVER_CALLS.fetch_add(1, Ordering::SeqCst);
            Err("solver must not run".into())
        }
    }

    let client = HttpClient::with_chain(
        Arc::new(Origin),
        HttpConfig {
            cloudflare_detect: false,
            ..HttpConfig::default()
        },
    );
    let proxy = Arc::new(crate::gobrowser_proxy::GoBrowserProxy::new(
        "http://127.0.0.1:1".to_string(),
        "",
    ));
    let mut state = crate::AppState::new(
        Arc::new(Provider),
        Arc::new(CookieCache::new(std::time::Duration::from_secs(300))),
        Arc::new(client),
        crate::EndpointDefaults::default(),
        ox_media::MediaConfig::default(),
        proxy,
    );
    let counting_site: ox_http::read_pipeline::SiteHandler = Arc::new(|_p, _f, _s| {
        SITE_CALLS.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { None })
    });
    state.site_handlers = Arc::new(vec![counting_site]);
    let app = crate::router(state);

    let post = |body: serde_json::Value| {
        axum::http::Request::builder()
            .method("POST")
            .uri("/read")
            .header("content-type", "application/json")
            .header("host", "localhost")
            .body(Body::from(body.to_string()))
            .unwrap()
    };

    // Supplied: served locally, nothing outbound.
    let resp = app
        .clone()
        .oneshot(post(serde_json::json!({
            "url": "http://1.1.1.1/biz",
            "format": "markdown",
            "html": "<html><head><title>Supplied</title></head><body><h1>Supplied page</h1><p>Supplied body text that is long enough to count as content for the extractor.</p></body></html>",
        })))
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let v: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(v["method"], "supplied", "{v}");
    assert_eq!(v["title"], "Supplied", "{v}");
    assert!(
        v["content"]
            .as_str()
            .unwrap()
            .contains("Supplied body text")
    );
    assert_eq!(ORIGIN_CALLS.load(Ordering::SeqCst), 0, "origin was fetched");
    assert_eq!(SITE_CALLS.load(Ordering::SeqCst), 0, "site handler ran");
    assert_eq!(SOLVER_CALLS.load(Ordering::SeqCst), 0, "solver ran");

    // Over the cap: 413, still nothing outbound.
    let big = "x".repeat(ox_http::read_pipeline::supplied_html_max_bytes() + 1);
    let resp = app
        .clone()
        .oneshot(post(
            serde_json::json!({"url": "http://1.1.1.1/biz", "html": big}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(ORIGIN_CALLS.load(Ordering::SeqCst), 0);

    // Control: the same route WITHOUT html does reach the transport, so the
    // zero counters above mean something.
    let resp = app
        .oneshot(post(serde_json::json!({"url": "http://1.1.1.1/biz"})))
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    assert_eq!(ORIGIN_CALLS.load(Ordering::SeqCst), 1, "control must fetch");
    assert_eq!(
        SITE_CALLS.load(Ordering::SeqCst),
        1,
        "control runs site handlers"
    );
}
