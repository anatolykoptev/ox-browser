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
