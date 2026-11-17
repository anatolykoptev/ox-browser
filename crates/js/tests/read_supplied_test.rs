//! `read_supplied`: caller-supplied HTML goes through the same extraction as a
//! fetched page, with no transport involved.
//!
//! Parity oracle: the fetched side serves the same bytes through a real
//! `HttpClient` chain (stub terminal handler standing in for the origin
//! server) and `read_page`; every field except `method` / `elapsed_ms` must be
//! identical for text, markdown, llm and html, `json_ld` and `quality`
//! included.

use std::sync::Arc;

use async_trait::async_trait;
use ox_http::content::ReadParams;
use ox_http::read_pipeline::{
    SuppliedError, read_page, read_supplied, read_supplied_capped, read_supplied_with,
};
use ox_http::{Handler, HttpClient, HttpConfig, HttpResponse, Request};

const FIXTURE: &str = include_str!("fixtures/supplied_page.html");
const URL: &str = "http://1.1.1.1/page";

struct Origin;

#[async_trait]
impl Handler for Origin {
    async fn handle(&self, req: Request) -> ox_http::Result<HttpResponse> {
        Ok(HttpResponse {
            status: 200,
            url: req.url,
            headers: Default::default(),
            body: FIXTURE.into(),
        })
    }
}

fn params(format: &str, html: Option<&str>) -> ReadParams {
    serde_json::from_value(serde_json::json!({
        "url": URL, "format": format, "html": html,
    }))
    .unwrap()
}

fn client() -> HttpClient {
    HttpClient::with_chain(
        Arc::new(Origin),
        HttpConfig {
            quality_check: true,
            cloudflare_detect: false,
            ..HttpConfig::default()
        },
    )
}

fn normalized(out: &ox_http::content::ReadOutput) -> serde_json::Value {
    let mut v = serde_json::to_value(out).unwrap();
    let o = v.as_object_mut().unwrap();
    o.remove("method");
    o.remove("elapsed_ms");
    v
}

#[tokio::test]
async fn supplied_matches_fetched_for_every_format() {
    for format in ["text", "markdown", "llm", "html"] {
        let fetched = read_page(&client(), &params(format, None), &[]).await;
        let supplied = read_supplied(&params(format, Some(FIXTURE)))
            .await
            .expect("supplied html accepted");

        assert!(fetched.error.is_none(), "{format}: {:?}", fetched.error);
        assert!(supplied.error.is_none(), "{format}: {:?}", supplied.error);
        assert_eq!(fetched.method, "direct");
        assert_eq!(supplied.method, "supplied");
        assert_eq!(
            normalized(&supplied),
            normalized(&fetched),
            "{format}: supplied output differs from fetched output"
        );
        // The oracle is not vacuous: real content and metadata came through.
        assert!(
            supplied.content.contains("family-owned plumbing"),
            "{format}"
        );
        assert_eq!(supplied.json_ld.len(), 1, "{format}");
        assert_eq!(supplied.json_ld[0]["name"], "Example Plumbing Co");
        assert_eq!(supplied.og_image, "https://example.com/cover.png");
        assert_eq!(supplied.title, "Example Plumbing Co");
        assert_eq!(supplied.url, URL);
    }
}

#[tokio::test]
async fn supplied_text_keeps_block_separation() {
    let out = read_supplied(&params("text", Some(FIXTURE))).await.unwrap();
    assert!(
        out.content
            .contains("Emergency repairs\nWater heaters\nDrain cleaning"),
        "{:?}",
        out.content
    );
}

#[tokio::test]
async fn over_cap_is_rejected_413() {
    let html = "x".repeat(101);
    let p = params("text", Some(&html));
    let err = read_supplied_capped(&p, 100).await.unwrap_err();
    assert_eq!(err, SuppliedError::TooLarge { len: 101, cap: 100 });
    assert_eq!(err.status_code(), 413);
    // At the cap exactly is accepted.
    let ok = params("text", Some(&"x".repeat(100)));
    assert!(read_supplied_capped(&ok, 100).await.is_ok());
}

#[tokio::test]
async fn invalid_url_is_rejected_400() {
    let p: ReadParams =
        serde_json::from_value(serde_json::json!({"url": "not a url", "html": "<p>x</p>"}))
            .unwrap();
    let err = read_supplied(&p).await.unwrap_err();
    assert_eq!(err, SuppliedError::InvalidUrl);
    assert_eq!(err.status_code(), 400);
}

/// `read_page` must never fetch `url` for a request that carries HTML.
#[tokio::test]
async fn read_page_refuses_supplied_html() {
    struct Boom;
    #[async_trait]
    impl Handler for Boom {
        async fn handle(&self, _req: Request) -> ox_http::Result<HttpResponse> {
            panic!("read_page fetched a request that carried supplied html");
        }
    }
    let http = HttpClient::with_chain(Arc::new(Boom), HttpConfig::default());
    let out = read_page(&http, &params("text", Some(FIXTURE)), &[]).await;
    assert!(out.error.is_some());
}

/// Admission bound: with every permit held the next request is shed with 503
/// before a copy of the HTML or a blocking task exists; permits come back when
/// work finishes.
#[tokio::test]
async fn supplied_extraction_sheds_load_when_permits_are_exhausted() {
    use tokio::sync::Semaphore;
    let limiter = Arc::new(Semaphore::new(2));
    let held = Arc::clone(&limiter).try_acquire_many_owned(2).unwrap();
    let p = params("text", Some(FIXTURE));

    let err = read_supplied_with(&p, 1 << 20, &limiter).await.unwrap_err();
    assert_eq!(err, SuppliedError::Busy);
    assert_eq!(err.status_code(), 503);
    assert_eq!(
        limiter.available_permits(),
        0,
        "rejected request took a permit"
    );

    drop(held);
    let out = read_supplied_with(&p, 1 << 20, &limiter).await.unwrap();
    assert_eq!(out.method, "supplied");
    assert_eq!(
        limiter.available_permits(),
        2,
        "permit leaked after the work"
    );
}

#[test]
fn supplied_error_statuses() {
    assert_eq!(
        SuppliedError::DeadlineExceeded { secs: 8 }.status_code(),
        504
    );
    assert_eq!(SuppliedError::Internal.status_code(), 500);
}
