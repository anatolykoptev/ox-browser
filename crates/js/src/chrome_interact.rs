//! Chrome interact endpoints: POST /chrome/interact, DELETE /chrome/session/:id
//!
//! All Chrome operations are proxied to go-browser via HTTP.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

use super::AppState;
use crate::inbound_auth::InboundAuth;

/// Vet the caller's `proxy` in a `chrome/interact` body before it is
/// forwarded: go-wowa's Chrome dials it, so it gets the same per-request
/// validator /fetch applies (issue #189). Its refusal carries no userinfo.
///
/// go-wowa decodes the body with Go `encoding/json`, which matches object
/// keys case-insensitively, so EVERY top-level key that is `proxy` modulo
/// ASCII case is vetted (`{"Proxy": ...}` must not skip the check). A value
/// that is neither a string nor null is refused, as is more than one such
/// key (Go keeps the last; which one wins is not ours to guess). A blank
/// string means "no proxy", as it does for go-wowa.
pub fn vet_caller_proxy(body: &serde_json::Value) -> Result<(), ox_http::HttpError> {
    let refused = |msg: &str| ox_http::HttpError::InvalidUrl(format!("SSRF blocked: {msg}"));
    let Some(obj) = body.as_object() else {
        return Ok(());
    };
    let mut values = obj
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("proxy"))
        .map(|(_, v)| v);
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(refused("multiple proxy keys"));
    }
    match value {
        serde_json::Value::Null => Ok(()),
        serde_json::Value::String(s) if s.trim().is_empty() => Ok(()),
        serde_json::Value::String(s) => ox_http::validate_proxy_url(s).map(|_| ()),
        _ => Err(refused("proxy must be a string")),
    }
}

#[axum::debug_handler]
pub async fn chrome_interact_handler(
    State(state): State<AppState>,
    auth: InboundAuth,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    // go-wowa's Chrome fetches outside Tor: an onion URL anywhere in the body
    // (top-level `url` or a nested navigate action) is refused up front.
    if ox_http::tor::json_mentions_onion(&body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": ox_http::HttpError::OnionRequiresTor.to_string()})),
        );
    }
    if let Err(e) = vet_caller_proxy(&body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        );
    }
    match state
        .gobrowser_proxy
        .forward("/api/v1/chrome/interact", &body, auth)
        .await
    {
        Ok((status, resp)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(resp),
        ),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

/// DELETE /chrome/session/:id — manually destroy a persistent Chrome session.
pub async fn destroy_session_handler(
    State(state): State<AppState>,
    auth: InboundAuth,
    Path(session_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // The id is caller-supplied: refuse empty and dot-segment ids (a "."
    // or ".." segment is normalised away by URL parsers, even when
    // percent-encoded), then percent-encode it so it stays one path segment
    // on go-wowa (SEC-CR-011).
    if session_id.is_empty() || session_id == "." || session_id == ".." {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid session id"})),
        );
    }
    let id = utf8_percent_encode(&session_id, NON_ALPHANUMERIC);
    match state
        .gobrowser_proxy
        .delete(&format!("/session/{id}"), auth)
        .await
    {
        Ok((status, resp)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::NOT_FOUND),
            Json(resp),
        ),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

#[cfg(test)]
mod auth_relay_tests {
    use crate::inbound_auth::{AuthConfig, Gate, Mode, SECRET_HEADER, protect};
    use axum::body::Body;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// End to end through the gate and the REST handler: in soft mode an
    /// anonymous `/chrome/interact` is relayed to go-wowa WITHOUT ox-browser's
    /// secret; an authenticated one carries it (SEC-CR-009).
    ///
    /// Falsification: pass `InboundAuth::from_marker(Some(&Authenticated))`
    /// instead of `auth` to `forward` (or make `client_for`/the `InboundAuth`
    /// extractor yield true unconditionally) and the anonymous relay carries
    /// the secret → RED.
    #[tokio::test]
    async fn relay_secret_follows_inbound_authentication() {
        for (inbound, want_secret) in [(Some("inbound"), true), (None, false)] {
            let (url, req) = ox_http::wowa_auth::capture_one(r#"{"status":"ok"}"#).await;
            let mut state = crate::tests::test_state();
            state.gobrowser_proxy = Arc::new(crate::gobrowser_proxy::GoBrowserProxy::new(
                url,
                "wowa-secret",
            ));
            let app = protect(
                crate::router(state),
                Gate::new(AuthConfig {
                    internal_secret: "inbound".into(),
                    mcp_token: String::new(),
                    mode: Mode::Soft,
                    allow_insecure: false,
                }),
            );
            let mut b = axum::http::Request::post("/chrome/interact")
                .header("content-type", "application/json");
            if let Some(s) = inbound {
                b = b.header(SECRET_HEADER, s);
            }
            let resp = app
                .oneshot(b.body(Body::from("{}")).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "inbound={inbound:?}");
            let head = req.await.expect("capture");
            assert_eq!(
                head.contains("x-internal-secret: wowa-secret"),
                want_secret,
                "inbound={inbound:?}: {head}"
            );
        }
    }

    /// The caller-supplied session id stays one percent-encoded path segment
    /// on the go-wowa side (SEC-CR-011).
    ///
    /// Falsification: format the raw `session_id` into the path again and the
    /// captured request line carries the unencoded `?`/`/` → RED.
    #[tokio::test]
    async fn destroy_session_id_is_percent_encoded() {
        let (url, req) = ox_http::wowa_auth::capture_one(r#"{"ok":true}"#).await;
        let mut state = crate::tests::test_state();
        state.gobrowser_proxy = Arc::new(crate::gobrowser_proxy::GoBrowserProxy::new(url, ""));
        let app = crate::router(state);
        let resp = app
            .oneshot(
                axum::http::Request::delete("/chrome/session/a%3Fb%2Fc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let head = req.await.expect("capture");
        assert!(head.starts_with("delete /session/a%3fb%2fc "), "{head}");
    }

    /// Empty and dot-segment session ids are refused before go-wowa is
    /// called (SEC-CR-011).
    ///
    /// Falsification: drop the empty/"."/".." check in
    /// `destroy_session_handler` and go-wowa gets a request → RED.
    #[tokio::test]
    async fn destroy_session_refuses_dot_segments() {
        for path in [
            "/chrome/session/%2E%2E",
            "/chrome/session/.",
            "/chrome/session/%2e",
        ] {
            let (url, captured) = ox_http::wowa_auth::capture_one(r#"{"ok":true}"#).await;
            let mut state = crate::tests::test_state();
            state.gobrowser_proxy = Arc::new(crate::gobrowser_proxy::GoBrowserProxy::new(url, ""));
            let resp = crate::router(state)
                .oneshot(
                    axum::http::Request::delete(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 400, "{path}");
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(200), captured)
                    .await
                    .is_err(),
                "{path}: go-wowa was called"
            );
        }
    }

    /// #189: a caller `proxy` in the REST body is vetted by the same
    /// validator /fetch applies before go-wowa sees it — a `socks*` scheme
    /// or a malformed value is refused 400, userinfo is never echoed, and
    /// the upstream is never called.
    ///
    /// Falsification: remove the `validate_proxy_url` check in
    /// `chrome_interact_handler` → go-wowa gets the request → RED.
    #[tokio::test]
    async fn chrome_interact_refuses_an_invalid_caller_proxy() {
        for proxy in ["socks5://8.8.8.8:1080", "http://user7:pw9@exa mple:8080"] {
            let (url, captured) = ox_http::wowa_auth::capture_one(r#"{"status":"ok"}"#).await;
            let mut state = crate::tests::test_state();
            state.gobrowser_proxy = Arc::new(crate::gobrowser_proxy::GoBrowserProxy::new(url, ""));
            let body = format!(
                r#"{{"url":"https://example.com","actions":[],"proxy":{}}}"#,
                serde_json::to_string(proxy).unwrap()
            );
            let resp = crate::router(state)
                .oneshot(
                    axum::http::Request::post("/chrome/interact")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 400, "{proxy}");
            let text = String::from_utf8(
                axum::body::to_bytes(resp.into_body(), 1 << 20)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert!(text.contains("SSRF blocked"), "{proxy}: {text}");
            assert!(
                !text.contains("user7") && !text.contains("pw9"),
                "{proxy}: userinfo leaked into the refusal: {text}"
            );
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(200), captured)
                    .await
                    .is_err(),
                "{proxy}: go-wowa was called"
            );
        }
    }

    /// POST `body` to /chrome/interact against a go-wowa capture stub;
    /// returns the response status and whether go-wowa saw a request.
    async fn post_chrome_interact(body: &str) -> (u16, bool) {
        let (url, captured) = ox_http::wowa_auth::capture_one(r#"{"status":"ok"}"#).await;
        let mut state = crate::tests::test_state();
        state.gobrowser_proxy = Arc::new(crate::gobrowser_proxy::GoBrowserProxy::new(url, ""));
        let resp = crate::router(state)
            .oneshot(
                axum::http::Request::post("/chrome/interact")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let forwarded = tokio::time::timeout(std::time::Duration::from_millis(500), captured)
            .await
            .is_ok();
        (resp.status().as_u16(), forwarded)
    }

    /// Go `encoding/json` matches keys case-insensitively, so `{"Proxy":..}`
    /// reaches go-wowa as the proxy: every case variant is vetted, a
    /// non-string value is refused, and two proxy keys are refused.
    ///
    /// Falsification: revert `vet_caller_proxy` to `body.get("proxy")` →
    /// the `Proxy` / `PROXY` rows are forwarded → RED.
    #[tokio::test]
    async fn chrome_interact_vets_every_case_variant_of_the_proxy_key() {
        for body in [
            r#"{"url":"https://example.com","Proxy":"socks5://127.0.0.1:9050"}"#,
            r#"{"url":"https://example.com","PROXY":"socks5://127.0.0.1:9050"}"#,
            r#"{"url":"https://example.com","pRoXy":"http://127.0.0.1:3128"}"#,
            r#"{"url":"https://example.com","proxy":5}"#,
            r#"{"url":"https://example.com","Proxy":5}"#,
            r#"{"url":"https://example.com","proxy":["http://8.8.8.8:80"]}"#,
            r#"{"url":"https://example.com","proxy":"http://8.8.8.8:80","Proxy":"http://8.8.4.4:80"}"#,
        ] {
            let (status, forwarded) = post_chrome_interact(body).await;
            assert_eq!(status, 400, "{body}");
            assert!(!forwarded, "{body}: go-wowa was called");
        }
    }

    /// Blank / null `proxy` means "no proxy" (go-wowa treats `""` as none)
    /// and is forwarded; so is a valid public proxy under a case variant.
    #[tokio::test]
    async fn chrome_interact_blank_or_null_proxy_means_no_proxy() {
        for body in [
            r#"{"url":"https://example.com","proxy":""}"#,
            r#"{"url":"https://example.com","Proxy":"   "}"#,
            r#"{"url":"https://example.com","proxy":null}"#,
            r#"{"url":"https://example.com","Proxy":"http://8.8.8.8:3128"}"#,
        ] {
            let (status, forwarded) = post_chrome_interact(body).await;
            assert_eq!(status, 200, "{body}");
            assert!(forwarded, "{body}: go-wowa was not called");
        }
    }

    /// The DELETE call site attaches ox-browser's go-wowa secret only for an
    /// authenticated inbound caller (soft mode).
    ///
    /// Falsification: stamp the token from a literal instead of the
    /// extracted `auth` (or make the `InboundAuth` extractor yield true
    /// unconditionally) and the anonymous DELETE carries the secret → RED.
    #[tokio::test]
    async fn destroy_session_relays_secret_only_when_authenticated() {
        for (inbound, want_secret) in [(Some("inbound"), true), (None, false)] {
            let (url, captured) = ox_http::wowa_auth::capture_one(r#"{"ok":true}"#).await;
            let mut state = crate::tests::test_state();
            state.gobrowser_proxy = Arc::new(crate::gobrowser_proxy::GoBrowserProxy::new(
                url,
                "wowa-secret",
            ));
            let app = protect(
                crate::router(state),
                Gate::new(AuthConfig {
                    internal_secret: "inbound".into(),
                    mcp_token: String::new(),
                    mode: Mode::Soft,
                    allow_insecure: false,
                }),
            );
            let mut b = axum::http::Request::delete("/chrome/session/abc");
            if let Some(s) = inbound {
                b = b.header(SECRET_HEADER, s);
            }
            let resp = app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(resp.status(), 200, "inbound={inbound:?}");
            let head = captured.await.expect("capture");
            assert_eq!(
                head.contains("x-internal-secret: wowa-secret"),
                want_secret,
                "inbound={inbound:?}: {head}"
            );
        }
    }
}
