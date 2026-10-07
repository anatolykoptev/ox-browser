//! Chrome interact endpoints: POST /chrome/interact, DELETE /chrome/session/:id
//!
//! All Chrome operations are proxied to go-browser via HTTP.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

use super::AppState;
use crate::inbound_auth::Authenticated;

#[axum::debug_handler]
pub async fn chrome_interact_handler(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state
        .gobrowser_proxy
        .forward("/api/v1/chrome/interact", &body, auth.is_some())
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
    auth: Option<Extension<Authenticated>>,
    Path(session_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // The id is caller-supplied: percent-encode it so it stays one path
    // segment and cannot steer the request elsewhere on go-wowa (SEC-CR-011).
    let id = utf8_percent_encode(&session_id, NON_ALPHANUMERIC);
    match state
        .gobrowser_proxy
        .delete(&format!("/session/{id}"), auth.is_some())
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
    /// Falsification: pass `true` instead of `auth.is_some()` in
    /// `chrome_interact_handler` and the anonymous relay carries the secret → RED.
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
}
