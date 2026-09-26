//! Router-level per-call deadline for the REST surfaces that do not wrap
//! themselves in `deadline::bounded` (issue #147): one layer bounds the
//! whole handler future — retries, solver escalation, multi-engine
//! fan-out — as a unit, so coverage does not depend on a hand-maintained
//! list of which handlers remembered the seam.
//!
//! The caller-supplied `timeout`/`timeout_secs` field is pulled out of the
//! JSON body here; each route's input type stays opaque to the layer.
//! Bodies are buffered under a cap — these routes take small JSON arg
//! objects, and an oversize body fails closed with 413 rather than
//! bypassing the bound.
//!
//! `/fetch` and `/read` are NOT mounted behind this layer: they bound
//! internally and map `CallOutcome` to route-specific error bodies a
//! generic 504 cannot reproduce — a second, outer bound would only
//! shadow that mapping.

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ox_http::deadline::{CallOutcome, bounded, resolve_timeout, timeout_from_json};
use serde_json::json;

/// Cap on the buffered request body. Every input behind this layer is a
/// small JSON arg object — 4 MiB is far past the largest legitimate one
/// (a chrome_interact script), and an oversize body gets 413, not an
/// unbounded pass.
const BODY_CAP: usize = 4 * 1024 * 1024;

/// Bound the whole call — not one attempt; semantics and the in-flight
/// gauge come from [`bounded`]. `DeadlineExceeded` renders as a uniform
/// 504 JSON error; routes needing a typed deadline body keep their own
/// internal bound instead of this layer.
pub async fn deadline_guard(req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = match to_bytes(body, BODY_CAP).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"error": "request body exceeds 4 MiB"})),
            )
                .into_response();
        }
    };
    let caller = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(timeout_from_json);
    let req = Request::from_parts(parts, Body::from(bytes));
    match bounded(resolve_timeout(caller), next.run(req)).await {
        CallOutcome::Ok(resp) => resp,
        CallOutcome::DeadlineExceeded { secs } => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({"error": format!("deadline exceeded ({secs}s per-call bound)")})),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::post;
    use http_body_util::BodyExt;
    use std::time::Duration;
    use tower::ServiceExt;

    async fn sleepy() -> &'static str {
        tokio::time::sleep(Duration::from_secs(30)).await;
        "done"
    }

    async fn fast() -> &'static str {
        "done"
    }

    fn guarded(handler: axum::routing::MethodRouter) -> Router {
        Router::new()
            .route("/x", handler)
            .layer(axum::middleware::from_fn(deadline_guard))
    }

    fn post_json(body: &str) -> Request {
        Request::post("/x")
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    /// Caller `timeout: 1` must bound a 30 s handler to ~1 s — and a
    /// missing layer would hang this test for the full 30 s.
    #[tokio::test]
    async fn guard_bounds_slow_handler_at_caller_timeout() {
        let start = std::time::Instant::now();
        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            guarded(post(sleepy)).oneshot(post_json(r#"{"timeout": 1}"#)),
        )
        .await
        .expect("guard must bound the call")
        .unwrap();
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("deadline exceeded (1s"));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn guard_accepts_timeout_secs_alias() {
        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            guarded(post(sleepy)).oneshot(post_json(r#"{"timeout_secs": 1}"#)),
        )
        .await
        .expect("guard must bound the call")
        .unwrap();
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn guard_passes_fast_handler_through() {
        let resp = guarded(post(fast))
            .oneshot(post_json(r#"{"timeout": 5}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A non-JSON body can't yield a caller timeout, but the default bound
    /// still applies — fail-closed, never unbounded.
    #[tokio::test]
    async fn guard_bounds_non_json_body_at_default() {
        let resp = tokio::time::timeout(
            Duration::from_secs(20),
            guarded(post(sleepy)).oneshot(
                Request::post("/x")
                    .header("content-type", "text/plain")
                    .body(Body::from("not json"))
                    .unwrap(),
            ),
        )
        .await
        .expect("default bound must still fire")
        .unwrap();
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn guard_rejects_oversize_body() {
        let big = "x".repeat(BODY_CAP + 1);
        let resp = guarded(post(fast))
            .oneshot(
                Request::post("/x")
                    .header("content-type", "application/json")
                    .body(Body::from(big))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
