//! Router-level per-call deadline for the REST surfaces that do not wrap
//! themselves in `deadline::bounded` (issue #147): one layer bounds the
//! whole handler future — retries, solver escalation, multi-engine
//! fan-out — as a unit, so coverage does not depend on a hand-maintained
//! list of which handlers remembered the seam.
//!
//! The caller-supplied `timeout`/`timeout_secs` field is pulled out of the
//! JSON body here; each route's input type stays opaque to the layer.
//! Bodies are buffered under a cap — these routes take small JSON arg
//! objects, and a body that cannot be read fails closed — 413 when it
//! exceeds the cap, 400 on a mid-read failure — rather than bypassing
//! the bound.
//!
//! The deadline default is PER ROUTE (`route_default_secs`), sized at
//! least to each surface's own inner designed bound: the fetch-calibrated
//! `DEFAULT_CALL_TIMEOUT_SECS` (8 s) would make every fresh CF solve
//! 504 — `provider.solve` is configured for up to 120 s behind Byparr
//! (`byparr_timeout_secs`). A caller's `timeout` may tighten the bound
//! but can never extend past the designed default.
//!
//! `/fetch` and `/read` are NOT mounted behind this layer: they bound
//! internally and map `CallOutcome` to route-specific error bodies a
//! generic 504 cannot reproduce — a second, outer bound would only
//! shadow that mapping. `/crawl` is excluded deliberately: it answers
//! SSE — the request resolves when the stream is produced, so a
//! request-level bound would cover only the discovery phase while
//! looking like it covers the crawl. Its discovery await is bounded
//! inside the handler instead.

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http_body_util::LengthLimitError;
use ox_http::deadline::{
    CHROME_PROXY_BOUND_SECS, CallOutcome, MEDIA_DOWNLOAD_BOUND_SECS, SOLVER_CALL_BOUND_SECS,
    bounded, resolve_timeout_for, timeout_from_json,
};
use serde_json::json;

/// Cap on the buffered request body. Every input behind this layer is a
/// small JSON arg object — 4 MiB is far past the largest legitimate one
/// (a chrome_interact script), and an oversize body gets 413, not an
/// unbounded pass.
const BODY_CAP: usize = 4 * 1024 * 1024;

/// The designed per-call bound for a guarded route — the deadline
/// `resolve_timeout_for` falls back to and clamps caller input at.
/// `SOLVER_CALL_BOUND_SECS` is the catch-all: every route behind this
/// layer goes through `http_client`, whose middleware chain escalates to
/// `provider.solve` — sized to the largest configured provider timeout
/// (`byparr_timeout_secs` = 120 s) plus the fetch itself.
fn route_default_secs(path: &str) -> u64 {
    if path == "/media/download" {
        MEDIA_DOWNLOAD_BOUND_SECS
    } else if path.starts_with("/chrome/") {
        CHROME_PROXY_BOUND_SECS
    } else {
        SOLVER_CALL_BOUND_SECS
    }
}

/// Bound the whole call — not one attempt; semantics and the in-flight
/// gauge come from [`bounded`]. `DeadlineExceeded` renders as a uniform
/// 504 JSON error; routes needing a typed deadline body keep their own
/// internal bound instead of this layer.
pub async fn deadline_guard(req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let default_secs = route_default_secs(parts.uri.path());
    let bytes = match to_bytes(body, BODY_CAP).await {
        Ok(b) => b,
        Err(e) => {
            // Oversize body -> 413; a truncated upload or reset connection
            // is a client read failure -> 400, not "too large".
            let oversize = std::error::Error::source(&e)
                .and_then(|s| s.downcast_ref::<LengthLimitError>())
                .is_some();
            return if oversize {
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(json!({"error": "request body exceeds 4 MiB"})),
                )
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("failed to read request body: {e}")})),
                )
            }
            .into_response();
        }
    };
    let caller = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(timeout_from_json);
    let req = Request::from_parts(parts, Body::from(bytes));
    match bounded(resolve_timeout_for(caller, default_secs), next.run(req)).await {
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

    fn guarded(handler: axum::routing::MethodRouter, path: &str) -> Router {
        Router::new()
            .route(path, handler)
            .layer(axum::middleware::from_fn(deadline_guard))
    }

    fn post_json(path: &str, body: &str) -> Request {
        Request::post(path)
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
            guarded(post(sleepy), "/solve").oneshot(post_json("/solve", r#"{"timeout": 1}"#)),
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
            guarded(post(sleepy), "/solve").oneshot(post_json("/solve", r#"{"timeout_secs": 1}"#)),
        )
        .await
        .expect("guard must bound the call")
        .unwrap();
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn guard_passes_fast_handler_through() {
        let resp = guarded(post(fast), "/analyze")
            .oneshot(post_json("/analyze", r#"{"timeout": 5}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A body that fails mid-read is a client error, not "too large":
    /// the layer must answer 400, not 413.
    #[tokio::test]
    async fn guard_maps_body_read_failure_to_400() {
        let body = Body::from_stream(async_stream::stream! {
            yield Ok::<&'static str, std::io::Error>("{}");
            yield Err::<&'static str, std::io::Error>(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "reset mid-body",
            ));
        });
        let resp = guarded(post(fast), "/analyze")
            .oneshot(
                Request::post("/analyze")
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn guard_rejects_oversize_body() {
        let big = "x".repeat(BODY_CAP + 1);
        let resp = guarded(post(fast), "/analyze")
            .oneshot(
                Request::post("/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(big))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn route_defaults_size_to_inner_designed_bounds() {
        assert_eq!(route_default_secs("/solve"), SOLVER_CALL_BOUND_SECS);
        assert_eq!(route_default_secs("/analyze"), SOLVER_CALL_BOUND_SECS);
        assert_eq!(
            route_default_secs("/media/download"),
            MEDIA_DOWNLOAD_BOUND_SECS
        );
        assert_eq!(
            route_default_secs("/chrome/interact"),
            CHROME_PROXY_BOUND_SECS
        );
        assert_eq!(
            route_default_secs("/chrome/session/abc"),
            CHROME_PROXY_BOUND_SECS
        );
    }
}
