//! Shared REST mapping of a local rate-limit refusal (`HttpError::RateLimited`):
//! HTTP 429 plus a real `Retry-After` header, the same on every route.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};

/// The status a refusal answers with.
pub(crate) const STATUS: StatusCode = StatusCode::TOO_MANY_REQUESTS;

/// A header map carrying `Retry-After: <secs>`.
pub(crate) fn retry_after_headers(secs: u64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
        headers.insert(header::RETRY_AFTER, v);
    }
    headers
}
