//! POST /readability endpoint — extract article content from a URL.
//!
//! Two-stage fetch: fast wreq first, headless fallback on 401/403/429/503.
//! DEPRECATED: Use POST /read instead.

use std::time::Instant;

use axum::http::StatusCode;
use axum::{Json, extract::State};
use ox_http::ChallengeType;
use serde::{Deserialize, Serialize};
use url::Url;

use super::AppState;
use crate::inbound_auth::InboundAuth;

#[derive(Deserialize)]
pub struct ReadabilityRequest {
    pub url: String,
    /// Return content as plain text instead of HTML. Default: true.
    #[serde(default = "default_true")]
    pub plain_text: bool,
    /// Maximum content length in chars. 0 = unlimited. Default: 0.
    #[serde(default)]
    pub max_length: usize,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
pub struct ReadabilityResponse {
    pub title: String,
    pub content: String,
    pub author: String,
    pub excerpt: String,
    pub length: usize,
    pub elapsed_ms: u64,
    /// "direct" or "solved" (headless fallback was used).
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn readability(
    State(state): State<AppState>,
    auth: InboundAuth,
    Json(req): Json<ReadabilityRequest>,
) -> (StatusCode, Json<ReadabilityResponse>) {
    let start = Instant::now();
    // ox-browser#177 / SEC-CR-018: `client_for` stamps the gate's
    // `ok_secret` decision — see `fetch`. The same token feeds
    // `headless_fetch`'s provider call and retry GET.
    let http = state.client_for(auth);

    let resp = match http.get(&req.url).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(error_response(
                    start,
                    "direct",
                    &format!("fetch failed: {e}"),
                )),
            );
        }
    };

    let (html, method) = if resp.status == 200 {
        (resp.body, "direct")
    } else if ox_http::content::should_fallback(resp.status) {
        tracing::info!(
            url = %req.url,
            status = resp.status,
            "readability: non-200, attempting headless fallback"
        );
        match headless_fetch(&state, &req.url, auth).await {
            Ok(body) => (body, "solved"),
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(error_response(
                        start,
                        "solved",
                        &format!("HTTP {} + fallback: {e}", resp.status),
                    )),
                );
            }
        }
    } else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(error_response(
                start,
                "direct",
                &format!("HTTP {}", resp.status),
            )),
        );
    };

    let format = if req.plain_text {
        ox_http::content::ContentFormat::Text
    } else {
        ox_http::content::ContentFormat::Html
    };
    let extracted = ox_http::content::extract_content(&html, &req.url, format);
    let mut content = extracted.content;
    if req.max_length > 0 {
        content = ox_http::content::truncate_utf8(&content, req.max_length);
    }
    let length = content.len();

    (
        StatusCode::OK,
        Json(ReadabilityResponse {
            title: extracted.title,
            content,
            author: extracted.author,
            excerpt: extracted.excerpt,
            length,
            elapsed_ms: start.elapsed().as_millis() as u64,
            method: method.into(),
            error: None,
        }),
    )
}

/// Solve via headless browser, cache cookies, retry GET.
///
/// `auth` is the inbound gate decision token — the provider's secret-relay
/// gate and the retry client's stamp both derive from it at the sink, so
/// this path cannot be given a literal `true` (SEC-CR-018).
async fn headless_fetch(state: &AppState, url: &str, auth: InboundAuth) -> Result<String, String> {
    let domain = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default();

    let solved = state
        .provider
        .solve(url, ChallengeType::JsChallenge, auth.is_authenticated())
        .await?;
    state.cache.put(&domain, solved);

    tracing::info!(domain = %domain, "headless solved, retrying GET");
    let retry = state
        .client_for(auth)
        .get(url)
        .await
        .map_err(|e| format!("retry after solve: {e}"))?;

    if retry.status != 200 {
        return Err(format!("retry got HTTP {}", retry.status));
    }
    Ok(retry.body)
}

fn error_response(start: Instant, method: &str, msg: &str) -> ReadabilityResponse {
    ReadabilityResponse {
        title: String::new(),
        content: String::new(),
        author: String::new(),
        excerpt: String::new(),
        length: 0,
        elapsed_ms: start.elapsed().as_millis() as u64,
        method: method.into(),
        error: Some(msg.into()),
    }
}
