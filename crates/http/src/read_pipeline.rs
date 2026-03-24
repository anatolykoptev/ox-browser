//! Shared read pipeline — async fetch + extract + quality fallback.
//!
//! Called by both MCP and REST layers.

use std::time::{Duration, Instant};

use url::Url;

use crate::content::{self, ContentFormat, ReadOutput, ReadParams};
use crate::cookie_cache::CookieCache;
use crate::cookie_provider::CookieProvider;
use crate::ChallengeType;
use crate::HttpClient;

/// Overall timeout for the entire read pipeline (fetch + extract + headless fallback).
const PIPELINE_TIMEOUT: Duration = Duration::from_secs(30);

/// Execute the full read pipeline with a 30s overall timeout.
pub async fn read_page(
    http: &HttpClient,
    provider: &dyn CookieProvider,
    cache: &CookieCache,
    params: &ReadParams,
) -> ReadOutput {
    match tokio::time::timeout(
        PIPELINE_TIMEOUT,
        read_page_inner(http, provider, cache, params),
    ).await {
        Ok(output) => output,
        Err(_) => build_error_output(params, "direct", PIPELINE_TIMEOUT.as_millis() as u64, "read pipeline timeout"),
    }
}

async fn read_page_inner(
    http: &HttpClient,
    provider: &dyn CookieProvider,
    cache: &CookieCache,
    params: &ReadParams,
) -> ReadOutput {
    let start = Instant::now();
    let format = ContentFormat::from_param(&params.format);

    let resp = match http.get(&params.url).await {
        Ok(r) => r,
        Err(e) => return build_error_output(params, "direct", elapsed(start), &e.to_string()),
    };

    if resp.status != 200 {
        if content::should_fallback(resp.status) {
            return headless_read(http, provider, cache, params, format, start).await;
        }
        return build_error_output(
            params,
            "direct",
            elapsed(start),
            &format!("HTTP {}", resp.status),
        );
    }

    let extracted = content::extract_content(&resp.body, &params.url, format);

    if content::is_low_quality(&resp.body, &extracted.content) {
        tracing::info!(url = %params.url, "low quality content, trying headless");
        return headless_read(http, provider, cache, params, format, start).await;
    }

    build_output(extracted, params, "direct", elapsed(start))
}

async fn headless_read(
    http: &HttpClient,
    provider: &dyn CookieProvider,
    cache: &CookieCache,
    params: &ReadParams,
    format: ContentFormat,
    start: Instant,
) -> ReadOutput {
    let domain = Url::parse(&params.url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default();

    let solved = match provider.solve(&params.url, ChallengeType::JsChallenge).await {
        Ok(s) => s,
        Err(e) => {
            return build_error_output(
                params,
                "solved",
                elapsed(start),
                &format!("headless solve failed: {e}"),
            )
        }
    };
    cache.put(&domain, solved.clone());

    // If solver returned the page body directly, use it (avoids IP mismatch on retry)
    if let Some(ref body) = solved.body {
        let extracted = content::extract_content(body, &params.url, format);
        return build_output(extracted, params, "solved", elapsed(start));
    }

    // No body — retry with cookies (may fail if IP differs between solver and wreq)
    match http.get(&params.url).await {
        Ok(retry) if retry.status == 200 => {
            let extracted = content::extract_content(&retry.body, &params.url, format);
            build_output(extracted, params, "solved", elapsed(start))
        }
        Ok(retry) => build_error_output(
            params,
            "solved",
            elapsed(start),
            &format!("HTTP {} after solve", retry.status),
        ),
        Err(e) => build_error_output(
            params,
            "solved",
            elapsed(start),
            &format!("retry: {e}"),
        ),
    }
}

pub fn build_output(
    ext: content::ExtractedContent,
    params: &ReadParams,
    method: &str,
    ms: u64,
) -> ReadOutput {
    let mut c = ext.content;
    if params.max_length > 0 {
        c = content::truncate_utf8(&c, params.max_length);
    }
    let length = c.len();
    ReadOutput {
        title: ext.title,
        content: c,
        author: ext.author,
        excerpt: ext.excerpt,
        url: params.url.clone(),
        format: params.format.clone(),
        length,
        method: method.into(),
        elapsed_ms: ms,
        json_ld: ext.json_ld,
        og_image: ext.og_image,
        error: None,
    }
}

pub fn build_error_output(params: &ReadParams, method: &str, ms: u64, msg: &str) -> ReadOutput {
    ReadOutput {
        title: String::new(),
        content: String::new(),
        author: String::new(),
        excerpt: String::new(),
        url: params.url.clone(),
        format: params.format.clone(),
        length: 0,
        method: method.into(),
        elapsed_ms: ms,
        json_ld: Vec::new(),
        og_image: String::new(),
        error: Some(msg.into()),
    }
}

fn elapsed(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

#[cfg(test)]
#[path = "read_pipeline_tests.rs"]
mod tests;
