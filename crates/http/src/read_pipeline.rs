//! Shared read pipeline — async fetch + extract via middleware chain.
//!
//! Called by both MCP and REST layers.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::content::{self, ContentFormat, ReadOutput, ReadParams};
use crate::HttpClient;

/// Overall timeout for the entire read pipeline (fetch + extract).
const PIPELINE_TIMEOUT: Duration = Duration::from_secs(30);

/// A site-specific handler: takes (params, format, start) → Option<ReadOutput>.
/// Injected from outside ox-http to avoid circular dependencies.
pub type SiteHandler = Arc<
    dyn Fn(ReadParams, ContentFormat, Instant) -> Pin<Box<dyn Future<Output = Option<ReadOutput>> + Send>>
        + Send
        + Sync,
>;

/// Execute the full read pipeline with a 30s overall timeout.
pub async fn read_page(
    http: &HttpClient,
    params: &ReadParams,
    site_handlers: &[SiteHandler],
) -> ReadOutput {
    match tokio::time::timeout(
        PIPELINE_TIMEOUT,
        read_page_inner(http, params, site_handlers),
    ).await {
        Ok(output) => output,
        Err(_) => build_error_output(params, "direct", PIPELINE_TIMEOUT.as_millis() as u64, "read pipeline timeout"),
    }
}

async fn read_page_inner(
    http: &HttpClient,
    params: &ReadParams,
    site_handlers: &[SiteHandler],
) -> ReadOutput {
    let start = Instant::now();
    let format = ContentFormat::from_param(&params.format);

    // External site-specific handlers (injected to avoid circular deps).
    for handler in site_handlers {
        if let Some(output) = handler(params.clone(), format, start).await {
            return output;
        }
    }

    // Site-specific handlers (rewrite URL, still go through middleware chain)
    if let Some(output) = crate::site_reddit::try_reddit_json(http, params, format, start).await {
        return output;
    }

    // All requests go through middleware chain:
    // CF detect → quality check → residential retry → solver (with body passthrough)
    let resp = match http.get(&params.url).await {
        Ok(r) => r,
        Err(e) => return build_error_output(params, "direct", elapsed(start), &e.to_string()),
    };

    if resp.status != 200 {
        return build_error_output(
            params,
            "direct",
            elapsed(start),
            &format!("HTTP {}", resp.status),
        );
    }

    let extracted = content::extract_content(&resp.body, &params.url, format);
    build_output(extracted, params, "direct", elapsed(start))
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
        published_at: ext.meta.published_at,
        modified_at: ext.meta.modified_at,
        section: ext.meta.section,
        site_name: ext.meta.site_name,
        tags: ext.meta.tags,
        language: ext.meta.language,
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
        published_at: String::new(),
        modified_at: String::new(),
        section: String::new(),
        site_name: String::new(),
        tags: Vec::new(),
        language: String::new(),
        error: Some(msg.into()),
    }
}

pub fn elapsed(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

#[cfg(test)]
#[path = "read_pipeline_tests.rs"]
mod tests;
