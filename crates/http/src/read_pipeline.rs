//! Shared read pipeline — async fetch + extract via middleware chain.
//!
//! Called by both MCP and REST layers.
//!
//! The read pipeline always fetches with GET — the extraction stage
//! assumes a document retrieved by a navigation-style GET. Method/body
//! support lives on `/fetch` and the CLI `fetch` subcommand only (issue
//! #114); it is intentionally NOT inherited here.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::HttpClient;
use crate::content::{self, ContentFormat, ReadOutput, ReadParams};
use crate::render_cache::RenderMode;

/// Overall timeout for the entire read pipeline (fetch + extract).
const PIPELINE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum chrome-render response body (50 MB — a rendered page DOM is the
/// same class as the main fetch path's 50 MB cap). The chrome-render service
/// is our own, but "it is our own service" is the assumption that stops
/// holding the day something upstream breaks (issue #119).
const CHROME_RENDER_MAX_BODY_BYTES: u64 = 50 * 1024 * 1024;

/// A site-specific handler: takes (params, format, start) → Option<ReadOutput>.
/// Injected from outside ox-http to avoid circular dependencies.
pub type SiteHandler = Arc<
    dyn Fn(
            ReadParams,
            ContentFormat,
            Instant,
        ) -> Pin<Box<dyn Future<Output = Option<ReadOutput>> + Send>>
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
    )
    .await
    {
        Ok(output) => output,
        Err(_) => build_error_output(
            params,
            "direct",
            PIPELINE_TIMEOUT.as_millis() as u64,
            "read pipeline timeout",
        ),
    }
}

async fn read_page_inner(
    http: &HttpClient,
    params: &ReadParams,
    site_handlers: &[SiteHandler],
) -> ReadOutput {
    let start = Instant::now();
    crate::metrics::record_fetch();
    let format = ContentFormat::from_param(&params.format);

    // External site-specific handlers (injected to avoid circular deps).
    for handler in site_handlers {
        if let Some(output) = handler(params.clone(), format, start).await {
            if output.error.is_none() {
                crate::metrics::record_fetch_success();
            }
            return output;
        }
    }

    // Site-specific handlers (rewrite URL, still go through middleware chain)
    if let Some(output) = crate::site_reddit::try_reddit_json(http, params, format, start).await {
        if output.error.is_none() {
            crate::metrics::record_fetch_success();
        }
        return output;
    }

    let config = http.config();
    let chrome_url = config.chrome_render_url.clone();
    let render_cache = config.render_cache.clone();

    // Check render cache: if domain is known to need Chrome or has given up, act accordingly.
    let domain = extract_domain(&params.url);
    if let (Some(cache), Some(url)) = (&render_cache, &chrome_url) {
        match cache.get(&domain) {
            Some(RenderMode::GiveUp) => {
                // BUG A fix: re-check the negcache. If the cooldown has lifted (is_blocked
                // now returns false), remove the GiveUp entry and fall through to a normal
                // fetch. If still blocked, fast-fail as before.
                // This makes the 300s negcache cooldown authoritative over the 3600s
                // RenderModeCache TTL — a domain whose solver recovers at t=300s is no
                // longer black-holed until t=3600s.
                let still_blocked = http
                    .config()
                    .solver_negcache
                    .as_ref()
                    .is_some_and(|nc| nc.is_blocked(&domain));
                if still_blocked {
                    tracing::debug!(domain = %domain, "render cache hit: GiveUp (negcache still blocked) — fast-failing");
                    return build_error_output(
                        params,
                        "direct",
                        elapsed(start),
                        "solver negcache: domain on cooldown (GiveUp)",
                    );
                } else {
                    // Cooldown lifted — remove stale GiveUp and proceed normally.
                    tracing::info!(domain = %domain, "render cache GiveUp evicted: negcache cooldown lifted — retrying fetch");
                    cache.remove(&domain);
                    // Fall through to the http.get() path below.
                }
            }
            Some(RenderMode::Chrome) => {
                tracing::debug!(domain = %domain, "render cache hit: Chrome");
                if let Some(output) = chrome_fallback(url, params, format, start).await {
                    crate::metrics::record_fetch_success();
                    return output;
                }
                // Chrome fallback failed — fall through to HTTP as last resort
            }
            _ => {}
        }
    } else if let Some(cache) = &render_cache
        && cache.get(&domain) == Some(RenderMode::GiveUp)
    {
        let still_blocked = http
            .config()
            .solver_negcache
            .as_ref()
            .is_some_and(|nc| nc.is_blocked(&domain));
        if still_blocked {
            tracing::debug!(domain = %domain, "render cache hit: GiveUp (no chrome_url) — fast-failing");
            return build_error_output(
                params,
                "direct",
                elapsed(start),
                "solver negcache: domain on cooldown (GiveUp)",
            );
        } else {
            tracing::info!(domain = %domain, "render cache GiveUp evicted (no chrome_url): negcache cooldown lifted");
            cache.remove(&domain);
        }
    }

    // All requests go through middleware chain:
    // CF detect → quality check → residential retry → solver (with body passthrough)
    let resp = match http.get(&params.url).await {
        Ok(r) => r,
        Err(e) => {
            // On Cloudflare error (genuine or inferred) → check negcache; if
            // domain is on cooldown set GiveUp so the next request fast-fails
            // before reaching chrome_fallback.
            if matches!(
                e,
                crate::HttpError::Cloudflare(_, _, _) | crate::HttpError::CloudflareInferred(_, _)
            ) && let (Some(cache), Some(url)) = (&render_cache, &chrome_url)
            {
                let negcache_blocked = http
                    .config()
                    .solver_negcache
                    .as_ref()
                    .is_some_and(|nc| nc.is_blocked(&domain));
                if negcache_blocked {
                    tracing::info!(domain = %domain, "CF error + negcache blocked → marking GiveUp, fast-failing");
                    cache.set(&domain, RenderMode::GiveUp);
                } else {
                    tracing::info!(domain = %domain, "CF error on HTTP fetch → marking Chrome, retrying via Chrome fallback");
                    cache.set(&domain, RenderMode::Chrome);
                    if let Some(output) = chrome_fallback(url, params, format, start).await {
                        crate::metrics::record_fetch_success();
                        return output;
                    }
                }
            }
            return build_error_output(params, "direct", elapsed(start), &e.to_string());
        }
    };

    if resp.status != 200 {
        return build_error_output(
            params,
            "direct",
            elapsed(start),
            &format!("HTTP {}", resp.status),
        );
    }

    // Detect JS-only shells after a successful HTTP fetch.
    if crate::content_detect::needs_js_rendering(&resp.body)
        && let (Some(cache), Some(url)) = (&render_cache, &chrome_url)
    {
        tracing::info!(domain = %domain, "JS shell detected → marking Chrome, retrying via Chrome fallback");
        cache.set(&domain, RenderMode::Chrome);
        if let Some(output) = chrome_fallback(url, params, format, start).await {
            crate::metrics::record_fetch_success();
            return output;
        }
    }

    crate::metrics::record_fetch_success();
    let extracted = content::extract_content(&resp.body, &params.url, format);
    build_output(extracted, params, "direct", elapsed(start))
}

/// Call go-wowa chrome/interact to fetch a JS-rendered page.
async fn chrome_fallback(
    chrome_url: &str,
    params: &ReadParams,
    format: ContentFormat,
    start: Instant,
) -> Option<ReadOutput> {
    let body = serde_json::json!({
        "url": params.url,
        "actions": [
            {"type": "wait_for", "wait_ms": 4000},
            {"type": "evaluate", "script": "document.documentElement.outerHTML"}
        ],
        "timeout_secs": 15
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .ok()?;

    let resp = client.post(chrome_url).json(&body).send().await.ok()?;

    if !resp.status().is_success() {
        tracing::warn!(url = %params.url, status = %resp.status(), "Chrome fallback failed");
        return None;
    }

    // Body cap (issue #119): stream the response body with a running-total
    // byte cap instead of `resp.json()` which reads the full body unbounded.
    // The cap and counter route through the same body_cap ceiling as #118.
    let text = crate::body_cap::read_text_capped_reqwest(resp, CHROME_RENDER_MAX_BODY_BYTES)
        .await
        .ok()?;
    let data: serde_json::Value = serde_json::from_str(&text).ok()?;

    // Extract HTML from the evaluate action result
    let html = data["actions"]
        .as_array()?
        .iter()
        .find(|a| a["action"].as_str() == Some("evaluate"))
        .and_then(|a| a["data"].as_str())?;

    if html.is_empty() {
        return None;
    }

    let extracted = content::extract_content(html, &params.url, format);
    Some(build_output(extracted, params, "chrome", elapsed(start)))
}

/// Extract the hostname from a URL (delegates to [`crate::url_util::extract_domain`]).
fn extract_domain(url: &str) -> String {
    crate::url_util::extract_domain(url).unwrap_or_default()
}

pub fn build_output(
    ext: content::ExtractedContent,
    params: &ReadParams,
    method: &str,
    ms: u64,
) -> ReadOutput {
    let format = content::ContentFormat::from_param(&params.format);
    let mut c = ext.content;

    // LLM format: post-process the markdown through the LLM cleanup pipeline.
    // This strips images/emphasis/CSS/JS noise, moves links to a footer, and
    // gates JSON-LD — producing token-optimized text for LLM consumption.
    if format == content::ContentFormat::Llm {
        let raw_output = ReadOutput {
            title: ext.title.clone(),
            content: std::mem::take(&mut c),
            author: ext.author.clone(),
            excerpt: ext.excerpt.clone(),
            url: params.url.clone(),
            format: params.format.clone(),
            length: 0,
            method: method.into(),
            elapsed_ms: ms,
            json_ld: ext.json_ld.clone(),
            og_image: ext.og_image.clone(),
            published_at: ext.meta.published_at.clone(),
            modified_at: ext.meta.modified_at.clone(),
            section: ext.meta.section.clone(),
            site_name: ext.meta.site_name.clone(),
            tags: ext.meta.tags.clone(),
            language: ext.meta.language.clone(),
            error: None,
            extraction_note: ext.extraction_note.clone(),
        };
        c = crate::llm::to_llm_text(&raw_output);
    }

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
        extraction_note: ext.extraction_note,
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
        extraction_note: None,
    }
}

pub fn elapsed(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

#[cfg(test)]
#[path = "read_pipeline_tests.rs"]
mod tests;
