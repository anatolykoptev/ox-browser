//! `fetch` subcommand — CLI surface for a raw page fetch with optional
//! CSS-selector extraction or plain-text output.
//!
//! Uses `ox_core::Browser` (the same construction path the service uses
//! for non-pipeline fetches), so the CLI and service present the same
//! identity for the same config (Issue #102).

use std::sync::Arc;

use ox_core::{Browser, BrowserConfig};
use ox_http::StaticPool;
use ox_http::deadline::{CallOutcome, bounded, resolve_timeout};

use crate::cli::resolve_cli_profile;
use crate::config;

/// Arguments for the `fetch` subcommand, parsed by clap in `main.rs`.
pub struct FetchArgs {
    pub url: String,
    pub css: Option<String>,
    pub text: bool,
    pub profile: Option<String>,
    pub proxy: Option<String>,
    pub debug: bool,
    /// HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE).
    /// Defaults to GET, or POST when `--data` is supplied (curl convention).
    pub method: Option<String>,
    /// Request body. Implies POST when `--method` is not set. Rejected when
    /// `--method GET` is explicit.
    pub data: Option<String>,
    /// Content-Type for the body. Defaults to `application/json` when a
    /// body is present. Ignored when no body.
    pub content_type: Option<String>,
    /// Per-call deadline in seconds (`--timeout`). `None` → seam default;
    /// `Some(s)` → clamped to `[1, MAX_CALL_TIMEOUT_SECS]`. Bounds the
    /// whole call, not one attempt (issue #139).
    pub timeout: Option<u64>,
}

/// Run the `fetch` subcommand.
///
/// Output contract:
/// - `--css <sel>`: for each matching node, print `node.html()` (or
///   `node.text()` if `--text`);
/// - `--text` (no `--css`): print `page.text()`;
/// - default: print `page.html()`;
/// - on error: reason → stderr (via the returned `Err`), exit non-zero.
pub async fn run(args: FetchArgs) -> anyhow::Result<()> {
    let mut cfg = BrowserConfig {
        profile: resolve_cli_profile(args.profile.as_deref())?,
        debug: args.debug,
        ..BrowserConfig::default()
    };

    if !config::proxy_disabled()
        && let Some(proxy_url) = args.proxy
    {
        let pool = StaticPool::new(vec![proxy_url]);
        cfg.proxy_pool = Some(Arc::new(pool));
    }

    // Resolve method: --method > (POST when --data, else GET).
    let body_bytes = args.data.as_deref().map(|d| d.as_bytes().to_vec());
    let method = args
        .method
        .as_deref()
        .map(|m| m.to_string())
        .unwrap_or_else(|| {
            if body_bytes.is_some() {
                "POST".into()
            } else {
                "GET".into()
            }
        });

    // Reject body with explicit GET.
    if body_bytes.is_some() && method.eq_ignore_ascii_case("GET") {
        anyhow::bail!("--data is not allowed with method GET");
    }

    // Content type: --content-type > default application/json (when body).
    let content_type = if body_bytes.is_some() {
        Some(
            args.content_type
                .unwrap_or_else(|| "application/json".to_string()),
        )
    } else {
        None
    };

    let browser = Browser::new(cfg)?;
    // Bound the whole call (retry loop + solver escalation + rate-limit
    // wait), not one attempt — issue #139. Browser::request routes through
    // HttpClient::request, so the same seam bounds the CLI as the service.
    let deadline = resolve_timeout(args.timeout);
    let page = match bounded(
        deadline,
        browser.request(&method, &args.url, body_bytes, content_type.as_deref()),
    )
    .await
    {
        CallOutcome::Ok(Ok(page)) => page,
        CallOutcome::Ok(Err(e)) => return Err(e.into()),
        CallOutcome::DeadlineExceeded { secs } => {
            anyhow::bail!("deadline exceeded ({secs}s per-call bound)");
        }
    };

    if let Some(selector) = args.css {
        let sel = page.select(&selector);
        for node in sel.iter() {
            if args.text {
                println!("{}", node.text());
            } else {
                println!("{}", node.html());
            }
        }
    } else if args.text {
        println!("{}", page.text());
    } else {
        println!("{}", page.html());
    }
    Ok(())
}
