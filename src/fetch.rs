//! `fetch` subcommand — CLI surface for a raw page fetch with optional
//! CSS-selector extraction or plain-text output.
//!
//! Uses `ox_core::Browser` (the same construction path the service uses
//! for non-pipeline fetches), so the CLI and service present the same
//! identity for the same config (Issue #102).

use std::sync::Arc;

use ox_core::{Browser, BrowserConfig};
use ox_http::StaticPool;

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

    let browser = Browser::new(cfg)?;
    let page = browser.page(&args.url).await?;

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
