mod config;
mod read;
mod serve;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ox_core::{Browser, BrowserConfig};
use ox_http::{BrowserProfile, HttpClient, HttpConfig, ProfileFilter, StaticPool, random_profile};

/// Select a builtin browser profile matching the host OS for the given
/// browser name. Shared by `fetch` and `read` (and future CLI subcommands)
/// so the CLI and service select the same profile for the same name
/// (Issue #81: one identity). Behaviour is identical to the previous inline
/// `fetch` logic — extracted, not changed.
fn select_profile(browser_name: &str) -> &'static BrowserProfile {
    let filter = ProfileFilter {
        browser: Some(browser_name.to_string()),
        os: Some(std::env::consts::OS.to_string()),
        mobile: Some(false),
    };
    random_profile(&filter)
}

/// Build a one-shot [`HttpClient`] for CLI subcommands from the profile/proxy
/// knobs shared across `fetch`/`read`/future `crawl`/`analyze`. The second
/// consumer is a one-line call, not a second copy of the plumbing.
///
/// No cookie cache / render cache / solver negcache / proxy pool are wired
/// (a one-shot CLI read has no cross-request state to share); every one of
/// those is `Option`-guarded in `read_page_inner`, so their absence degrades
/// gracefully. `GO_BROWSER_URL` is honoured so JS-heavy pages escalate to
/// chrome render the same way as the server when that env var is set.
pub(crate) fn build_cli_http_client(
    profile: Option<&str>,
    proxy: Option<String>,
    debug: bool,
) -> anyhow::Result<HttpClient> {
    let mut cfg = HttpConfig::default();

    if let Some(browser_name) = profile {
        cfg.profile = Some(select_profile(browser_name));
    }

    if !config::proxy_disabled()
        && let Some(proxy_url) = proxy
    {
        let pool = StaticPool::new(vec![proxy_url]);
        cfg.proxy_pool = Some(Arc::new(pool));
    }

    if let Ok(url) = std::env::var("GO_BROWSER_URL")
        && !url.is_empty()
    {
        cfg.chrome_render_url = Some(format!("{url}/api/v1/chrome/interact"));
    }

    cfg.debug = debug;

    Ok(HttpClient::new(cfg)?)
}

#[derive(Parser)]
#[command(name = "ox-browser", version, about = "Lightweight headless browser")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch a URL and output content
    Fetch {
        /// URL to fetch
        url: String,
        /// CSS selector to extract
        #[arg(long)]
        css: Option<String>,
        /// Output plain text instead of HTML
        #[arg(long)]
        text: bool,
        /// Browser profile: chrome, firefox, safari, edge
        #[arg(long)]
        profile: Option<String>,
        /// Proxy URL (e.g. http://user:pass@host:port)
        #[arg(long)]
        proxy: Option<String>,
        /// Enable debug logging for HTTP requests
        #[arg(long)]
        debug: bool,
    },
    /// Read a URL through the content-extraction pipeline (readability,
    /// format conversion, LLM cleanup, chrome-render escalation). Same
    /// pipeline as POST /read and the MCP `read` tool.
    Read {
        /// URL to read
        url: String,
        /// Output format: text (default), markdown, html, llm
        #[arg(long, default_value = "text")]
        format: String,
        /// Max content length in chars (0 = unlimited)
        #[arg(long, default_value_t = 0)]
        max_length: usize,
        /// Browser profile: chrome, firefox, safari, edge
        #[arg(long)]
        profile: Option<String>,
        /// Proxy URL (e.g. http://user:pass@host:port)
        #[arg(long)]
        proxy: Option<String>,
        /// Emit the full ReadOutput as JSON (pipeable to jq)
        #[arg(long)]
        json: bool,
        /// Enable debug logging for HTTP requests
        #[arg(long)]
        debug: bool,
    },
    /// Start HTTP API server
    Serve {
        /// Path to config file
        #[arg(long, env = "OX_BROWSER_CONFIG", default_value = "config.toml")]
        config: PathBuf,
        /// Port to listen on (overrides config file)
        #[arg(long, env = "OX_PORT")]
        port: Option<u16>,
        /// Byparr/FlareSolverr URL for challenge solving (overrides config)
        #[arg(long, env = "BYPARR_URL")]
        byparr_url: Option<String>,
        /// Proxy URL (overrides config)
        #[arg(long, env = "PROXY_URL")]
        proxy_url: Option<String>,
        /// Enable debug logging (overrides config)
        #[arg(long)]
        debug: bool,
    },
    /// Show version info
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Fetch {
            url,
            css,
            text,
            profile,
            proxy,
            debug,
        } => {
            let mut cfg = BrowserConfig::default();

            if let Some(browser_name) = &profile {
                // Match the host OS so the CLI and service select the same
                // profile for the same browser name. (Issue #81: one identity)
                cfg.profile = Some(select_profile(browser_name));
            }

            if !config::proxy_disabled()
                && let Some(proxy_url) = proxy
            {
                let pool = StaticPool::new(vec![proxy_url]);
                cfg.proxy_pool = Some(Arc::new(pool));
            }

            cfg.debug = debug;

            let browser = Browser::new(cfg)?;
            let page = browser.page(&url).await?;

            if let Some(selector) = css {
                let sel = page.select(&selector);
                for node in sel.iter() {
                    if text {
                        println!("{}", node.text());
                    } else {
                        println!("{}", node.html());
                    }
                }
            } else if text {
                println!("{}", page.text());
            } else {
                println!("{}", page.html());
            }
        }
        Commands::Read {
            url,
            format,
            max_length,
            profile,
            proxy,
            json,
            debug,
        } => {
            let args = read::ReadArgs {
                url,
                format,
                max_length,
                profile,
                proxy,
                json,
                debug,
            };
            read::run(args).await?;
        }
        Commands::Serve {
            config: config_path,
            port,
            byparr_url,
            proxy_url,
            debug,
        } => {
            let mut server_config = config::ServerConfig::load(&config_path)?;
            server_config.apply_cli_overrides(port, byparr_url, proxy_url, debug);
            serve::run(server_config).await?;
        }
        Commands::Version => {
            println!("ox-browser {}", env!("CARGO_PKG_VERSION"));
        }
    }
    Ok(())
}
