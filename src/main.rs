mod config;
mod serve;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ox_core::{Browser, BrowserConfig};
use ox_http::{ProfileFilter, StaticPool, random_profile};

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
                let filter = ProfileFilter {
                    browser: Some(browser_name.clone()),
                    ..Default::default()
                };
                cfg.profile = Some(random_profile(&filter));
            }

            if let Some(proxy_url) = proxy {
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
