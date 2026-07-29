mod cli;
mod config;
mod doctor;
mod fetch;
mod read;
mod serve;

// Re-exported so `read.rs` keeps its `use crate::build_cli_http_client;`
// import unchanged — the helper lives in `cli.rs` now.
pub(crate) use cli::build_cli_http_client;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
        /// HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE).
        /// Defaults to GET, or POST when --data is supplied (curl convention).
        #[arg(short = 'X', long)]
        method: Option<String>,
        /// Request body. Implies POST when --method is not set.
        /// Rejected when --method GET is explicit.
        #[arg(long, alias = "body")]
        data: Option<String>,
        /// Content-Type for the body (default: application/json).
        /// Ignored when no --data.
        #[arg(long)]
        content_type: Option<String>,
        /// Per-call deadline in seconds. None → seam default (8s);
        /// clamped to [1, 60]. Bounds the whole call, not one attempt.
        #[arg(long)]
        timeout: Option<u64>,
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
        /// Per-call deadline in seconds. None → seam default (8s);
        /// clamped to [1, 60]. Bounds the whole read pipeline, not one
        /// attempt.
        #[arg(long)]
        timeout: Option<u64>,
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
    /// Self-check the running instance: fingerprint against the embedded
    /// reference, reference age, config validity, solver / chrome-render /
    /// proxy reachability. Makes live calls to third-party echo services —
    /// runs only when invoked explicitly, never from `serve` or a health
    /// check (issue #109).
    Doctor {
        /// Override the proxy URL (else taken from config.toml `[proxy]`).
        #[arg(long)]
        proxy: Option<String>,
        /// Enable debug logging for the measured HTTP requests.
        #[arg(long)]
        debug: bool,
        /// Emit the structured verdict as JSON on stdout (pipeable to jq).
        #[arg(long)]
        json: bool,
    },
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
            method,
            data,
            content_type,
            timeout,
        } => {
            let args = fetch::FetchArgs {
                url,
                css,
                text,
                profile,
                proxy,
                debug,
                method,
                data,
                content_type,
                timeout,
            };
            fetch::run(args).await?;
        }
        Commands::Read {
            url,
            format,
            max_length,
            profile,
            proxy,
            json,
            debug,
            timeout,
        } => {
            let args = read::ReadArgs {
                url,
                format,
                max_length,
                profile,
                proxy,
                json,
                debug,
                timeout,
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
        Commands::Doctor { proxy, debug, json } => {
            let args = doctor::DoctorArgs { proxy, debug, json };
            doctor::run(args).await?;
        }
    }
    Ok(())
}
