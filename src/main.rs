use clap::{Parser, Subcommand};
use ox_core::{Browser, BrowserConfig};

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
    },
    /// Show version info
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Fetch { url, css, text } => {
            let browser = Browser::new(BrowserConfig::default())?;
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
        Commands::Version => {
            println!("ox-browser {}", env!("CARGO_PKG_VERSION"));
        }
    }
    Ok(())
}
