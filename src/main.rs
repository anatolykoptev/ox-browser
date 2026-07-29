mod config;
mod read;
mod serve;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ox_core::{Browser, BrowserConfig};
use ox_http::{BrowserProfile, HttpClient, HttpConfig, StaticPool};

/// Resolve the browser profile for a CLI subcommand, mirroring the
/// service's resolution so the CLI and service present the same identity
/// for the same config (Issue #102).
///
/// Resolution goes through `HttpSection::profile()` — the SAME path the
/// service uses (`build_http_config` → `config.http.profile()`) — so the
/// OS-filter retry and deprecation warnings are inherited (Issue #102-C:
/// the old `select_profile` called `random_profile` directly with no retry,
/// silently returning a wrong-browser profile on an unusual host).
///
/// - `--profile none` / `""` → `None` (bare client, explicit opt-out).
/// - `--profile <name>` → resolved via `HttpSection::profile()`.
/// - no `--profile` → `[http].profile` from config.toml
///   (`OX_BROWSER_CONFIG` or `config.toml`), defaulting to the documented
///   `chrome` when the file is absent. Never silently bare.
fn resolve_cli_profile(profile: Option<&str>) -> anyhow::Result<Option<&'static BrowserProfile>> {
    Ok(cli_profile_section(profile)?.profile())
}

/// Build the `HttpSection` describing the CLI's effective profile setting.
/// `Some(name)` honours the `--profile` flag; `None` loads the service's
/// configured default from config.toml (Issue #102-B).
fn cli_profile_section(profile: Option<&str>) -> anyhow::Result<config::HttpSection> {
    Ok(match profile {
        Some(name) => config::HttpSection {
            profile: name.to_string(),
            ..config::HttpSection::default()
        },
        None => config::load_http_section_for_cli()?,
    })
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
    let mut cfg = HttpConfig {
        profile: resolve_cli_profile(profile)?,
        debug,
        ..HttpConfig::default()
    };

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
            let mut cfg = BrowserConfig {
                profile: resolve_cli_profile(profile.as_deref())?,
                debug,
                ..BrowserConfig::default()
            };

            if !config::proxy_disabled()
                && let Some(proxy_url) = proxy
            {
                let pool = StaticPool::new(vec![proxy_url]);
                cfg.proxy_pool = Some(Arc::new(pool));
            }

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

#[cfg(test)]
mod tests {
    //! Issue #102: the CLI must present the same identity the service
    //! presents unless explicitly told otherwise. These tests guard the
    //! shared seam (`resolve_cli_profile`) so a third subcommand inherits
    //! the fix and a revert to `BrowserConfig::default()` (profile: None /
    //! bare) is caught.
    use super::*;
    use ox_http::{browser_headers, profile_to_emulation};

    /// The GREASE brand in `sec-ch-ua` is randomized per call by design
    /// (real Chrome does this too) — raw comparison flaps. Normalize the
    /// four GREASE brands to a token before comparing header sets, per the
    /// fingerprint-verification skill's GREASE trap. Everything else in
    /// `browser_headers` is deterministic given the profile.
    fn normalize_grease(headers: Vec<(String, String)>) -> Vec<(String, String)> {
        const GREASE: &[&str] = &[
            r#""Not_A Brand";v="8""#,
            r#""Not/A)Brand";v="8""#,
            r#""Not A(Brand";v="99""#,
            r#""Not:A-Brand";v="99""#,
        ];
        headers
            .into_iter()
            .map(|(k, v)| {
                let mut v = v;
                for g in GREASE {
                    v = v.replace(g, "<grease>");
                }
                (k, v)
            })
            .collect()
    }

    /// `--profile none` (and `""`) yield the bare client — the documented
    /// opt-out must keep working.
    #[test]
    fn resolve_cli_profile_none_yields_bare() {
        assert!(resolve_cli_profile(Some("none")).unwrap().is_none());
        assert!(resolve_cli_profile(Some("")).unwrap().is_none());
    }

    /// `--profile chrome` resolves to a chrome profile carrying a TLS
    /// fingerprint — not just a non-`ox-browser/` UA.
    #[test]
    fn resolve_cli_profile_explicit_chrome_has_fingerprint() {
        let p = resolve_cli_profile(Some("chrome"))
            .unwrap()
            .expect("chrome resolves");
        assert_eq!(p.browser, "chrome");
        assert!(!p.user_agent.starts_with("ox-browser/"));
        assert!(p.user_agent.contains("Chrome/148.0.0.0"));
        assert!(
            profile_to_emulation(p).is_some(),
            "profile must carry a TLS/HTTP2 fingerprint, not just a UA"
        );
    }

    /// Absent config → the documented default (`chrome`), NEVER the bare
    /// client. This is the core #102 invariant: a silent fallback to bare
    /// is the bug being fixed.
    #[test]
    fn cli_absent_config_is_chrome_not_bare() {
        let section =
            config::load_http_section_from(std::path::Path::new("/nonexistent/oxb102-absent.toml"))
                .unwrap();
        assert_eq!(section.profile, "chrome");
        let p = section.profile().expect("default chrome resolves");
        assert_eq!(p.browser, "chrome");
        assert!(!p.user_agent.starts_with("ox-browser/"));
        assert!(profile_to_emulation(p).is_some());
    }

    /// A config naming a different profile is honoured by the CLI — parity
    /// with the deployed service (Issue #102-B, option 1).
    #[test]
    fn cli_default_honours_config_profile() {
        let path = std::env::temp_dir().join("oxb102-firefox.toml");
        std::fs::write(&path, "[http]\nprofile = \"firefox\"\n").unwrap();
        let section = config::load_http_section_from(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(section.profile, "firefox");
        let p = section.profile().expect("firefox resolves");
        assert_eq!(p.browser, "firefox");
        assert!(profile_to_emulation(p).is_some());
    }

    /// A malformed config is a LOUD error, not a silent fallback to bare
    /// (the #102 failure mode). Only `[http]`/syntax errors fire — a
    /// `[solver]` typo does not (unknown sections ignored).
    #[test]
    fn cli_malformed_config_is_loud_not_bare() {
        let path = std::env::temp_dir().join("oxb102-bad.toml");
        std::fs::write(&path, "[http\nprofile = \n").unwrap(); // unclosed table
        let res = config::load_http_section_from(&path);
        let _ = std::fs::remove_file(&path);
        assert!(
            res.is_err(),
            "malformed config must error, not fall back to bare"
        );
    }

    /// A `[solver]` typo must NOT break the CLI — only the `[http]` surface
    /// is pulled in (the option-1 coupling concern, mitigated).
    #[test]
    fn cli_ignores_non_http_section_errors() {
        let path = std::env::temp_dir().join("oxb102-solver-typo.toml");
        // [solver] has a wrong type (int for a string field) — the full
        // ServerConfig loader would reject this, but the CLI loads only
        // [http] and ignores [solver].
        std::fs::write(
            &path,
            "[http]\nprofile = \"chrome\"\n[solver]\nbyparr_url = 123\n",
        )
        .unwrap();
        let section = config::load_http_section_from(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(section.profile, "chrome");
    }

    /// The CLI no-flag default and the service default resolve to the SAME
    /// identity — same browser, same UA, same fingerprint derivability, same
    /// header set + order. A test that passes while the binary still sends
    /// `ox-browser/…` is the failure mode this task removes, so the UA is
    /// asserted explicitly AND the fingerprint-bearing fields are asserted.
    /// On the linux/mac/windows CI host both draws pick the same OS bucket,
    /// so the UA is byte-identical.
    #[test]
    fn cli_and_service_default_same_identity() {
        let cli_section =
            config::load_http_section_from(std::path::Path::new("/nonexistent/oxb102-parity.toml"))
                .unwrap();
        let svc_section = config::HttpSection::default();
        assert_eq!(
            cli_section.profile, svc_section.profile,
            "absent config must equal the documented service default"
        );
        let cli_p = cli_section.profile().expect("cli default profile");
        let svc_p = svc_section.profile().expect("svc default profile");
        assert_eq!(cli_p.browser, svc_p.browser);
        assert_eq!(cli_p.user_agent, svc_p.user_agent);
        assert!(!cli_p.user_agent.starts_with("ox-browser/"));
        assert!(profile_to_emulation(cli_p).is_some());
        assert!(profile_to_emulation(svc_p).is_some());
        assert_eq!(
            normalize_grease(browser_headers(cli_p)),
            normalize_grease(browser_headers(svc_p)),
            "header set + wire order must match (GREASE brand normalized)"
        );
    }

    /// The regression guard: the actual `resolve_cli_profile(None)` seam
    /// must return a browser profile, not `None` (the old
    /// `BrowserConfig::default()` behaviour). If someone reverts the seam
    /// to bare, this fails.
    #[test]
    fn resolve_cli_profile_no_flag_is_not_bare() {
        // SAFETY: OX_BROWSER_CONFIG is process-global; this is the only test
        // setting it. Pointed at a non-existent path so the CLI uses
        // HttpSection::default() (chrome) — the documented no-config default.
        // Restored before assertions so a panic cannot leak the override.
        let prev = std::env::var("OX_BROWSER_CONFIG").ok();
        unsafe {
            std::env::set_var("OX_BROWSER_CONFIG", "/nonexistent/oxb102-guard.toml");
        }
        let resolved = resolve_cli_profile(None);
        unsafe {
            match &prev {
                Some(v) => std::env::set_var("OX_BROWSER_CONFIG", v),
                None => std::env::remove_var("OX_BROWSER_CONFIG"),
            }
        }
        let p = resolved
            .unwrap()
            .expect("no-flag CLI must NOT be the bare client (Issue #102)");
        assert_eq!(p.browser, "chrome");
        assert!(!p.user_agent.starts_with("ox-browser/"));
        assert!(p.user_agent.contains("Chrome/148.0.0.0"));
        assert!(
            profile_to_emulation(p).is_some(),
            "must carry a TLS fingerprint"
        );
    }
}
