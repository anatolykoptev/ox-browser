pub mod types;
pub mod url;
pub mod fxtwitter;
pub mod graphql;
pub mod request;
pub(crate) mod request_vars;
pub mod parser;
pub mod social;
pub mod client;
pub mod format;
pub mod login;

pub(crate) mod tw_http;
mod xtid_cubic;
mod xtid_parser;
pub(crate) mod xtid;
pub(crate) mod xtid_manager;

pub use types::{Tweet, UserProfile};
pub use url::{parse as parse_url, TwitterUrl};
pub use client::{fetch_tweet, fetch_profile};
pub use format::{format_tweet, format_profile};

/// Shared Chrome UA for all Twitter API requests.
pub const TWITTER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";

/// Global XtidManager instance — initialized lazily on first GraphQL request.
static XTID_MANAGER: std::sync::OnceLock<xtid_manager::XtidManager> = std::sync::OnceLock::new();

/// Get or initialize the global XtidManager.
fn xtid_mgr() -> &'static xtid_manager::XtidManager {
    XTID_MANAGER.get_or_init(xtid_manager::XtidManager::new)
}

/// Try to generate x-client-transaction-id for a request.
/// Returns None on failure (caller proceeds without the header).
pub(crate) async fn xtid_header(method: &str, url: &str) -> Option<String> {
    let path = ::url::Url::parse(url).ok().map(|u| u.path().to_string())?;
    match xtid_mgr().generate_id(method, &path).await {
        Ok(id) => Some(id),
        Err(e) => {
            tracing::warn!("xtid generation failed: {e}");
            None
        }
    }
}
