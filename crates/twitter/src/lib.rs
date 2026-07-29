pub mod client;
pub mod format;
pub mod fxtwitter;
pub mod graphql;
pub mod parser;
pub mod request;
pub(crate) mod request_vars;
pub mod social;
pub mod types;
pub mod url;

pub(crate) mod tw_http;
pub(crate) mod xtid;
mod xtid_cubic;
pub(crate) mod xtid_manager;
mod xtid_parser;

pub use client::{fetch_profile, fetch_tweet};
pub use format::{format_profile, format_tweet};
pub use types::{Tweet, UserProfile};
pub use url::{TwitterUrl, parse as parse_url};

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
