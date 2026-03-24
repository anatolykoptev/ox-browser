pub mod types;
pub mod url;
pub mod fxtwitter;
pub mod graphql;
pub mod request;
pub mod parser;
pub mod social;
pub mod client;
pub mod format;

pub use types::{Tweet, UserProfile};
pub use url::{parse as parse_url, TwitterUrl};
pub use client::{fetch_tweet, fetch_profile};
pub use format::{format_tweet, format_profile};

/// Shared Chrome UA for all Twitter API requests.
pub const TWITTER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
