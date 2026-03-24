//! Twitter/X site handler for read pipeline.
//! Detects twitter.com/x.com URLs and fetches via ox-twitter crate.

use std::time::Instant;

use ox_twitter::{TwitterUrl, format_tweet, format_profile, fetch_tweet, fetch_profile, parse_url};

use crate::content::{ContentFormat, ExtractedContent, ReadOutput, ReadParams};
use crate::read_pipeline::{build_output, elapsed};

/// Try Twitter handler. Returns Some(output) if URL is twitter.com/x.com.
pub async fn try_twitter(
    params: &ReadParams,
    _format: ContentFormat,
    start: Instant,
) -> Option<ReadOutput> {
    let tw_url = parse_url(&params.url)?;
    let proxy = std::env::var("RESIDENTIAL_PROXY_URL").ok();

    match tw_url {
        TwitterUrl::Tweet(id) => {
            tracing::info!(url = %params.url, id = %id, "twitter: fetching tweet");
            let tweet = fetch_tweet(&id, proxy.as_deref()).await?;
            let title = format!("@{}: {}", tweet.author_screen_name,
                ox_twitter::format::truncate(&tweet.text, 60));
            let content = format_tweet(&tweet);
            let ext = ExtractedContent {
                title,
                content,
                author: tweet.author_screen_name.clone(),
                excerpt: String::new(),
                length: 0,
                json_ld: vec![],
                og_image: String::new(),
            };
            Some(build_output(ext, params, "twitter", elapsed(start)))
        }
        TwitterUrl::Profile(screen_name) => {
            tracing::info!(url = %params.url, screen_name = %screen_name, "twitter: fetching profile");
            let profile = fetch_profile(&screen_name, proxy.as_deref()).await?;
            let title = format!("@{} · {}", profile.screen_name, profile.name);
            let content = format_profile(&profile);
            let ext = ExtractedContent {
                title,
                content,
                author: profile.screen_name.clone(),
                excerpt: profile.bio.clone(),
                length: 0,
                json_ld: vec![],
                og_image: String::new(),
            };
            Some(build_output(ext, params, "twitter", elapsed(start)))
        }
    }
}
