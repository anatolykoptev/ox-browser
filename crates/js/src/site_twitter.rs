//! Twitter/X site handler — injected into ox-http read pipeline.
//!
//! Lives in ox-js (not ox-http) to avoid circular dependency:
//! ox-http → ox-twitter → ox-http would be a cycle.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use ox_http::content::{ContentFormat, ExtractedContent, ReadOutput, ReadParams};
use ox_http::read_pipeline::{build_output, elapsed, SiteHandler};
use ox_twitter::{format_profile, format_tweet, fetch_profile, fetch_tweet, parse_url, TwitterUrl};

/// Build a `SiteHandler` that handles Twitter/X URLs via ox-twitter.
pub fn make_twitter_handler() -> SiteHandler {
    Arc::new(|params: ReadParams, _format: ContentFormat, start: Instant| -> Pin<Box<dyn std::future::Future<Output = Option<ReadOutput>> + Send>> {
        Box::pin(async move {
            let tw_url = parse_url(&params.url)?;

            match tw_url {
                TwitterUrl::Tweet(id) => {
                    tracing::info!(url = %params.url, id = %id, "twitter: fetching tweet");
                    let tweet = fetch_tweet(&id).await?;
                    let title = format!(
                        "@{}: {}",
                        tweet.author_screen_name,
                        ox_twitter::format::truncate(&tweet.text, 60),
                    );
                    let content = format_tweet(&tweet);
                    let ext = ExtractedContent {
                        title,
                        content,
                        author: tweet.author_screen_name.clone(),
                        excerpt: String::new(),
                        length: 0,
                        json_ld: vec![],
                        og_image: String::new(),
                        meta: ox_http::content::ArticleMeta::default(),
                    };
                    Some(build_output(ext, &params, "twitter", elapsed(start)))
                }
                TwitterUrl::Profile(screen_name) => {
                    tracing::info!(url = %params.url, screen_name = %screen_name, "twitter: fetching profile");
                    let profile = fetch_profile(&screen_name).await?;
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
                        meta: ox_http::content::ArticleMeta::default(),
                    };
                    Some(build_output(ext, &params, "twitter", elapsed(start)))
                }
            }
        })
    })
}
