//! Fallback orchestrator: FxTwitter → GraphQL.

use crate::{fxtwitter, graphql, parser, request};
use crate::types::{Tweet, UserProfile};

/// Fetch a single tweet by ID with fallback chain.
pub async fn fetch_tweet(id: &str, proxy: Option<&str>) -> Option<Tweet> {
    // 1. Try FxTwitter (fast, free)
    tracing::debug!(id, "twitter: trying FxTwitter for tweet");
    if let Some(tweet) = fxtwitter::fetch_tweet(id, proxy).await {
        tracing::info!(id, "twitter: got tweet from FxTwitter");
        return Some(tweet);
    }

    // 2. Fallback to GraphQL
    tracing::debug!(id, "twitter: FxTwitter failed, trying GraphQL");
    let vars = request::tweet_detail_vars(id);
    let url = request::build_url(&graphql::TWEET_DETAIL, &vars);
    let body = request::execute(&url, proxy, 10).await.ok()?;
    let tweets = parser::parse_tweet_detail(&body)?;
    let tweet = tweets.into_iter().find(|t| t.id == id);
    if tweet.is_some() {
        tracing::info!(id, "twitter: got tweet from GraphQL");
    }
    tweet
}

/// Fetch a user profile by screen name with fallback chain.
pub async fn fetch_profile(screen_name: &str, proxy: Option<&str>) -> Option<UserProfile> {
    // 1. Try FxTwitter for basic profile
    tracing::debug!(screen_name, "twitter: trying FxTwitter for profile");
    let mut profile = fxtwitter::fetch_profile(screen_name, proxy).await;

    // 2. Fallback to GraphQL for profile
    if profile.is_none() {
        tracing::debug!(screen_name, "twitter: FxTwitter failed, trying GraphQL for profile");
        let vars = request::user_by_screen_name_vars(screen_name);
        let url = request::build_url(&graphql::USER_BY_SCREEN_NAME, &vars);
        if let Ok(body) = request::execute(&url, proxy, 10).await {
            profile = parser::parse_user_profile(&body);
        }
    }

    // 3. Fetch recent tweets via GraphQL (need user ID from profile)
    let mut profile = profile?;
    if !profile.id.is_empty() {
        tracing::debug!(screen_name, user_id = %profile.id, "twitter: fetching recent tweets");
        let vars = request::user_tweets_vars(&profile.id, 10);
        let url = request::build_url(&graphql::USER_TWEETS, &vars);
        if let Ok(body) = request::execute(&url, proxy, 10).await {
            if let Some(tweets) = parser::parse_user_tweets(&body) {
                profile.recent_tweets = tweets;
            }
        }
    }

    tracing::info!(screen_name, "twitter: got profile");
    Some(profile)
}
