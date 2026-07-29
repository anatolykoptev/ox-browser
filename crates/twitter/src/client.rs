//! Fallback orchestrator: go-social → go-hully → FxTwitter → GraphQL.

use crate::types::{Tweet, UserProfile};
use crate::{fxtwitter, graphql, parser, request, social};

const GO_HULLY_ENV: &str = "GO_HULLY_URL";
const GO_SOCIAL_URL_ENV: &str = "GO_SOCIAL_URL";

/// Maximum go-hully response body (1 MB). A single tweet JSON is <10 KB;
/// 1 MB is very generous. go-hully is our own service, but "it is our own
/// service" is the assumption that stops holding the day something upstream
/// breaks (issue #119).
const HULLY_MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Fetch a single tweet by ID with fallback chain.
/// Order: go-social (auth pool) → go-hully → FxTwitter → GraphQL (guest token).
pub async fn fetch_tweet(id: &str) -> Option<Tweet> {
    // 1. Try go-social (centralized auth account pool — most reliable)
    if let Some(base) = go_social_url() {
        tracing::debug!(id, "twitter: trying go-social");
        match social::fetch_tweet(&base, id).await {
            Ok(tweet) => {
                tracing::info!(id, "twitter: got tweet from go-social");
                return Some(tweet);
            }
            Err(e) => tracing::warn!(id, error = %e, "twitter: go-social failed"),
        }
    }

    // 2. Try go-hully (existing fallback)
    if let Some(base) = go_hully_url() {
        tracing::debug!(id, "twitter: trying go-hully");
        match fetch_tweet_from_hully(&base, id).await {
            Ok(tweet) => {
                tracing::info!(id, "twitter: got tweet from go-hully");
                return Some(tweet);
            }
            Err(e) => tracing::debug!(id, error = %e, "twitter: go-hully failed"),
        }
    }

    // 3. Try FxTwitter (fast, free, no auth)
    tracing::debug!(id, "twitter: trying FxTwitter");
    if let Some(tweet) = fxtwitter::fetch_tweet(id).await {
        tracing::info!(id, "twitter: got tweet from FxTwitter");
        return Some(tweet);
    }

    // 4. Fallback to GraphQL (guest token)
    tracing::info!(id, "twitter: trying GraphQL with guest token");
    let vars = request::tweet_detail_vars(id);
    let url = request::build_url(&graphql::TWEET_DETAIL, &vars);
    match request::execute(&url).await {
        Ok(body) => {
            tracing::debug!(id, body_len = body.len(), "twitter: GraphQL response");
            match parser::parse_tweet_detail(&body) {
                Some(tweets) => {
                    tracing::info!(id, count = tweets.len(), "twitter: parsed from GraphQL");
                    tweets.into_iter().find(|t| t.id == id)
                }
                None => {
                    tracing::warn!(id, "twitter: failed to parse GraphQL response");
                    None
                }
            }
        }
        Err(e) => {
            tracing::warn!(id, error = %e, "twitter: GraphQL failed");
            None
        }
    }
}

/// Fetch a user profile by screen name with fallback chain.
pub async fn fetch_profile(screen_name: &str) -> Option<UserProfile> {
    // 1. Try FxTwitter for basic profile (fast, doesn't need auth)
    tracing::debug!(screen_name, "twitter: trying FxTwitter for profile");
    let mut profile = fxtwitter::fetch_profile(screen_name).await;

    // 2. Fallback to GraphQL for profile
    if profile.is_none() {
        tracing::debug!(screen_name, "twitter: FxTwitter failed, trying GraphQL");
        let vars = request::user_by_screen_name_vars(screen_name);
        let url = request::build_url(&graphql::USER_BY_SCREEN_NAME, &vars);
        if let Ok(body) = request::execute(&url).await {
            profile = parser::parse_user_profile(&body);
        }
    }

    // 3. Fetch recent tweets via GraphQL (need user ID from profile)
    let mut profile = profile?;
    if !profile.id.is_empty() {
        tracing::debug!(screen_name, user_id = %profile.id, "twitter: fetching recent tweets");
        let vars = request::user_tweets_vars(&profile.id, 10);
        let url = request::build_url(&graphql::USER_TWEETS, &vars);
        if let Ok(body) = request::execute(&url).await
            && let Some(tweets) = parser::parse_user_tweets(&body)
        {
            profile.recent_tweets = tweets;
        }
    }

    tracing::info!(screen_name, "twitter: got profile");
    Some(profile)
}

fn go_social_url() -> Option<String> {
    std::env::var(GO_SOCIAL_URL_ENV)
        .ok()
        .filter(|s| !s.is_empty())
}

fn go_hully_url() -> Option<String> {
    std::env::var(GO_HULLY_ENV).ok().filter(|s| !s.is_empty())
}

async fn fetch_tweet_from_hully(base_url: &str, id: &str) -> Result<Tweet, String> {
    let url = format!("{base_url}/v1/tweet/{id}");
    let client = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(&url)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status().as_u16();
    if status != 200 {
        return Err(format!("go-hully HTTP {status}"));
    }

    let body = ox_http::body_cap::read_text_capped(resp, HULLY_MAX_BODY_BYTES)
        .await
        .map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    Ok(Tweet {
        id: v["ID"].as_str().unwrap_or("").to_string(),
        text: v["Text"].as_str().unwrap_or("").to_string(),
        author_id: v["AuthorID"].as_str().unwrap_or("").to_string(),
        author_name: v["AuthorName"].as_str().unwrap_or("").to_string(),
        author_screen_name: v["AuthorHandle"].as_str().unwrap_or("").to_string(),
        created_at: v["CreatedAt"].as_str().unwrap_or("").to_string(),
        likes: v["Likes"].as_u64().unwrap_or(0),
        retweets: v["Retweets"].as_u64().unwrap_or(0),
        quotes: v["Quotes"].as_u64().unwrap_or(0),
        replies: 0,
        views: v["Views"].as_u64().unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    /// A body over the cap is rejected with the error naming the limit, and
    /// the counter increments. Uses a small cap to avoid allocating a 1 MB+
    /// body in a test — the mechanism is identical regardless of the limit
    /// value (issue #119).
    #[tokio::test]
    #[serial_test::serial]
    async fn hully_cap_rejects_oversized_body() {
        use std::sync::atomic::Ordering;

        let before = ox_http::metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);

        // Start a mock HTTP server serving a body that exceeds the cap.
        let cap: u64 = 100;
        let body = "x".repeat(200);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), sock.readable()).await;
            let _ = sock.try_read(&mut buf);
            let resp = format!("HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n{body}");
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Use a bare wreq client with a small cap — same mechanism as
        // fetch_tweet_from_hully but with a test-sized cap.
        let client = wreq::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        let resp = client
            .get(format!("{base_url}/v1/tweet/123"))
            .header("accept", "application/json")
            .send()
            .await
            .unwrap();
        let err = ox_http::body_cap::read_text_capped(resp, cap)
            .await
            .unwrap_err();

        match err {
            ox_http::HttpError::BodyTooLarge { limit, observed } => {
                assert_eq!(limit, cap, "error should name the limit");
                assert!(
                    observed > cap,
                    "observed ({observed}) should exceed cap ({cap})"
                );
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }

        let after = ox_http::metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);
        assert_eq!(after, before + 1, "counter must increment on rejection");
    }
}
