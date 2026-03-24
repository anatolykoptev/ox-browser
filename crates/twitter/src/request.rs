//! Build Twitter GraphQL HTTP requests.

use crate::graphql::{self, Endpoint, BEARER_TOKEN};

/// Build the full URL for a GraphQL request with variables and features.
pub fn build_url(endpoint: &Endpoint, variables: &serde_json::Value) -> String {
    let vars = serde_json::to_string(variables).unwrap_or_default();
    let features = graphql::features_json();
    format!(
        "{}?variables={}&features={}",
        endpoint.url(),
        urlencoding::encode(&vars),
        urlencoding::encode(&features),
    )
}

/// Variables for TweetDetail query.
pub fn tweet_detail_vars(tweet_id: &str) -> serde_json::Value {
    serde_json::json!({
        "focalTweetId": tweet_id,
        "with_rux_injections": false,
        "rankingMode": "Relevance",
        "includePromotedContent": true,
        "withCommunity": true,
        "withQuickPromoteEligibilityTweetFields": true,
        "withBirdwatchNotes": true,
        "withVoice": true
    })
}

/// Variables for UserByScreenName query.
pub fn user_by_screen_name_vars(screen_name: &str) -> serde_json::Value {
    serde_json::json!({
        "screen_name": screen_name,
        "withSafetyModeUserFields": true
    })
}

/// Variables for UserTweets query.
pub fn user_tweets_vars(user_id: &str, count: u32) -> serde_json::Value {
    serde_json::json!({
        "userId": user_id,
        "count": count,
        "includePromotedContent": false,
        "withQuickPromoteEligibilityTweetFields": true,
        "withVoice": true,
        "withV2Timeline": true
    })
}

/// Execute a GraphQL GET request with proper Twitter headers.
pub async fn execute(
    url: &str,
    proxy: Option<&str>,
    timeout_secs: u64,
) -> Result<String, String> {
    let mut builder = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .emulation(wreq_util::Emulation::Chrome136)
        .cookie_store(true);

    if let Some(p) = proxy {
        let proxy = wreq::Proxy::all(p).map_err(|e| e.to_string())?;
        builder = builder.proxy(proxy);
    }

    let client = builder.build().map_err(|e| e.to_string())?;
    let resp = client
        .get(url)
        .header("authorization", format!("Bearer {BEARER_TOKEN}"))
        .header("x-twitter-active-user", "yes")
        .header("x-twitter-client-language", "en")
        .header("content-type", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status().as_u16();
    if status != 200 {
        return Err(format!("GraphQL HTTP {status}"));
    }
    resp.text().await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphql::TWEET_DETAIL;

    #[test]
    fn build_tweet_detail_url() {
        let vars = tweet_detail_vars("123");
        let url = build_url(&TWEET_DETAIL, &vars);
        assert!(url.starts_with("https://x.com/i/api/graphql/"));
        assert!(url.contains("TweetDetail"));
        assert!(url.contains("focalTweetId"));
    }

    #[test]
    fn build_url_encodes_variables() {
        let vars = user_by_screen_name_vars("testuser");
        let url = build_url(&crate::graphql::USER_BY_SCREEN_NAME, &vars);
        assert!(url.contains("UserByScreenName"));
        assert!(url.contains("screen_name"));
    }

    #[test]
    fn user_tweets_vars_has_correct_fields() {
        let vars = user_tweets_vars("456", 20);
        assert_eq!(vars["userId"], "456");
        assert_eq!(vars["count"], 20);
        assert_eq!(vars["withV2Timeline"], true);
    }
}
