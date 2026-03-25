//! GraphQL URL builder and query variable constructors.
//!
//! Ported from go-twitter/request.go (jsonEscape) and go-twitter/headers.go.

use crate::graphql::{self, Endpoint};

/// Build the full URL for a GraphQL request with variables and features.
///
/// Uses Twitter-specific JSON escaping (ported from go-twitter/request.go:jsonEscape).
pub fn build_url(endpoint: &Endpoint, variables: &serde_json::Value) -> String {
    let vars = serde_json::to_string(variables).unwrap_or_default();
    let features = graphql::features_json();
    format!(
        "{}?variables={}&features={}",
        endpoint.url(),
        json_escape(&vars),
        json_escape(&features),
    )
}

/// Twitter-specific URL encoding for JSON query params.
/// Ported from go-twitter/request.go:jsonEscape — NOT standard percent encoding.
pub(crate) fn json_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for ch in s.chars() {
        match ch {
            ' ' => result.push_str("%20"),
            '"' => result.push_str("%22"),
            '{' => result.push_str("%7B"),
            '}' => result.push_str("%7D"),
            '[' => result.push_str("%5B"),
            ']' => result.push_str("%5D"),
            ':' => result.push_str("%3A"),
            ',' => result.push_str("%2C"),
            '\'' => result.push_str("%27"),
            '|' => result.push_str("%7C"),
            _ => result.push(ch),
        }
    }
    result
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphql::{TWEET_DETAIL, USER_BY_SCREEN_NAME};

    #[test]
    fn build_tweet_detail_url() {
        let vars = tweet_detail_vars("123");
        let url = build_url(&TWEET_DETAIL, &vars);
        assert!(url.starts_with("https://x.com/i/api/graphql/"));
        assert!(url.contains("TweetDetail"));
        assert!(url.contains("focalTweetId"));
    }

    #[test]
    fn build_url_uses_twitter_encoding() {
        let vars = user_by_screen_name_vars("test");
        let url = build_url(&USER_BY_SCREEN_NAME, &vars);
        assert!(url.contains("%7B"));
        assert!(url.contains("%22"));
        assert!(!url.contains("%7b"));
    }

    #[test]
    fn json_escape_matches_go_twitter() {
        let input = r#"{"key": "value", "arr": [1, 2]}"#;
        let escaped = json_escape(input);
        assert!(escaped.contains("%7B"));
        assert!(escaped.contains("%22"));
        assert!(escaped.contains("%3A"));
        assert!(escaped.contains("%2C"));
        assert!(escaped.contains("%5B"));
        assert!(escaped.contains("%5D"));
        assert!(!escaped.contains('{'));
        assert!(!escaped.contains('"'));
    }

    #[test]
    fn user_tweets_vars_has_correct_fields() {
        let vars = user_tweets_vars("456", 20);
        assert_eq!(vars["userId"], "456");
        assert_eq!(vars["count"], 20);
        assert_eq!(vars["withV2Timeline"], true);
    }
}
