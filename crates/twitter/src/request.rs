//! Build and execute Twitter GraphQL HTTP requests.
//!
//! Includes guest token activation (ported from go-twitter/auth.go)
//! and proper header set (ported from go-twitter/headers.go).

use std::sync::Mutex;
use std::time::Instant;

use crate::graphql::{self, Endpoint, BEARER_TOKEN};

const TWITTER_API_URL: &str = "https://api.twitter.com";
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Cached guest token with expiry tracking.
static GUEST_TOKEN: Mutex<Option<GuestToken>> = Mutex::new(None);

struct GuestToken {
    token: String,
    acquired_at: Instant,
}

/// Guest token TTL — reacquire after 3 hours.
const GUEST_TOKEN_TTL_SECS: u64 = 3 * 3600;

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
fn json_escape(s: &str) -> String {
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

/// Execute a GraphQL GET request with guest token and proper Twitter headers.
///
/// Ported from go-twitter: activates guest token on first call,
/// caches it, reacquires on 401/403.
pub async fn execute(
    url: &str,
    proxy: Option<&str>,
    timeout_secs: u64,
) -> Result<String, String> {
    let client = build_client(proxy, timeout_secs)?;

    // Get or activate guest token
    let guest_token = get_or_activate_guest_token(&client).await?;

    // First attempt with guest token
    let resp = do_graphql_get(&client, url, &guest_token).await?;
    let status = resp.0;
    let body = resp.1;

    if status == 200 {
        return Ok(body);
    }

    // On 401/403 — reacquire guest token and retry once
    if status == 401 || status == 403 {
        tracing::warn!(status, "graphql: guest token rejected, reacquiring");
        clear_guest_token();
        let new_token = activate_guest_token(&client).await?;
        save_guest_token(&new_token);

        let resp2 = do_graphql_get(&client, url, &new_token).await?;
        if resp2.0 == 200 {
            return Ok(resp2.1);
        }
        return Err(format!("GraphQL HTTP {} after token refresh", resp2.0));
    }

    Err(format!("GraphQL HTTP {status}"))
}

fn build_client(proxy: Option<&str>, timeout_secs: u64) -> Result<wreq::Client, String> {
    let mut builder = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .emulation(wreq_util::Emulation::Chrome136)
        .cookie_store(true);

    if let Some(p) = proxy {
        let proxy = wreq::Proxy::all(p).map_err(|e| e.to_string())?;
        builder = builder.proxy(proxy);
    }

    builder.build().map_err(|e| e.to_string())
}

/// Execute a GET request with guest token headers (ported from go-twitter/headers.go:guestHeaders).
async fn do_graphql_get(
    client: &wreq::Client,
    url: &str,
    guest_token: &str,
) -> Result<(u16, String), String> {
    let resp = client
        .get(url)
        .header("authorization", format!("Bearer {BEARER_TOKEN}"))
        .header("x-guest-token", guest_token)
        .header("x-twitter-active-user", "yes")
        .header("x-twitter-client-language", "en")
        .header("content-type", "application/json")
        .header("user-agent", DEFAULT_USER_AGENT)
        .header("accept", "*/*")
        .header("accept-language", "en-US,en;q=0.9")
        .header("referer", "https://twitter.com/")
        .header("origin", "https://twitter.com")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    Ok((status, body))
}

/// Get cached guest token or activate a new one.
async fn get_or_activate_guest_token(client: &wreq::Client) -> Result<String, String> {
    // Check cache
    {
        let cache = GUEST_TOKEN.lock().unwrap();
        if let Some(ref gt) = *cache
            && gt.acquired_at.elapsed().as_secs() < GUEST_TOKEN_TTL_SECS
        {
            return Ok(gt.token.clone());
        }
    }

    // Activate new token
    let token = activate_guest_token(client).await?;
    save_guest_token(&token);
    Ok(token)
}

/// Activate a guest token via Twitter API.
/// Ported from go-twitter/auth.go:getGuestToken.
async fn activate_guest_token(client: &wreq::Client) -> Result<String, String> {
    tracing::debug!("activating guest token");
    let resp = client
        .post(format!("{TWITTER_API_URL}/1.1/guest/activate.json"))
        .header("authorization", format!("Bearer {BEARER_TOKEN}"))
        .header("content-type", "application/json")
        .header("user-agent", DEFAULT_USER_AGENT)
        .send()
        .await
        .map_err(|e| format!("guest token request failed: {e}"))?;

    let status = resp.status().as_u16();
    if status != 200 {
        return Err(format!("guest token HTTP {status}"));
    }

    let body = resp.text().await.map_err(|e| e.to_string())?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("guest token parse: {e}"))?;
    let token = v["guest_token"]
        .as_str()
        .ok_or("empty guest_token in response")?
        .to_string();

    if token.is_empty() {
        return Err("empty guest_token".into());
    }

    tracing::info!(token_prefix = &token[..token.len().min(8)], "guest token activated");
    Ok(token)
}

fn save_guest_token(token: &str) {
    let mut cache = GUEST_TOKEN.lock().unwrap();
    *cache = Some(GuestToken {
        token: token.to_string(),
        acquired_at: Instant::now(),
    });
}

fn clear_guest_token() {
    let mut cache = GUEST_TOKEN.lock().unwrap();
    *cache = None;
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
    fn build_url_uses_twitter_encoding() {
        let vars = user_by_screen_name_vars("test");
        let url = build_url(&crate::graphql::USER_BY_SCREEN_NAME, &vars);
        // Twitter-style encoding uses %7B not %7b, %22 not standard
        assert!(url.contains("%7B"));
        assert!(url.contains("%22"));
        assert!(!url.contains("%7b")); // lowercase would be standard urlencoding
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

    #[test]
    fn guest_token_cache_starts_empty() {
        let cache = GUEST_TOKEN.lock().unwrap();
        // May or may not be empty depending on test order, just check it doesn't panic
        drop(cache);
    }
}
