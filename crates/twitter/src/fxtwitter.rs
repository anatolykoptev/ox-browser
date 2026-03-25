//! FxTwitter API provider — free, no auth, public endpoint.
//! Tweets: GET https://api.fxtwitter.com/i/status/{id}
//! Profiles: GET https://api.fxtwitter.com/{screen_name}

use crate::types::{Tweet, UserProfile};

const FXTWITTER_BASE: &str = "https://api.fxtwitter.com";

/// Fetch a tweet by ID from FxTwitter API.
pub async fn fetch_tweet(id: &str) -> Option<Tweet> {
    let url = format!("{FXTWITTER_BASE}/i/status/{id}");
    let body = http_get(&url).await.ok()?;
    parse_tweet_response(&body)
}

/// Fetch a user profile from FxTwitter API.
pub async fn fetch_profile(screen_name: &str) -> Option<UserProfile> {
    let url = format!("{FXTWITTER_BASE}/{screen_name}");
    let body = http_get(&url).await.ok()?;
    parse_profile_response(&body)
}

fn parse_tweet_response(body: &str) -> Option<Tweet> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    if v["code"].as_u64() != Some(200) {
        return None;
    }
    let t = &v["tweet"];
    let a = &t["author"];
    Some(Tweet {
        id: t["id"].as_str()?.to_string(),
        text: t["text"].as_str().unwrap_or("").to_string(),
        author_id: a["id"].as_str().unwrap_or("").to_string(),
        author_name: a["name"].as_str().unwrap_or("").to_string(),
        author_screen_name: a["screen_name"].as_str().unwrap_or("").to_string(),
        created_at: t["created_at"].as_str().unwrap_or("").to_string(),
        likes: t["likes"].as_u64().unwrap_or(0),
        retweets: t["retweets"].as_u64().unwrap_or(0),
        quotes: t["quotes"].as_u64().unwrap_or(0),
        replies: t["replies"].as_u64().unwrap_or(0),
        views: t["views"].as_u64().unwrap_or(0),
    })
}

fn parse_profile_response(body: &str) -> Option<UserProfile> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    if v["code"].as_u64() != Some(200) {
        return None;
    }
    let u = &v["user"];
    Some(UserProfile {
        id: u["id"].as_str().unwrap_or("").to_string(),
        name: u["name"].as_str().unwrap_or("").to_string(),
        screen_name: u["screen_name"].as_str().unwrap_or("").to_string(),
        bio: u["description"].as_str().unwrap_or("").to_string(),
        followers: u["followers"].as_u64().unwrap_or(0),
        following: u["following"].as_u64().unwrap_or(0),
        tweet_count: u["tweets"].as_u64().unwrap_or(0),
        verified: false,
        recent_tweets: vec![],
    })
}

/// HTTP GET via shared Twitter HttpClient.
async fn http_get(url: &str) -> Result<String, String> {
    let resp = crate::tw_http::twitter_http()
        .get_with_headers(url, &[("accept", "application/json")])
        .await
        .map_err(|e| e.to_string())?;

    if resp.status != 200 {
        return Err(format!("HTTP {}", resp.status));
    }
    Ok(resp.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWEET_JSON: &str = r#"{
        "code": 200,
        "message": "OK",
        "tweet": {
            "id": "123",
            "text": "Hello world",
            "created_at": "Mon Mar 24 12:00:00 +0000 2026",
            "likes": 42,
            "retweets": 10,
            "quotes": 3,
            "replies": 5,
            "views": 1000,
            "author": {
                "id": "456",
                "name": "Test User",
                "screen_name": "testuser"
            }
        }
    }"#;

    const PROFILE_JSON: &str = r#"{
        "code": 200,
        "message": "OK",
        "user": {
            "id": "456",
            "name": "Test User",
            "screen_name": "testuser",
            "description": "Hello bio",
            "followers": 1000,
            "following": 100,
            "tweets": 5000,
            "likes": 2000,
            "media_count": 300,
            "url": "https://x.com/testuser"
        }
    }"#;

    #[test]
    fn parse_tweet_response_ok() {
        let tweet = parse_tweet_response(TWEET_JSON).unwrap();
        assert_eq!(tweet.id, "123");
        assert_eq!(tweet.text, "Hello world");
        assert_eq!(tweet.author_screen_name, "testuser");
        assert_eq!(tweet.likes, 42);
        assert_eq!(tweet.views, 1000);
    }

    #[test]
    fn parse_profile_response_ok() {
        let profile = parse_profile_response(PROFILE_JSON).unwrap();
        assert_eq!(profile.screen_name, "testuser");
        assert_eq!(profile.bio, "Hello bio");
        assert_eq!(profile.followers, 1000);
        assert_eq!(profile.tweet_count, 5000);
    }

    #[test]
    fn parse_404_response() {
        let json = r#"{"code": 404, "message": "NOT_FOUND", "tweet": null}"#;
        assert!(parse_tweet_response(json).is_none());
    }
}
