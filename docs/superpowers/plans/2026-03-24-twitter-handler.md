# Twitter Site Handler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Twitter/X content extraction to ox-browser with multi-provider fallback (FxTwitter + GraphQL).

**Architecture:** New `crates/twitter` crate with URL parsing, two providers (FxTwitter API, Twitter GraphQL ported from go-twitter), fallback orchestrator, and text formatter. Site handler in `crates/http` integrates into the read pipeline.

**Tech Stack:** Rust 1.93, wreq 6.0 + wreq_util 3.0 (Chrome TLS), serde_json, tokio

**Spec:** `docs/superpowers/specs/2026-03-24-twitter-handler-design.md`

**Reference code:** `/home/krolik/src/go-twitter/` — Go library being partially ported

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `crates/twitter/Cargo.toml` | Create | Crate manifest |
| `crates/twitter/src/lib.rs` | Create | Module declarations, re-exports |
| `crates/twitter/src/types.rs` | Create | `Tweet`, `UserProfile` structs |
| `crates/twitter/src/url.rs` | Create | Parse twitter/x.com URLs → `TwitterUrl` enum |
| `crates/twitter/src/fxtwitter.rs` | Create | FxTwitter API provider |
| `crates/twitter/src/graphql.rs` | Create | GraphQL endpoints, features, bearer token |
| `crates/twitter/src/request.rs` | Create | Build GraphQL HTTP requests |
| `crates/twitter/src/parser.rs` | Create | Parse GraphQL JSON → types |
| `crates/twitter/src/client.rs` | Create | Fallback orchestrator |
| `crates/twitter/src/format.rs` | Create | Format types → text output |
| `crates/http/src/site_twitter.rs` | Create | Read pipeline handler |
| `crates/http/src/read_pipeline.rs` | Modify | Add `try_twitter` call |
| `crates/http/src/lib.rs` | Modify | Add `site_twitter` module |
| `crates/http/Cargo.toml` | Modify | Add `ox-twitter` dependency |
| `Cargo.toml` | Modify | Add `crates/twitter` to workspace members |
| `src/config/ratelimit.rs` | Modify | Add `*.x.com` default rule |

---

## Task 1: Crate scaffold + types

**Files:**
- Create: `crates/twitter/Cargo.toml`
- Create: `crates/twitter/src/lib.rs`
- Create: `crates/twitter/src/types.rs`
- Modify: `Cargo.toml` (workspace)

- [ ] **Step 1: Create Cargo.toml**

```toml
[package]
name = "ox-twitter"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
url = "2"
wreq = { version = "6.0.0-rc.28", default-features = false, features = ["cookies", "gzip", "brotli"] }
wreq-util = "3.0.0-rc.10"
urlencoding = "2"
tokio.workspace = true
tracing.workspace = true
thiserror.workspace = true
```

- [ ] **Step 2: Create types.rs**

```rust
//! Twitter data types for tweets and user profiles.

use serde::{Deserialize, Serialize};

/// A single tweet with author info and engagement stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tweet {
    pub id: String,
    pub text: String,
    pub author_id: String,
    pub author_name: String,
    pub author_screen_name: String,
    pub created_at: String,
    pub likes: u64,
    pub retweets: u64,
    pub quotes: u64,
    pub replies: u64,
    pub views: u64,
}

/// A user profile with bio and recent tweets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: String,
    pub name: String,
    pub screen_name: String,
    pub bio: String,
    pub followers: u64,
    pub following: u64,
    pub tweet_count: u64,
    pub verified: bool,
    pub recent_tweets: Vec<Tweet>,
}
```

- [ ] **Step 3: Create lib.rs**

```rust
pub mod types;
pub use types::{Tweet, UserProfile};
```

- [ ] **Step 4: Add to workspace Cargo.toml**

Add `"crates/twitter"` to the `members` list in the root `Cargo.toml`.

- [ ] **Step 5: Verify it compiles**

Run: `cd /home/krolik/src/ox-browser && cargo check -p ox-twitter`
Expected: OK

- [ ] **Step 6: Commit**

```bash
git add crates/twitter/ Cargo.toml
git commit -m "feat(twitter): scaffold crate with Tweet and UserProfile types"
```

---

## Task 2: URL parser

**Files:**
- Create: `crates/twitter/src/url.rs`
- Modify: `crates/twitter/src/lib.rs`

- [ ] **Step 1: Write tests**

```rust
// In url.rs, at the bottom:
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tweet_x_com() {
        let r = parse("https://x.com/elonmusk/status/1234567890").unwrap();
        assert!(matches!(r, TwitterUrl::Tweet(id) if id == "1234567890"));
    }

    #[test]
    fn parse_tweet_twitter_com() {
        let r = parse("https://twitter.com/user/status/9999").unwrap();
        assert!(matches!(r, TwitterUrl::Tweet(id) if id == "9999"));
    }

    #[test]
    fn parse_tweet_mobile() {
        let r = parse("https://mobile.twitter.com/user/status/123").unwrap();
        assert!(matches!(r, TwitterUrl::Tweet(id) if id == "123"));
    }

    #[test]
    fn parse_tweet_with_query_params() {
        let r = parse("https://x.com/user/status/123?s=20&t=abc").unwrap();
        assert!(matches!(r, TwitterUrl::Tweet(id) if id == "123"));
    }

    #[test]
    fn parse_profile_x_com() {
        let r = parse("https://x.com/elonmusk").unwrap();
        assert!(matches!(r, TwitterUrl::Profile(name) if name == "elonmusk"));
    }

    #[test]
    fn parse_profile_trailing_slash() {
        let r = parse("https://twitter.com/rustlang/").unwrap();
        assert!(matches!(r, TwitterUrl::Profile(name) if name == "rustlang"));
    }

    #[test]
    fn non_twitter_url() {
        assert!(parse("https://example.com/page").is_none());
    }

    #[test]
    fn skip_settings_path() {
        assert!(parse("https://x.com/settings").is_none());
        assert!(parse("https://x.com/home").is_none());
        assert!(parse("https://x.com/explore").is_none());
        assert!(parse("https://x.com/search").is_none());
    }

    #[test]
    fn skip_i_paths() {
        // Internal Twitter paths like /i/flow/login
        assert!(parse("https://x.com/i/flow/login").is_none());
    }
}
```

- [ ] **Step 2: Implement url.rs**

```rust
//! Parse Twitter/X.com URLs into structured references.

use url::Url;

/// Parsed Twitter URL — either a tweet or a profile.
#[derive(Debug, Clone, PartialEq)]
pub enum TwitterUrl {
    Tweet(String),
    Profile(String),
}

/// Non-profile top-level paths to skip.
const SKIP_PATHS: &[&str] = &[
    "settings", "home", "explore", "search", "notifications",
    "messages", "i", "login", "logout", "signup",
];

/// Parse a URL. Returns `Some(TwitterUrl)` if it's a twitter.com/x.com URL, `None` otherwise.
pub fn parse(raw: &str) -> Option<TwitterUrl> {
    let url = Url::parse(raw).ok()?;
    let host = url.host_str()?;
    if !host.contains("twitter.com") && !host.contains("x.com") {
        return None;
    }

    let segments: Vec<&str> = url.path_segments()?
        .filter(|s| !s.is_empty())
        .collect();

    // /user/status/{id} → Tweet
    if segments.len() >= 3 && segments[1] == "status" {
        let id = segments[2].split('?').next().unwrap_or(segments[2]);
        if id.chars().all(|c| c.is_ascii_digit()) {
            return Some(TwitterUrl::Tweet(id.to_string()));
        }
    }

    // /{screen_name} → Profile (skip reserved paths)
    if segments.len() == 1 {
        let name = segments[0];
        if !SKIP_PATHS.contains(&name) && !name.starts_with('@') {
            return Some(TwitterUrl::Profile(name.to_string()));
        }
    }

    None
}
```

- [ ] **Step 3: Register in lib.rs**

Add `pub mod url;` to `lib.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p ox-twitter`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/twitter/src/url.rs crates/twitter/src/lib.rs
git commit -m "feat(twitter): URL parser for tweets and profiles"
```

---

## Task 3: FxTwitter provider

**Files:**
- Create: `crates/twitter/src/fxtwitter.rs`
- Modify: `crates/twitter/src/lib.rs`

- [ ] **Step 1: Write tests with mock JSON**

```rust
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
    fn parse_tweet_response() {
        let tweet = parse_tweet_response(TWEET_JSON).unwrap();
        assert_eq!(tweet.id, "123");
        assert_eq!(tweet.text, "Hello world");
        assert_eq!(tweet.author_screen_name, "testuser");
        assert_eq!(tweet.likes, 42);
        assert_eq!(tweet.views, 1000);
    }

    #[test]
    fn parse_profile_response() {
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
```

- [ ] **Step 2: Implement fxtwitter.rs**

```rust
//! FxTwitter API provider — free, no auth, public endpoint.
//! Tweets: GET https://api.fxtwitter.com/i/status/{id}
//! Profiles: GET https://api.fxtwitter.com/{screen_name}

use crate::types::{Tweet, UserProfile};

const FXTWITTER_BASE: &str = "https://api.fxtwitter.com";

/// Fetch a tweet by ID from FxTwitter API.
pub async fn fetch_tweet(id: &str, proxy: Option<&str>) -> Option<Tweet> {
    let url = format!("{FXTWITTER_BASE}/i/status/{id}");
    let body = http_get(&url, proxy, 5).await.ok()?;
    parse_tweet_response(&body)
}

/// Fetch a user profile from FxTwitter API.
pub async fn fetch_profile(screen_name: &str, proxy: Option<&str>) -> Option<UserProfile> {
    let url = format!("{FXTWITTER_BASE}/{screen_name}");
    let body = http_get(&url, proxy, 5).await.ok()?;
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
        verified: false, // FxTwitter doesn't reliably expose this
        recent_tweets: vec![],
    })
}

/// Simple HTTP GET with optional proxy and timeout.
async fn http_get(url: &str, proxy: Option<&str>, timeout_secs: u64) -> Result<String, String> {
    let mut builder = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .emulation(wreq_util::Emulation::Chrome136)
        .cookie_store(true);

    if let Some(p) = proxy {
        let proxy = wreq::Proxy::all(p).map_err(|e| e.to_string())?;
        builder = builder.proxy(proxy);
    }

    let client = builder.build().map_err(|e| e.to_string())?;
    let resp = client.get(url)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status() != wreq::StatusCode::OK {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    resp.text().await.map_err(|e| e.to_string())
}
```

- [ ] **Step 3: Register in lib.rs**

Add `pub mod fxtwitter;` to `lib.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p ox-twitter`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/twitter/src/fxtwitter.rs crates/twitter/src/lib.rs
git commit -m "feat(twitter): FxTwitter API provider with tweet and profile parsing"
```

---

## Task 4: GraphQL endpoints + request builder

**Files:**
- Create: `crates/twitter/src/graphql.rs`
- Create: `crates/twitter/src/request.rs`
- Modify: `crates/twitter/src/lib.rs`

- [ ] **Step 1: Create graphql.rs**

Port bearer token, endpoints map, and features from `/home/krolik/src/go-twitter/endpoints.go`.

```rust
//! Twitter GraphQL API constants — endpoints, bearer token, feature flags.
//! Ported from go-twitter/endpoints.go.

/// Public bearer token from Twitter's web app JS (decoded form for Authorization header).
pub const BEARER_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs=1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";

const BASE_URL: &str = "https://x.com/i/api/graphql";

/// GraphQL endpoint definition.
pub struct Endpoint {
    pub id: &'static str,
    pub name: &'static str,
}

pub const TWEET_DETAIL: Endpoint = Endpoint {
    id: "zXaXQgfyR4GxE21uwYQSyA",
    name: "TweetDetail",
};

pub const USER_BY_SCREEN_NAME: Endpoint = Endpoint {
    id: "sLVLhk0bGj3MVFEKTdax1w",
    name: "UserByScreenName",
};

pub const USER_TWEETS: Endpoint = Endpoint {
    id: "HuTx74BxAnezK1gWvYY7zg",
    name: "UserTweets",
};

impl Endpoint {
    pub fn url(&self) -> String {
        format!("{BASE_URL}/{}/{}", self.id, self.name)
    }
}

/// Canonical GraphQL feature flags (from go-twitter gqlFeatures()).
pub fn features_json() -> String {
    serde_json::json!({
        "articles_preview_enabled": false,
        "c9s_tweet_anatomy_moderator_badge_enabled": true,
        "communities_web_enable_tweet_community_results_fetch": true,
        "creator_subscriptions_quote_tweet_preview_enabled": false,
        "creator_subscriptions_tweet_preview_api_enabled": true,
        "freedom_of_speech_not_reach_fetch_enabled": true,
        "graphql_is_translatable_rweb_tweet_is_translatable_enabled": true,
        "longform_notetweets_consumption_enabled": true,
        "longform_notetweets_inline_media_enabled": true,
        "longform_notetweets_rich_text_read_enabled": true,
        "premium_content_api_read_enabled": false,
        "profile_label_improvements_pcf_label_in_post_enabled": false,
        "responsive_web_edit_tweet_api_enabled": true,
        "responsive_web_enhance_cards_enabled": false,
        "responsive_web_graphql_exclude_directive_enabled": true,
        "responsive_web_graphql_skip_user_profile_image_extensions_enabled": false,
        "responsive_web_graphql_timeline_navigation_enabled": true,
        "responsive_web_grok_analyze_button_fetch_trends_enabled": false,
        "responsive_web_grok_analyze_post_followups_enabled": false,
        "responsive_web_grok_image_annotation_enabled": false,
        "responsive_web_grok_share_attachment_enabled": false,
        "responsive_web_media_download_video_enabled": false,
        "responsive_web_twitter_article_tweet_consumption_enabled": true,
        "rweb_tipjar_consumption_enabled": true,
        "rweb_video_timestamps_enabled": true,
        "standardized_nudges_misinfo": true,
        "tweet_awards_web_tipping_enabled": false,
        "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": true,
        "tweet_with_visibility_results_prefer_gql_media_interstitial_enabled": false,
        "tweetypie_unmention_optimization_enabled": true,
        "verified_phone_label_enabled": false,
        "view_counts_everywhere_api_enabled": true
    }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_url_format() {
        assert_eq!(
            TWEET_DETAIL.url(),
            "https://x.com/i/api/graphql/zXaXQgfyR4GxE21uwYQSyA/TweetDetail"
        );
    }

    #[test]
    fn features_json_is_valid() {
        let s = features_json();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.is_object());
        assert_eq!(v.as_object().unwrap().len(), 31);
    }
}
```

- [ ] **Step 2: Create request.rs**

```rust
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
    let resp = client.get(url)
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
}
```

Note: `urlencoding` is already in `Cargo.toml` from Task 1.

**Important:** The bearer token in `graphql.rs` may be flagged by gitleaks pre-commit hook. If the commit is blocked, add this to `.gitleaksignore` in the repo root:
```
crates/twitter/src/graphql.rs:BEARER_TOKEN
```

- [ ] **Step 3: Register in lib.rs**

Add `pub mod graphql;` and `pub mod request;`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p ox-twitter`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/twitter/src/graphql.rs crates/twitter/src/request.rs crates/twitter/src/lib.rs crates/twitter/Cargo.toml
git commit -m "feat(twitter): GraphQL endpoints, features, and request builder"
```

---

## Task 5: GraphQL response parser

Port `parseTweetResult`, `extractTweetsFromTimeline`, `parseUserResult` from go-twitter's `parsers.go`.

**Files:**
- Create: `crates/twitter/src/parser.rs`
- Modify: `crates/twitter/src/lib.rs`

- [ ] **Step 1: Write tests with mock JSON**

Construct test fixtures from go-twitter's inline struct shapes. The key challenge: TweetDetail uses a timeline wrapper, not a flat response.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tweet_from_timeline() {
        let json = serde_json::json!({
            "data": {
                "threaded_conversation_with_injections_v2": {
                    "instructions": [{
                        "type": "TimelineAddEntries",
                        "entries": [{
                            "content": {
                                "entryType": "TimelineTimelineItem",
                                "itemContent": {
                                    "__typename": "TimelineTweet",
                                    "tweet_results": {
                                        "result": {
                                            "rest_id": "123",
                                            "legacy": {
                                                "full_text": "Hello from GraphQL",
                                                "user_id_str": "456",
                                                "created_at": "Mon Mar 24 12:00:00 +0000 2026",
                                                "favorite_count": 42,
                                                "retweet_count": 10,
                                                "quote_count": 3,
                                                "reply_count": 5
                                            },
                                            "views": { "count": "1000" },
                                            "core": {
                                                "user_results": {
                                                    "result": {
                                                        "legacy": {
                                                            "screen_name": "testuser",
                                                            "name": "Test User"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }]
                    }]
                }
            }
        });
        let tweets = parse_tweet_detail(&json.to_string()).unwrap();
        assert_eq!(tweets.len(), 1);
        assert_eq!(tweets[0].id, "123");
        assert_eq!(tweets[0].text, "Hello from GraphQL");
        assert_eq!(tweets[0].likes, 42);
        assert_eq!(tweets[0].views, 1000);
        assert_eq!(tweets[0].author_screen_name, "testuser");
    }

    #[test]
    fn parse_user_by_screen_name() {
        let json = serde_json::json!({
            "data": {
                "user": {
                    "result": {
                        "rest_id": "456",
                        "legacy": {
                            "screen_name": "testuser",
                            "name": "Test User",
                            "description": "A test bio",
                            "followers_count": 1000,
                            "friends_count": 100,
                            "statuses_count": 5000,
                            "verified": false
                        },
                        "is_blue_verified": true
                    }
                }
            }
        });
        let profile = parse_user_profile(&json.to_string()).unwrap();
        assert_eq!(profile.screen_name, "testuser");
        assert_eq!(profile.bio, "A test bio");
        assert_eq!(profile.followers, 1000);
        assert!(profile.verified);
    }

    #[test]
    fn parse_empty_timeline() {
        let json = r#"{"data":{"threaded_conversation_with_injections_v2":{"instructions":[]}}}"#;
        let tweets = parse_tweet_detail(json).unwrap();
        assert!(tweets.is_empty());
    }
}
```

- [ ] **Step 2: Implement parser.rs**

```rust
//! Parse Twitter GraphQL JSON responses into typed structs.
//! Ported from go-twitter/parsers.go.

use crate::types::{Tweet, UserProfile};

/// Parse TweetDetail GraphQL response. Returns all tweets in the conversation
/// (focal tweet is typically first).
pub fn parse_tweet_detail(body: &str) -> Option<Vec<Tweet>> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    // Try known timeline keys — Twitter has used different names historically
    let instructions = v["data"]["threaded_conversation_with_injections_v2"]["instructions"]
        .as_array()
        .or_else(|| v["data"]["tweetResult"]["result"]["timeline"]["instructions"].as_array())?;
    let mut tweets = Vec::new();
    for instruction in instructions {
        let entries = match instruction["entries"].as_array() {
            Some(e) => e,
            None => continue,
        };
        for entry in entries {
            let item = &entry["content"]["itemContent"];
            if item.is_null() {
                continue;
            }
            if item["__typename"].as_str() != Some("TimelineTweet") {
                continue;
            }
            if let Some(tweet) = parse_tweet_result(&item["tweet_results"]["result"]) {
                tweets.push(tweet);
            }
        }
    }
    Some(tweets)
}

/// Parse UserByScreenName GraphQL response.
pub fn parse_user_profile(body: &str) -> Option<UserProfile> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let result = &v["data"]["user"]["result"];
    parse_user_result(result)
}

/// Parse UserTweets timeline response.
pub fn parse_user_tweets(body: &str) -> Option<Vec<Tweet>> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let result = &v["data"]["user"]["result"];
    // Try timeline_v2 first, then timeline (go-twitter logic).
    // Match Go's len(tl.Instructions) == 0 check — not .is_null() which misses empty arrays.
    let v2_instructions = result["timeline_v2"]["timeline"]["instructions"].as_array();
    let tl = if v2_instructions.is_some_and(|a| !a.is_empty()) {
        &result["timeline_v2"]["timeline"]
    } else {
        &result["timeline"]["timeline"]
    };
    let instructions = tl["instructions"].as_array()?;
    let mut tweets = Vec::new();
    for instruction in instructions {
        let entries = match instruction["entries"].as_array() {
            Some(e) => e,
            None => continue,
        };
        for entry in entries {
            let item = &entry["content"]["itemContent"];
            if item.is_null() {
                continue;
            }
            if item["__typename"].as_str() != Some("TimelineTweet") {
                continue;
            }
            if let Some(tweet) = parse_tweet_result(&item["tweet_results"]["result"]) {
                tweets.push(tweet);
            }
        }
    }
    Some(tweets)
}

fn parse_tweet_result(r: &serde_json::Value) -> Option<Tweet> {
    let id = r["rest_id"].as_str()?.to_string();
    let legacy = &r["legacy"];
    let user = &r["core"]["user_results"]["result"]["legacy"];
    Some(Tweet {
        id,
        text: legacy["full_text"].as_str().unwrap_or("").to_string(),
        author_id: legacy["user_id_str"].as_str().unwrap_or("").to_string(),
        author_name: user["name"].as_str().unwrap_or("").to_string(),
        author_screen_name: user["screen_name"].as_str().unwrap_or("").to_string(),
        created_at: legacy["created_at"].as_str().unwrap_or("").to_string(),
        likes: legacy["favorite_count"].as_u64().unwrap_or(0),
        retweets: legacy["retweet_count"].as_u64().unwrap_or(0),
        quotes: legacy["quote_count"].as_u64().unwrap_or(0),
        replies: legacy["reply_count"].as_u64().unwrap_or(0),
        views: r["views"]["count"].as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    })
}

fn parse_user_result(r: &serde_json::Value) -> Option<UserProfile> {
    let id = r["rest_id"].as_str()?.to_string();
    let legacy = &r["legacy"];
    let verified = legacy["verified"].as_bool().unwrap_or(false)
        || r["is_blue_verified"].as_bool().unwrap_or(false);
    Some(UserProfile {
        id,
        name: legacy["name"].as_str().unwrap_or("").to_string(),
        screen_name: legacy["screen_name"].as_str().unwrap_or("").to_string(),
        bio: legacy["description"].as_str().unwrap_or("").trim().to_string(),
        followers: legacy["followers_count"].as_u64().unwrap_or(0),
        following: legacy["friends_count"].as_u64().unwrap_or(0),
        tweet_count: legacy["statuses_count"].as_u64().unwrap_or(0),
        verified,
        recent_tweets: vec![],
    })
}
```

- [ ] **Step 3: Register in lib.rs**

Add `pub mod parser;`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p ox-twitter`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/twitter/src/parser.rs crates/twitter/src/lib.rs
git commit -m "feat(twitter): GraphQL response parser (TweetDetail, UserProfile, UserTweets)"
```

---

## Task 6: Fallback client + formatter

**Files:**
- Create: `crates/twitter/src/client.rs`
- Create: `crates/twitter/src/format.rs`
- Modify: `crates/twitter/src/lib.rs`

- [ ] **Step 1: Create format.rs with tests**

```rust
//! Format Tweet and UserProfile into human-readable text.

use crate::types::{Tweet, UserProfile};

pub fn format_tweet(t: &Tweet) -> String {
    let mut s = format!("@{}", t.author_screen_name);
    if !t.created_at.is_empty() {
        s.push_str(&format!(" · {}", &t.created_at));
    }
    s.push_str(&format!("\n\n{}", t.text));
    s.push_str(&format!(
        "\n\n♥ {}  🔁 {}  💬 {}  👁 {}",
        t.likes, t.retweets, t.replies, t.views
    ));
    s
}

pub fn format_profile(p: &UserProfile) -> String {
    let mut s = format!("@{} · {}", p.screen_name, p.name);
    if !p.bio.is_empty() {
        s.push_str(&format!("\n{}", p.bio));
    }
    s.push_str(&format!(
        "\n\nFollowers: {} · Following: {} · Tweets: {}",
        p.followers, p.following, p.tweet_count
    ));
    if !p.recent_tweets.is_empty() {
        s.push_str("\n\n--- Recent tweets ---\n");
        for t in &p.recent_tweets {
            s.push_str(&format!("\n[♥ {}] {}", t.likes, truncate(&t.text, 120)));
        }
    }
    s
}

pub fn truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        s
    } else {
        let mut idx = max_bytes;
        while idx > 0 && !s.is_char_boundary(idx) {
            idx -= 1;
        }
        &s[..idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Tweet;

    #[test]
    fn format_tweet_output() {
        let t = Tweet {
            id: "1".into(), text: "Hello world".into(),
            author_id: "2".into(), author_name: "Test".into(),
            author_screen_name: "test".into(), created_at: "2026-03-24".into(),
            likes: 42, retweets: 10, quotes: 3, replies: 5, views: 1000,
        };
        let out = format_tweet(&t);
        assert!(out.contains("@test"));
        assert!(out.contains("Hello world"));
        assert!(out.contains("♥ 42"));
    }

    #[test]
    fn format_profile_output() {
        let p = UserProfile {
            id: "1".into(), name: "Test User".into(),
            screen_name: "test".into(), bio: "A bio".into(),
            followers: 1000, following: 100, tweet_count: 5000,
            verified: true, recent_tweets: vec![],
        };
        let out = format_profile(&p);
        assert!(out.contains("@test · Test User"));
        assert!(out.contains("Followers: 1000"));
    }
}
```

- [ ] **Step 2: Create client.rs**

```rust
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
```

- [ ] **Step 3: Register in lib.rs, add re-exports**

```rust
pub mod types;
pub mod url;
pub mod fxtwitter;
pub mod graphql;
pub mod request;
pub mod parser;
pub mod client;
pub mod format;

pub use types::{Tweet, UserProfile};
pub use url::{parse as parse_url, TwitterUrl};
pub use client::{fetch_tweet, fetch_profile};
pub use format::{format_tweet, format_profile};
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p ox-twitter`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/twitter/src/
git commit -m "feat(twitter): fallback client (FxTwitter→GraphQL) + text formatter"
```

---

## Task 7: Site handler + read pipeline integration

**Files:**
- Create: `crates/http/src/site_twitter.rs`
- Modify: `crates/http/src/read_pipeline.rs`
- Modify: `crates/http/src/lib.rs`
- Modify: `crates/http/Cargo.toml`

- [ ] **Step 1: Add ox-twitter dependency to crates/http/Cargo.toml**

Add: `ox-twitter = { path = "../twitter" }`

- [ ] **Step 2: Create site_twitter.rs**

```rust
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
```

- [ ] **Step 3: Register site_twitter in lib.rs**

Add `pub mod site_twitter;` to `crates/http/src/lib.rs`.

- [ ] **Step 4: Add try_twitter to read_pipeline.rs**

After the `try_reddit_json` block, add:

```rust
// Twitter/X handler
if let Some(output) = crate::site_twitter::try_twitter(params, format, start).await {
    return output;
}
```

- [ ] **Step 5: Run all tests**

Run: `cd /home/krolik/src/ox-browser && cargo test --workspace`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/http/src/site_twitter.rs crates/http/src/lib.rs crates/http/src/read_pipeline.rs crates/http/Cargo.toml
git commit -m "feat(twitter): site handler in read pipeline with fallback chain"
```

---

## Task 8: Rate limiting + deploy + verify

**Files:**
- Modify: `src/config/ratelimit.rs`

- [ ] **Step 1: Add x.com rate limit rule**

In `src/config/ratelimit.rs`, add to the default rules vec (before the catch-all):

```rust
RatelimitRule {
    domain: "*.x.com".into(),
    requests_per_window: 40,
    window_secs: 900,
    min_delay_ms: 1000,
    random_delay_ms: 500,
},
```

- [ ] **Step 2: Run tests**

Run: `cargo test --workspace`

- [ ] **Step 3: Commit**

```bash
git add src/config/ratelimit.rs
git commit -m "feat(ratelimit): add x.com rate limit rule (40 req/15min)"
```

- [ ] **Step 4: Build and deploy**

```bash
cd ~/deploy/krolik-server
docker compose build ox-browser
docker compose up -d --no-deps --force-recreate ox-browser
```

- [ ] **Step 5: Verify health**

```bash
curl -sf http://127.0.0.1:8901/health
```

- [ ] **Step 6: Test tweet**

```bash
curl -s -X POST http://127.0.0.1:8901/read \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://x.com/rustlang/status/1904338529518715034","format":"text","max_length":500}'
```
Expected: `method=twitter`, tweet content with @author, likes, retweets

- [ ] **Step 7: Test profile**

```bash
curl -s -X POST http://127.0.0.1:8901/read \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://x.com/rustlang","format":"text","max_length":500}'
```
Expected: `method=twitter`, profile with bio, followers, recent tweets

---

## Dependency Graph

```
Task 1 (types + scaffold) ──→ Task 2 (URL parser)
Task 1 ──→ Task 3 (FxTwitter)
Task 1 ──→ Task 4 (GraphQL + request)
Task 4 ──→ Task 5 (parser)
Tasks 2,3,5 ──→ Task 6 (client + formatter)
Task 6 ──→ Task 7 (site handler + pipeline)
Task 7 ──→ Task 8 (rate limit + deploy)
```

Parallel: Tasks 2, 3, 4 can run in parallel after Task 1.
Task 5 depends on Task 4.
Task 6 depends on Tasks 2, 3, 5.
Task 7 depends on Task 6.
Task 8 depends on Task 7.
