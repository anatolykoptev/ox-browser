//! Parse Twitter GraphQL JSON responses into typed structs.
//! Ported from go-twitter/parsers.go.

use crate::types::{Tweet, UserProfile};

/// Parse TweetDetail GraphQL response.
pub fn parse_tweet_detail(body: &str) -> Option<Vec<Tweet>> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    // Try known timeline keys — Twitter uses different names
    let instructions = v["data"]["threaded_conversation_with_injections_v2"]["instructions"]
        .as_array()
        .or_else(|| v["data"]["tweetResult"]["result"]["timeline"]["instructions"].as_array())?;
    extract_tweets_from_instructions(instructions)
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
    // Try timeline_v2 first, then timeline (matches go-twitter logic).
    let v2_instructions = result["timeline_v2"]["timeline"]["instructions"].as_array();
    let tl = if v2_instructions.is_some_and(|a| !a.is_empty()) {
        &result["timeline_v2"]["timeline"]
    } else {
        &result["timeline"]["timeline"]
    };
    let instructions = tl["instructions"].as_array()?;
    extract_tweets_from_instructions(instructions)
}

fn extract_tweets_from_instructions(instructions: &[serde_json::Value]) -> Option<Vec<Tweet>> {
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
        views: r["views"]["count"]
            .as_str()
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
        bio: legacy["description"]
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string(),
        followers: legacy["followers_count"].as_u64().unwrap_or(0),
        following: legacy["friends_count"].as_u64().unwrap_or(0),
        tweet_count: legacy["statuses_count"].as_u64().unwrap_or(0),
        verified,
        recent_tweets: vec![],
    })
}

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

    #[test]
    fn parse_user_tweets_v2() {
        let json = serde_json::json!({
            "data": {
                "user": {
                    "result": {
                        "timeline_v2": {
                            "timeline": {
                                "instructions": [{
                                    "entries": [{
                                        "content": {
                                            "itemContent": {
                                                "__typename": "TimelineTweet",
                                                "tweet_results": {
                                                    "result": {
                                                        "rest_id": "789",
                                                        "legacy": {
                                                            "full_text": "User tweet",
                                                            "user_id_str": "456",
                                                            "favorite_count": 5,
                                                            "retweet_count": 1,
                                                            "quote_count": 0,
                                                            "reply_count": 0
                                                        },
                                                        "views": { "count": "50" },
                                                        "core": {
                                                            "user_results": {
                                                                "result": {
                                                                    "legacy": {
                                                                        "screen_name": "testuser",
                                                                        "name": "Test"
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
                    }
                }
            }
        });
        let tweets = parse_user_tweets(&json.to_string()).unwrap();
        assert_eq!(tweets.len(), 1);
        assert_eq!(tweets[0].id, "789");
        assert_eq!(tweets[0].text, "User tweet");
    }
}
