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
