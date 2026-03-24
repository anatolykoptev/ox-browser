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

/// Truncate a string to max_bytes, ensuring valid UTF-8 boundary.
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

    #[test]
    fn truncate_ascii() {
        assert_eq!(truncate("hello world", 5), "hello");
    }

    #[test]
    fn truncate_utf8_boundary() {
        // Russian text — each char is 2 bytes
        let s = "Привет мир";
        let t = truncate(s, 7);
        // Should not split in middle of a char
        assert!(t.len() <= 7);
        assert_eq!(t, "При"); // 3 chars × 2 bytes = 6 bytes
    }
}
