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
    "settings",
    "home",
    "explore",
    "search",
    "notifications",
    "messages",
    "i",
    "login",
    "logout",
    "signup",
];

/// Parse a URL. Returns `Some(TwitterUrl)` if it's a twitter.com/x.com URL, `None` otherwise.
pub fn parse(raw: &str) -> Option<TwitterUrl> {
    let url = Url::parse(raw).ok()?;
    let host = url.host_str()?;
    if !host.contains("twitter.com") && !host.contains("x.com") {
        return None;
    }

    let segments: Vec<&str> = url.path_segments()?.filter(|s| !s.is_empty()).collect();

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
        assert!(parse("https://x.com/i/flow/login").is_none());
    }
}
