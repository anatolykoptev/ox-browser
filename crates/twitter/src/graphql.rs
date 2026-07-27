//! Twitter GraphQL API constants — endpoints, bearer token, feature flags.
//! Ported from go-twitter/endpoints.go.

/// Public bearer token from Twitter's web app JS (decoded form for Authorization header).
pub const BEARER_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs=1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";

/// Alternative bearer token (from imperatrona/twitter-scraper) — does NOT require
/// x-client-transaction-id header. Used for login flow only.
pub const BEARER_TOKEN_LOGIN: &str = "AAAAAAAAAAAAAAAAAAAAAFQODgEAAAAAVHTp76lzh3rFzcHbmHVvQxYYpTw=";

const BASE_URL: &str = "https://x.com/i/api/graphql";

pub struct Endpoint {
    pub id: &'static str,
    pub name: &'static str,
}

pub const TWEET_DETAIL: Endpoint = Endpoint {
    id: "VWFGPVAGkZMGRKGe3GFFnA",
    name: "TweetDetail",
};

pub const USER_BY_SCREEN_NAME: Endpoint = Endpoint {
    id: "sLVLhk0bGj3MVFEKTdax1w",
    name: "UserByScreenName",
};

pub const USER_BY_REST_ID: Endpoint = Endpoint {
    id: "GazOglcBvgLigl3ywt6b3Q",
    name: "UserByRestId",
};

pub const USER_TWEETS: Endpoint = Endpoint {
    id: "HuTx74BxAnezK1gWvYY7zg",
    name: "UserTweets",
};

pub const FOLLOWERS: Endpoint = Endpoint {
    id: "pd8Tt1qUz1YWrICegqZ8cw",
    name: "Followers",
};

pub const FOLLOWING: Endpoint = Endpoint {
    id: "wjvx62Hye2dGVvnvVco0xA",
    name: "Following",
};

pub const SEARCH_TIMELINE: Endpoint = Endpoint {
    id: "nK1dw4oV3k4w5TdtcAdSww",
    name: "SearchTimeline",
};

pub const RETWEETERS: Endpoint = Endpoint {
    id: "0BoJlKAxoNPQUHRftlwZ2w",
    name: "Retweeters",
};

pub const CREATE_TWEET: Endpoint = Endpoint {
    id: "7TKRKCPuAGsmYde0CudbVg",
    name: "CreateTweet",
};

impl Endpoint {
    pub fn url(&self) -> String {
        format!("{BASE_URL}/{}/{}", self.id, self.name)
    }
}

/// Canonical GraphQL feature flags (from go-twitter gqlFeatures()).
/// 32 flags ported exactly from go-twitter endpoints.go lines 54-89.
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
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_url_format() {
        assert_eq!(
            TWEET_DETAIL.url(),
            "https://x.com/i/api/graphql/VWFGPVAGkZMGRKGe3GFFnA/TweetDetail"
        );
    }

    #[test]
    fn features_json_is_valid() {
        let s = features_json();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.is_object());
        // 32 feature flags ported from go-twitter
        assert_eq!(v.as_object().unwrap().len(), 32);
    }

    #[test]
    fn all_endpoints_have_correct_ids() {
        assert_eq!(USER_BY_SCREEN_NAME.id, "sLVLhk0bGj3MVFEKTdax1w");
        assert_eq!(USER_TWEETS.id, "HuTx74BxAnezK1gWvYY7zg");
        assert_eq!(SEARCH_TIMELINE.id, "nK1dw4oV3k4w5TdtcAdSww");
    }
}
