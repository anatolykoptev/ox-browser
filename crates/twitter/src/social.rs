//! go-social integration: fetch tweets via go-social's server-side GraphQL.
//!
//! go-social handles account acquisition, TLS fingerprinting (go-stealth),
//! and result reporting internally. ox-browser just calls GET /twitter/tweet/{id}.

use crate::types::Tweet;

const GO_SOCIAL_TOKEN_ENV: &str = "GO_SOCIAL_TOKEN";

/// go-twitter's Tweet JSON format uses PascalCase (Go default, no json tags).
#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct GoTweet {
    ID: String,
    AuthorID: Option<String>,
    AuthorHandle: Option<String>,
    AuthorName: Option<String>,
    Text: String,
    CreatedAt: Option<String>,
    Views: Option<u64>,
    Likes: Option<u64>,
    Retweets: Option<u64>,
    Quotes: Option<u64>,
    ReplyCount: Option<u64>,
}

impl From<GoTweet> for Tweet {
    fn from(g: GoTweet) -> Self {
        Tweet {
            id: g.ID,
            text: g.Text,
            author_id: g.AuthorID.unwrap_or_default(),
            author_name: g.AuthorName.unwrap_or_default(),
            author_screen_name: g.AuthorHandle.unwrap_or_default(),
            created_at: g.CreatedAt.unwrap_or_default(),
            likes: g.Likes.unwrap_or(0),
            retweets: g.Retweets.unwrap_or(0),
            quotes: g.Quotes.unwrap_or(0),
            replies: g.ReplyCount.unwrap_or(0),
            views: g.Views.unwrap_or(0),
        }
    }
}

/// Fetch tweet via go-social: delegates GraphQL request to go-social which uses
/// go-twitter with matching TLS fingerprint (go-stealth/bogdanfinn).
pub async fn fetch_tweet(base_url: &str, tweet_id: &str) -> Result<Tweet, String> {
    let token = std::env::var(GO_SOCIAL_TOKEN_ENV).unwrap_or_default();

    let client = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("{base_url}/twitter/tweet/{tweet_id}");
    let resp = client
        .get(&url)
        .header("authorization", format!("Bearer {token}"))
        .header("x-consumer", "ox-browser")
        .send()
        .await
        .map_err(|e| format!("go-social tweet request: {e}"))?;

    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("go-social read: {e}"))?;

    match status {
        200 => {
            let go_tweet: GoTweet =
                serde_json::from_str(&body).map_err(|e| format!("go-social parse: {e}"))?;
            Ok(go_tweet.into())
        }
        404 => Err(format!("go-social: tweet {tweet_id} not found")),
        429 => Err("go-social: rate limited".to_string()),
        502 => Err(format!("go-social: upstream error — {body}")),
        _ => Err(format!("go-social HTTP {status}: {body}")),
    }
}
