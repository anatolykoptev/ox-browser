//! go-social integration: fetch Twitter credentials from centralized account pool.
//!
//! Endpoint: `GET /twitter/account` → credentials → GraphQL → `POST /twitter/report/{id}`.

use crate::{graphql, parser, request, types::Tweet};

const GO_SOCIAL_TOKEN_ENV: &str = "GO_SOCIAL_TOKEN";

#[allow(dead_code)]
const TWITTER_BASE_URL: &str = "https://x.com";

/// Response from go-social `GET /twitter/account`.
#[derive(serde::Deserialize)]
struct SocialAcquireResponse {
    id: String,
    credentials: std::collections::HashMap<String, String>,
    #[serde(default)]
    #[allow(dead_code)]
    proxy: String,
}

/// Fetch tweet via go-social: acquire auth credentials, make GraphQL request, report outcome.
pub async fn fetch_tweet(base_url: &str, tweet_id: &str) -> Result<Tweet, String> {
    let token = std::env::var(GO_SOCIAL_TOKEN_ENV).unwrap_or_default();

    let api_client = wreq::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    // Step 1: Acquire credentials from go-social.
    let social = acquire_account(&api_client, base_url, &token).await?;

    let auth_token = social
        .credentials
        .get("auth_token")
        .cloned()
        .unwrap_or_default();
    let ct0 = social
        .credentials
        .get("ct0")
        .cloned()
        .unwrap_or_default();

    if auth_token.is_empty() || ct0.is_empty() {
        let _ = report(&api_client, base_url, &token, &social.id, "auth_error").await;
        return Err("go-social: missing auth_token or ct0".to_string());
    }

    // Step 2: Make TweetDetail GraphQL request with auth cookies via shared ox-http client.
    let vars = request::tweet_detail_vars(tweet_id);
    let url = request::build_url(&graphql::TWEET_DETAIL, &vars);

    // Generate x-client-transaction-id header (optional — proceed without on failure)
    let xtid = crate::xtid_header("GET", &url).await;

    match graphql_get_authed(&url, &auth_token, &ct0, xtid.as_deref()).await {
        Ok(body) => match parser::parse_tweet_detail(&body) {
            Some(tweets) => {
                if let Some(tweet) = tweets.into_iter().find(|t| t.id == tweet_id) {
                    let _ = report(&api_client, base_url, &token, &social.id, "success").await;
                    Ok(tweet)
                } else {
                    let _ = report(&api_client, base_url, &token, &social.id, "auth_error").await;
                    Err(format!("go-social: tweet {tweet_id} not found in response"))
                }
            }
            None => {
                let _ = report(&api_client, base_url, &token, &social.id, "auth_error").await;
                Err("go-social: failed to parse GraphQL response".to_string())
            }
        },
        Err(e) => {
            let report_status = if e.contains("429") || e.contains("rate") {
                "rate_limited"
            } else {
                "auth_error"
            };
            let _ = report(&api_client, base_url, &token, &social.id, report_status).await;
            Err(format!("go-social GraphQL: {e}"))
        }
    }
}

/// Acquire the next available Twitter account from go-social.
async fn acquire_account(
    client: &wreq::Client,
    base_url: &str,
    token: &str,
) -> Result<SocialAcquireResponse, String> {
    let url = format!("{base_url}/twitter/account");
    let resp = client
        .get(&url)
        .header("authorization", format!("Bearer {token}"))
        .header("x-consumer", "ox-browser")
        .send()
        .await
        .map_err(|e| format!("go-social acquire request: {e}"))?;

    let status = resp.status().as_u16();
    if status != 200 {
        return Err(format!("go-social acquire HTTP {status}"));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| format!("go-social acquire read: {e}"))?;
    serde_json::from_str(&body).map_err(|e| format!("go-social acquire parse: {e}"))
}

/// Make a TweetDetail GraphQL GET request using the shared ox-http client with Chrome TLS
/// fingerprinting and Twitter-ordered headers.
async fn graphql_get_authed(
    url: &str,
    auth_token: &str,
    ct0: &str,
    xtid: Option<&str>,
) -> Result<String, String> {
    let cookie = format!("auth_token={auth_token}; ct0={ct0}");
    let bearer = format!("Bearer {}", graphql::BEARER_TOKEN);

    let mut pairs: Vec<(&str, &str)> = vec![
        ("authorization", &bearer),
        ("content-type", "application/json"),
        ("x-csrf-token", ct0),
        ("x-twitter-active-user", "yes"),
        ("x-twitter-auth-type", "OAuth2Session"),
        ("x-twitter-client-language", "en"),
        ("sec-ch-ua", r#""Chromium";v="136", "Not.A/Brand";v="99", "Google Chrome";v="136""#),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", r#""Windows""#),
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-site", "same-origin"),
        ("cookie", &cookie),
        ("user-agent", crate::TWITTER_USER_AGENT),
        ("accept", "*/*"),
        ("accept-language", "en-US,en;q=0.9"),
        ("accept-encoding", "gzip, deflate, br"),
        ("referer", "https://twitter.com/"),
        ("origin", "https://twitter.com"),
    ];
    if let Some(tid) = xtid {
        pairs.push(("x-client-transaction-id", tid));
    }

    let headers = crate::tw_http::ordered_headers(&pairs);
    let req = ox_http::middleware::Request {
        method: "GET".to_string(),
        url: url.to_string(),
        headers,
        body: None,
        proxy: None,
    };

    let resp = crate::tw_http::twitter_http()
        .execute(req)
        .await
        .map_err(|e| e.to_string())?;

    match resp.status {
        200 => Ok(resp.body),
        401 | 403 => Err(format!("auth rejected HTTP {}", resp.status)),
        429 => Err(format!("rate limited HTTP {}", resp.status)),
        _ => Err(format!("GraphQL HTTP {}", resp.status)),
    }
}

/// Report outcome back to go-social for account health tracking.
async fn report(
    client: &wreq::Client,
    base_url: &str,
    token: &str,
    account_id: &str,
    status: &str,
) -> Result<(), String> {
    let url = format!("{base_url}/twitter/report/{account_id}");
    let body = format!(r#"{{"status":"{status}"}}"#);
    client
        .post(&url)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
