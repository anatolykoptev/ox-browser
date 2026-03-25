//! Execute Twitter GraphQL HTTP requests with guest token auth.
//!
//! Guest token activation ported from go-twitter/auth.go.
//! URL building and query variables live in `request_vars`.

use std::sync::Mutex;
use std::time::Instant;

use crate::graphql::BEARER_TOKEN;

// Re-export URL builders for callers using `request::` prefix.
pub use crate::request_vars::{
    build_url, tweet_detail_vars, user_by_screen_name_vars, user_tweets_vars,
};

const TWITTER_API_URL: &str = "https://api.twitter.com";

/// Cached guest token with expiry tracking.
static GUEST_TOKEN: Mutex<Option<GuestToken>> = Mutex::new(None);

struct GuestToken {
    token: String,
    acquired_at: Instant,
}

/// Guest token TTL — reacquire after 3 hours.
const GUEST_TOKEN_TTL_SECS: u64 = 3 * 3600;

/// Execute a GraphQL GET request with guest token and proper Twitter headers.
///
/// Ported from go-twitter: activates guest token on first call,
/// caches it, reacquires on 401/403.
pub async fn execute(url: &str) -> Result<String, String> {
    let guest_token = get_or_activate_guest_token().await?;
    let xtid = crate::xtid_header("GET", url).await;

    let resp = do_graphql_get(url, &guest_token, xtid.as_deref()).await?;
    if resp.0 == 200 {
        return Ok(resp.1);
    }

    // On 401/403 — reacquire guest token and retry once
    if resp.0 == 401 || resp.0 == 403 {
        tracing::warn!(status = resp.0, "graphql: guest token rejected, reacquiring");
        clear_guest_token();
        let new_token = activate_guest_token().await?;
        save_guest_token(&new_token);

        let resp2 = do_graphql_get(url, &new_token, xtid.as_deref()).await?;
        if resp2.0 == 200 {
            return Ok(resp2.1);
        }
        return Err(format!("GraphQL HTTP {} after token refresh", resp2.0));
    }

    Err(format!("GraphQL HTTP {}", resp.0))
}

/// GET with guest token headers (ported from go-twitter/headers.go:guestHeaders).
async fn do_graphql_get(
    url: &str,
    guest_token: &str,
    xtid: Option<&str>,
) -> Result<(u16, String), String> {
    let bearer = format!("Bearer {BEARER_TOKEN}");
    let mut pairs: Vec<(&str, &str)> = vec![
        ("authorization", &bearer),
        ("x-guest-token", guest_token),
        ("x-twitter-active-user", "yes"),
        ("x-twitter-client-language", "en"),
        ("content-type", "application/json"),
        ("user-agent", crate::TWITTER_USER_AGENT),
        ("accept", "*/*"),
        ("accept-language", "en-US,en;q=0.9"),
        ("referer", "https://twitter.com/"),
        ("origin", "https://twitter.com"),
    ];

    let xtid_owned;
    if let Some(tid) = xtid {
        xtid_owned = tid.to_string();
        pairs.push(("x-client-transaction-id", &xtid_owned));
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
    Ok((resp.status, resp.body))
}

/// Get cached guest token or activate a new one.
async fn get_or_activate_guest_token() -> Result<String, String> {
    {
        let cache = GUEST_TOKEN.lock().unwrap();
        if let Some(ref gt) = *cache
            && gt.acquired_at.elapsed().as_secs() < GUEST_TOKEN_TTL_SECS
        {
            return Ok(gt.token.clone());
        }
    }
    let token = activate_guest_token().await?;
    save_guest_token(&token);
    Ok(token)
}

/// Activate a guest token via Twitter API.
/// Ported from go-twitter/auth.go:getGuestToken.
async fn activate_guest_token() -> Result<String, String> {
    tracing::debug!("activating guest token");
    let req = ox_http::middleware::Request {
        method: "POST".to_string(),
        url: format!("{TWITTER_API_URL}/1.1/guest/activate.json"),
        headers: vec![
            ("authorization".to_string(), format!("Bearer {BEARER_TOKEN}")),
            ("content-type".to_string(), "application/json".to_string()),
            ("user-agent".to_string(), crate::TWITTER_USER_AGENT.to_string()),
        ],
        body: None,
        proxy: None,
    };

    let resp = crate::tw_http::twitter_http()
        .execute(req)
        .await
        .map_err(|e| format!("guest token request failed: {e}"))?;

    if resp.status != 200 {
        return Err(format!("guest token HTTP {}", resp.status));
    }

    let v: serde_json::Value =
        serde_json::from_str(&resp.body).map_err(|e| format!("guest token parse: {e}"))?;
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

    #[test]
    fn guest_token_cache_starts_empty() {
        // Check it doesn't panic regardless of test order
        let cache = GUEST_TOKEN.lock().unwrap();
        drop(cache);
    }
}
