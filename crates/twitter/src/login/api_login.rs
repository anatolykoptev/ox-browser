//! Twitter API login — twikit-style HTTP flow via onboarding/task.json.
//! No browser needed: direct HTTP POST with flow_token chaining.

use std::collections::HashMap;
use std::sync::Arc;

use super::api_preseed;
use super::error::TwitterLoginError;
use super::LoginRequest;

mod flow {
    pub(super) use super::super::api_flow::FlowState;
}

const API_BASE: &str = "https://api.x.com";
const GUEST_ACTIVATE: &str = "/1.1/guest/activate.json";

/// Successful API login result.
pub struct ApiLoginResult {
    pub auth_token: String,
    pub ct0: String,
    pub cookies: HashMap<String, String>,
}

/// Perform login via Twitter's internal API (no browser needed).
pub async fn login(
    req: &LoginRequest,
) -> Result<ApiLoginResult, TwitterLoginError> {
    tracing::info!(username = %req.username, "API login: starting");
    let jar = Arc::new(wreq::cookie::Jar::default());
    let client = build_client(Arc::clone(&jar), req.proxy.as_deref())?;
    tracing::info!("API login: client built with Chrome136 emulation");

    // Step 0: pre-seed cookies by visiting x.com + set ct0 in cookie jar
    let ct0 = api_preseed::pre_seed_cookies(&client).await?;
    // ct0 must be in BOTH the cookie jar AND X-Csrf-Token header
    jar.add(
        format!("ct0={ct0}; Domain=.x.com; Path=/; Secure").as_str(),
        "https://api.x.com",
    );
    tracing::info!(ct0_len = ct0.len(), "API login: ct0 pre-seeded + added to jar");

    // Step 1: get guest token + add gt cookie
    let guest_token = get_guest_token(&client).await?;
    jar.add(
        format!("gt={guest_token}; Domain=.x.com; Path=/; Secure").as_str(),
        "https://api.x.com",
    );
    tracing::info!(guest_token = %guest_token, "API login: got guest token");

    // Step 1.5: sso_init (twikit calls this before login flow)
    let _ = sso_init(&client, &guest_token).await;
    tracing::info!("API login: sso_init done");

    // Step 2: init login flow (use pre-seeded ct0 for first request)
    let mut state =
        flow::FlowState::init(&client, &guest_token, Some(&ct0)).await?;
    tracing::info!(task = %state.current_task(), "API login: flow initialized");

    // After init, Twitter sets ct0 in Set-Cookie — extract and use it
    if let Some(real_ct0) = extract_ct0_from_jar(&jar) {
        tracing::info!(ct0_len = real_ct0.len(), "API login: got real ct0 from jar");
        state.set_csrf_token(&real_ct0);
    }

    // Step 3: JS instrumentation
    state.js_instrumentation(&client).await?;
    tracing::info!(task = %state.current_task(), "API login: js instrumentation");

    // Twitter may update ct0 after each step — refresh from jar
    if let Some(updated_ct0) = extract_ct0_from_jar(&jar) {
        state.set_csrf_token(&updated_ct0);
    }

    // Step 4: enter username
    state.enter_username(&client, &req.username).await?;
    tracing::info!(task = %state.current_task(), "API login: username entered");

    // Step 4a: alternate identifier if needed
    if state.current_task() == "LoginEnterAlternateIdentifierSubtask" {
        let alt = req
            .email
            .as_deref()
            .or(req.phone.as_deref())
            .ok_or(TwitterLoginError::MissingEmail)?;
        state
            .enter_text(&client, "LoginEnterAlternateIdentifierSubtask", alt)
            .await?;
        tracing::info!(task = %state.current_task(), "API login: alt id entered");
    }

    if state.current_task() == "DenyLoginSubtask" {
        let msg = state
            .deny_message()
            .unwrap_or_else(|| "login denied".into());
        return Err(TwitterLoginError::WrongCredentials {
            message: msg,
            screenshot: None,
        });
    }

    // Step 5: enter password
    state.enter_password(&client, &req.password).await?;
    tracing::info!(task = %state.current_task(), "API login: password entered");

    if state.current_task() == "DenyLoginSubtask" {
        let msg = state
            .deny_message()
            .unwrap_or_else(|| "wrong password".into());
        return Err(TwitterLoginError::WrongCredentials {
            message: msg,
            screenshot: None,
        });
    }

    // Step 5a: 2FA if needed
    if state.current_task() == "LoginTwoFactorAuthChallenge" {
        let secret = req.totp_secret.as_deref().ok_or_else(|| {
            TwitterLoginError::TotpFailed("no TOTP secret".into())
        })?;
        let code = super::flow::actions::generate_totp(secret)?;
        state
            .enter_text(&client, "LoginTwoFactorAuthChallenge", &code)
            .await?;
        tracing::info!(task = %state.current_task(), "API login: 2FA done");
    }

    // Step 5b: LoginAcid (email verification)
    if state.current_task() == "LoginAcid" {
        return Err(TwitterLoginError::EmailVerificationRequired);
    }

    // Step 6: duplication check
    state.duplication_check(&client).await?;
    tracing::info!("API login: duplication check done");

    // Extract cookies from the shared jar
    let cookies = extract_cookies(&jar);
    let auth_token = cookies
        .get("auth_token")
        .cloned()
        .ok_or(TwitterLoginError::CookiesNotFound)?;
    let final_ct0 = cookies
        .get("ct0")
        .cloned()
        .ok_or(TwitterLoginError::CookiesNotFound)?;

    tracing::info!(
        username = %req.username,
        cookie_count = cookies.len(),
        "API login: success"
    );
    Ok(ApiLoginResult {
        auth_token,
        ct0: final_ct0,
        cookies,
    })
}

fn build_client(
    jar: Arc<wreq::cookie::Jar>,
    proxy: Option<&str>,
) -> Result<wreq::Client, TwitterLoginError> {
    let mut builder = wreq::Client::builder()
        .cookie_provider(jar)
        .user_agent(crate::TWITTER_USER_AGENT)
        .emulation(wreq_util::Emulation::Chrome136);

    if let Some(proxy_url) = proxy {
        let p = wreq::Proxy::all(proxy_url).map_err(|e| TwitterLoginError::ApiError {
            status: 0,
            body: format!("proxy config: {e}"),
        })?;
        builder = builder.proxy(p);
        tracing::info!(proxy = proxy_url, "API login: using proxy");
    }

    builder.build().map_err(|e| TwitterLoginError::ApiError {
        status: 0,
        body: format!("client build: {e}"),
    })
}

async fn get_guest_token(
    client: &wreq::Client,
) -> Result<String, TwitterLoginError> {
    let url = format!("{API_BASE}{GUEST_ACTIVATE}");

    // Generate xtid for guest/activate too
    let mut headers = super::api_headers::guest_activate_headers();
    if let Some(xtid) = crate::xtid_header("POST", &url).await {
        if let Ok(v) = wreq::header::HeaderValue::from_str(&xtid) {
            headers.insert("x-client-transaction-id", v);
        }
    }

    let resp = client
        .post(&url)
        .headers(headers)
        .body("{}")  // twikit sends data={} (empty form), httpx sends Content-Length: 0
        .send()
        .await
        .map_err(|e| TwitterLoginError::ApiError {
            status: 0,
            body: e.to_string(),
        })?;

    let status = resp.status().as_u16();
    let body: serde_json::Value =
        resp.json().await.map_err(|e| TwitterLoginError::ApiError {
            status,
            body: e.to_string(),
        })?;

    body["guest_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| TwitterLoginError::ApiError {
            status,
            body: "no guest_token in response".into(),
        })
}

/// Call sso_init('apple') — twikit does this before the login flow.
/// Response is discarded, but it may set server-side session state.
async fn sso_init(
    client: &wreq::Client,
    guest_token: &str,
) -> Result<(), TwitterLoginError> {
    let url = format!("{API_BASE}/1.1/onboarding/sso_init.json");
    let mut headers = super::api_headers::onboarding_headers(guest_token, None);
    if let Some(xtid) = crate::xtid_header("POST", &url).await {
        if let Ok(v) = wreq::header::HeaderValue::from_str(&xtid) {
            headers.insert("x-client-transaction-id", v);
        }
    }
    client
        .post(&url)
        .headers(headers)
        .json(&serde_json::json!({"provider": "apple"}))
        .send()
        .await
        .map_err(|e| TwitterLoginError::ApiError {
            status: 0,
            body: format!("sso_init: {e}"),
        })?;
    Ok(())
}

fn extract_cookies(jar: &wreq::cookie::Jar) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for cookie in jar.get_all() {
        map.insert(cookie.name().to_string(), cookie.value().to_string());
    }
    map
}

/// Extract ct0 cookie from jar (set by Twitter via Set-Cookie after init).
fn extract_ct0_from_jar(jar: &wreq::cookie::Jar) -> Option<String> {
    for cookie in jar.get_all() {
        if cookie.name() == "ct0" {
            let val = cookie.value().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}
