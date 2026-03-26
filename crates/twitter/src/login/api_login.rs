//! Twitter API login — matches twikit's exact HTTP flow.
//! No browser needed: direct HTTP POST with flow_token chaining.
//!
//! Flow: guest_activate → sso_init → onboarding/task.json (login flow)
//! No pre-seeding, no xtid, no TLS emulation — matches twikit exactly.

use std::collections::HashMap;
use std::sync::Arc;

use super::error::TwitterLoginError;
use super::LoginRequest;

mod flow {
    pub(super) use super::super::api_flow::FlowState;
}

const API_BASE: &str = "https://api.x.com";

/// Successful API login result.
pub struct ApiLoginResult {
    pub auth_token: String,
    pub ct0: String,
    pub cookies: HashMap<String, String>,
}

/// Perform login via Twitter's internal API (no browser needed).
/// Matches twikit's flow exactly: no pre-seeding, no xtid, no TLS emulation.
pub async fn login(req: &LoginRequest) -> Result<ApiLoginResult, TwitterLoginError> {
    tracing::info!(username = %req.username, "API login: starting");

    let jar = Arc::new(wreq::cookie::Jar::default());
    let client = build_client(Arc::clone(&jar), req.proxy.as_deref())?;

    // Step 1: get guest token
    let guest_token = get_guest_token(&client).await?;
    tracing::info!(guest_token = %guest_token, "API login: got guest token");

    // Step 2: sso_init (twikit calls this before login flow, result discarded)
    let _ = sso_init(&client, &guest_token).await;

    // Step 3: init login flow (no csrf token — server hasn't issued one yet)
    let mut state = flow::FlowState::init(&client, &guest_token, None).await?;
    tracing::info!(task = %state.current_task(), "API login: flow initialized");

    // After init, check if server set ct0 cookie
    update_csrf_from_jar(&jar, &mut state);

    // Step 4: JS instrumentation
    state.js_instrumentation(&client).await?;
    tracing::info!(task = %state.current_task(), "API login: js instrumentation");
    update_csrf_from_jar(&jar, &mut state);

    // Step 5: enter username
    state.enter_username(&client, &req.username).await?;
    tracing::info!(task = %state.current_task(), "API login: username entered");

    // Step 5a: alternate identifier if needed
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
        let msg = state.deny_message().unwrap_or_else(|| "login denied".into());
        return Err(TwitterLoginError::WrongCredentials {
            message: msg,
            screenshot: None,
        });
    }

    // Step 6: enter password
    state.enter_password(&client, &req.password).await?;
    tracing::info!(task = %state.current_task(), "API login: password entered");

    if state.current_task() == "DenyLoginSubtask" {
        let msg = state.deny_message().unwrap_or_else(|| "wrong password".into());
        return Err(TwitterLoginError::WrongCredentials {
            message: msg,
            screenshot: None,
        });
    }

    // Step 6a: 2FA if needed
    if state.current_task() == "LoginTwoFactorAuthChallenge" {
        let secret = req.totp_secret.as_deref().ok_or_else(|| {
            TwitterLoginError::TotpFailed("no TOTP secret".into())
        })?;
        let code = super::flow::actions::generate_totp(secret)?;
        state.enter_text(&client, "LoginTwoFactorAuthChallenge", &code).await?;
        tracing::info!(task = %state.current_task(), "API login: 2FA done");
    }

    // Step 6b: LoginAcid (email verification)
    if state.current_task() == "LoginAcid" {
        return Err(TwitterLoginError::EmailVerificationRequired);
    }

    // Step 7: duplication check
    state.duplication_check(&client).await?;

    // Extract cookies
    let cookies = extract_cookies(&jar);
    let auth_token = cookies.get("auth_token").cloned()
        .ok_or(TwitterLoginError::CookiesNotFound)?;
    let ct0 = cookies.get("ct0").cloned()
        .ok_or(TwitterLoginError::CookiesNotFound)?;

    tracing::info!(username = %req.username, "API login: success");
    Ok(ApiLoginResult { auth_token, ct0, cookies })
}

/// Build wreq client — NO TLS emulation (twikit uses plain httpx).
fn build_client(
    jar: Arc<wreq::cookie::Jar>,
    proxy: Option<&str>,
) -> Result<wreq::Client, TwitterLoginError> {
    let mut builder = wreq::Client::builder()
        .cookie_provider(jar)
        .user_agent(crate::TWITTER_USER_AGENT);

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

/// POST /1.1/guest/activate.json — get guest token.
async fn get_guest_token(client: &wreq::Client) -> Result<String, TwitterLoginError> {
    let url = format!("{API_BASE}/1.1/guest/activate.json");
    let headers = super::api_headers::guest_activate_headers();

    let resp = client
        .post(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| TwitterLoginError::ApiError { status: 0, body: e.to_string() })?;

    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await
        .map_err(|e| TwitterLoginError::ApiError { status, body: e.to_string() })?;

    body["guest_token"].as_str().map(|s| s.to_string())
        .ok_or_else(|| TwitterLoginError::ApiError {
            status,
            body: "no guest_token in response".into(),
        })
}

/// POST /1.1/onboarding/sso_init.json — twikit calls this, result discarded.
async fn sso_init(client: &wreq::Client, guest_token: &str) -> Result<(), TwitterLoginError> {
    let url = format!("{API_BASE}/1.1/onboarding/sso_init.json");
    let headers = super::api_headers::onboarding_headers(guest_token, None);
    client.post(&url).headers(headers)
        .json(&serde_json::json!({"provider": "apple"}))
        .send().await
        .map_err(|e| TwitterLoginError::ApiError { status: 0, body: format!("sso_init: {e}") })?;
    Ok(())
}

/// If server set ct0 cookie, use it as CSRF token for subsequent requests.
fn update_csrf_from_jar(jar: &wreq::cookie::Jar, state: &mut flow::FlowState) {
    for cookie in jar.get_all() {
        if cookie.name() == "ct0" {
            let val = cookie.value().to_string();
            if !val.is_empty() {
                state.set_csrf_token(&val);
                return;
            }
        }
    }
}

fn extract_cookies(jar: &wreq::cookie::Jar) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for cookie in jar.get_all() {
        map.insert(cookie.name().to_string(), cookie.value().to_string());
    }
    map
}
