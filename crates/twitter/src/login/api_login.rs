//! Twitter API login — twikit-style HTTP flow via onboarding/task.json.
//! No browser needed: direct HTTP POST with flow_token chaining.

use std::collections::HashMap;
use std::sync::Arc;

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
pub async fn login(req: &LoginRequest) -> Result<ApiLoginResult, TwitterLoginError> {
    let jar = Arc::new(wreq::cookie::Jar::default());
    let client = build_client(Arc::clone(&jar))?;

    // Step 1: get guest token
    let guest_token = get_guest_token(&client).await?;

    // Step 2: init login flow
    let mut state = flow::FlowState::init(&client, &guest_token).await?;

    // Step 3: JS instrumentation (send empty response)
    state.js_instrumentation(&client).await?;

    // Step 4: enter username
    state.enter_username(&client, &req.username).await?;

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
    }

    // Check for denial
    if state.current_task() == "DenyLoginSubtask" {
        let msg = state.deny_message().unwrap_or_else(|| "login denied".into());
        return Err(TwitterLoginError::WrongCredentials {
            message: msg,
            screenshot: None,
        });
    }

    // Step 5: enter password
    state.enter_password(&client, &req.password).await?;

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
        let secret = req
            .totp_secret
            .as_deref()
            .ok_or_else(|| TwitterLoginError::TotpFailed("no TOTP secret".into()))?;
        let code = super::flow::actions::generate_totp(secret)?;
        state
            .enter_text(&client, "LoginTwoFactorAuthChallenge", &code)
            .await?;
    }

    // Step 5b: LoginAcid (email verification)
    if state.current_task() == "LoginAcid" {
        return Err(TwitterLoginError::EmailVerificationRequired);
    }

    // Step 6: duplication check
    state.duplication_check(&client).await?;

    // Extract cookies from the shared jar
    let cookies = extract_cookies(&jar);
    let auth_token = cookies
        .get("auth_token")
        .cloned()
        .ok_or(TwitterLoginError::CookiesNotFound)?;
    let ct0 = cookies
        .get("ct0")
        .cloned()
        .ok_or(TwitterLoginError::CookiesNotFound)?;

    Ok(ApiLoginResult {
        auth_token,
        ct0,
        cookies,
    })
}

fn build_client(jar: Arc<wreq::cookie::Jar>) -> Result<wreq::Client, TwitterLoginError> {
    wreq::Client::builder()
        .cookie_provider(jar)
        .user_agent(crate::TWITTER_USER_AGENT)
        .build()
        .map_err(|e| TwitterLoginError::ApiError {
            status: 0,
            body: format!("client build: {e}"),
        })
}

async fn get_guest_token(client: &wreq::Client) -> Result<String, TwitterLoginError> {
    let resp = client
        .post(format!("{API_BASE}{GUEST_ACTIVATE}"))
        .header(
            "authorization",
            format!("Bearer {}", crate::graphql::BEARER_TOKEN),
        )
        .send()
        .await
        .map_err(|e| TwitterLoginError::ApiError {
            status: 0,
            body: e.to_string(),
        })?;

    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.map_err(|e| TwitterLoginError::ApiError {
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

fn extract_cookies(jar: &wreq::cookie::Jar) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for cookie in jar.get_all() {
        map.insert(cookie.name().to_string(), cookie.value().to_string());
    }
    map
}
