//! Internal flow state for Twitter API login via onboarding/task.json.

use serde_json::json;
use wreq::header::{HeaderMap, HeaderValue};

use super::error::TwitterLoginError;

const API_BASE: &str = "https://api.x.com";
const ONBOARDING_TASK: &str = "/1.1/onboarding/task.json";

pub(super) struct FlowState {
    pub flow_token: String,
    pub response: serde_json::Value,
    guest_token: String,
}

impl FlowState {
    pub fn current_task(&self) -> &str {
        self.response["subtasks"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|t| t["subtask_id"].as_str())
            .unwrap_or("")
    }

    pub fn deny_message(&self) -> Option<String> {
        self.response["subtasks"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|t| t["cta"]["secondary_text"]["text"].as_str())
            .map(|s| s.to_string())
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {}", crate::graphql::BEARER_TOKEN)).unwrap(),
        );
        h.insert(
            "x-guest-token",
            HeaderValue::from_str(&self.guest_token).unwrap(),
        );
        h.insert("x-twitter-active-user", HeaderValue::from_static("yes"));
        h.insert(
            "x-twitter-client-language",
            HeaderValue::from_static("en"),
        );
        h
    }

    pub async fn init(client: &wreq::Client, guest_token: &str) -> Result<Self, TwitterLoginError> {
        let body = json!({
            "input_flow_data": {
                "flow_context": {
                    "debug_overrides": {},
                    "start_location": { "location": "splash_screen" }
                }
            },
            "subtask_versions": subtask_versions()
        });

        let mut state = Self {
            flow_token: String::new(),
            response: serde_json::Value::Null,
            guest_token: guest_token.to_string(),
        };

        let resp = client
            .post(format!("{API_BASE}{ONBOARDING_TASK}"))
            .headers(state.headers())
            .query(&[("flow_name", "login")])
            .json(&body)
            .send()
            .await
            .map_err(|e| TwitterLoginError::ApiError {
                status: 0,
                body: e.to_string(),
            })?;

        state.parse_response(resp).await?;
        Ok(state)
    }

    pub async fn execute_task(
        &mut self,
        client: &wreq::Client,
        subtask_data: serde_json::Value,
    ) -> Result<(), TwitterLoginError> {
        let body = json!({
            "flow_token": self.flow_token,
            "subtask_inputs": [subtask_data]
        });

        let resp = client
            .post(format!("{API_BASE}{ONBOARDING_TASK}"))
            .headers(self.headers())
            .json(&body)
            .send()
            .await
            .map_err(|e| TwitterLoginError::ApiError {
                status: 0,
                body: e.to_string(),
            })?;

        self.parse_response(resp).await
    }

    async fn parse_response(&mut self, resp: wreq::Response) -> Result<(), TwitterLoginError> {
        let status = resp.status().as_u16();
        if status == 429 {
            return Err(TwitterLoginError::RateLimited);
        }

        let body: serde_json::Value = resp.json().await.map_err(|e| {
            TwitterLoginError::ApiError {
                status,
                body: e.to_string(),
            }
        })?;

        if let Some(token) = body["flow_token"].as_str() {
            self.flow_token = token.to_string();
        }
        self.response = body;

        if status >= 400 {
            return Err(TwitterLoginError::ApiError {
                status,
                body: self.response.to_string(),
            });
        }
        Ok(())
    }

    pub async fn js_instrumentation(&mut self, client: &wreq::Client) -> Result<(), TwitterLoginError> {
        self.execute_task(client, json!({
            "subtask_id": "LoginJsInstrumentationSubtask",
            "js_instrumentation": { "response": "", "link": "next_link" }
        }))
        .await
    }

    pub async fn enter_username(
        &mut self,
        client: &wreq::Client,
        username: &str,
    ) -> Result<(), TwitterLoginError> {
        self.execute_task(client, json!({
            "subtask_id": "LoginEnterUserIdentifierSSO",
            "settings_list": {
                "setting_responses": [{
                    "key": "user_identifier",
                    "response_data": { "text_data": { "result": username } }
                }],
                "link": "next_link"
            }
        }))
        .await
    }

    pub async fn enter_password(
        &mut self,
        client: &wreq::Client,
        password: &str,
    ) -> Result<(), TwitterLoginError> {
        self.execute_task(client, json!({
            "subtask_id": "LoginEnterPassword",
            "enter_password": { "password": password, "link": "next_link" }
        }))
        .await
    }

    pub async fn enter_text(
        &mut self,
        client: &wreq::Client,
        subtask_id: &str,
        text: &str,
    ) -> Result<(), TwitterLoginError> {
        self.execute_task(client, json!({
            "subtask_id": subtask_id,
            "enter_text": { "text": text, "link": "next_link" }
        }))
        .await
    }

    pub async fn duplication_check(&mut self, client: &wreq::Client) -> Result<(), TwitterLoginError> {
        self.execute_task(client, json!({
            "subtask_id": "AccountDuplicationCheck",
            "check_logged_in_account": { "link": "AccountDuplicationCheck_false" }
        }))
        .await
    }
}

fn subtask_versions() -> serde_json::Value {
    json!({
        "action_list": 2, "alert_dialog": 1, "app_download_cta": 1,
        "check_logged_in_account": 1, "choice_selection": 3,
        "contacts_live_sync_permission_prompt": 0, "cta": 7,
        "email_verification": 2, "end_flow": 1, "enter_date": 1,
        "enter_email": 2, "enter_password": 5, "enter_phone": 2,
        "enter_recaptcha": 1, "enter_text": 5, "enter_username": 2,
        "generic_urt": 3, "in_app_notification": 1, "interest_picker": 3,
        "js_instrumentation": 1, "menu_dialog": 1,
        "notifications_permission_prompt": 2, "open_account": 2,
        "open_home_timeline": 1, "open_link": 1, "phone_verification": 4,
        "privacy_options": 1, "security_key": 3, "select_avatar": 4,
        "select_banner": 2, "settings_list": 7, "show_code": 1,
        "sign_up": 2, "sign_up_review": 4, "tweet_selection_urt": 1,
        "update_users": 1, "upload_media": 1,
        "user_recommendations_list": 4, "user_recommendations_urt": 1,
        "wait_spinner": 3, "web_modal": 1
    })
}
