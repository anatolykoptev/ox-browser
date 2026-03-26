//! Internal flow state for Twitter API login via onboarding/task.json.
//! No xtid headers — twikit doesn't send them for login flow.

use super::{api_headers, api_subtasks};
use super::error::TwitterLoginError;

const API_BASE: &str = "https://api.x.com";
const ONBOARDING_TASK: &str = "/1.1/onboarding/task.json";

pub(super) struct FlowState {
    pub flow_token: String,
    pub response: serde_json::Value,
    guest_token: String,
    csrf_token: Option<String>,
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

    pub fn set_csrf_token(&mut self, ct0: &str) {
        self.csrf_token = Some(ct0.to_string());
    }

    pub async fn init(
        client: &wreq::Client,
        guest_token: &str,
        csrf_token: Option<&str>,
    ) -> Result<Self, TwitterLoginError> {
        let mut state = Self {
            flow_token: String::new(),
            response: serde_json::Value::Null,
            guest_token: guest_token.to_string(),
            csrf_token: csrf_token.map(|s| s.to_string()),
        };

        let url = format!("{API_BASE}{ONBOARDING_TASK}");
        let headers = api_headers::onboarding_headers(
            &state.guest_token,
            state.csrf_token.as_deref(),
        );

        let resp = client
            .post(&url)
            .headers(headers)
            .query(&[("flow_name", "login")])
            .json(&api_subtasks::init_body())
            .send()
            .await
            .map_err(|e| TwitterLoginError::ApiError { status: 0, body: e.to_string() })?;

        state.parse_response(resp).await?;
        Ok(state)
    }

    pub async fn execute_task(
        &mut self,
        client: &wreq::Client,
        subtask_data: serde_json::Value,
    ) -> Result<(), TwitterLoginError> {
        let url = format!("{API_BASE}{ONBOARDING_TASK}");
        let headers = api_headers::onboarding_headers(
            &self.guest_token,
            self.csrf_token.as_deref(),
        );

        let resp = client
            .post(&url)
            .headers(headers)
            .json(&api_subtasks::task_body(&self.flow_token, subtask_data))
            .send()
            .await
            .map_err(|e| TwitterLoginError::ApiError { status: 0, body: e.to_string() })?;

        self.parse_response(resp).await
    }

    async fn parse_response(&mut self, resp: wreq::Response) -> Result<(), TwitterLoginError> {
        let status = resp.status().as_u16();
        if status == 429 {
            return Err(TwitterLoginError::RateLimited);
        }

        // Debug: log Set-Cookie
        let set_cookies: Vec<_> = resp.headers()
            .get_all("set-cookie").iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or("").to_string())
            .collect();
        if !set_cookies.is_empty() {
            tracing::info!(cookies = ?set_cookies, "API login: Set-Cookie received");
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| TwitterLoginError::ApiError { status, body: e.to_string() })?;

        if let Some(token) = body["flow_token"].as_str() {
            self.flow_token = token.to_string();
        }
        self.response = body;

        if status >= 400 {
            tracing::warn!(status, body = %self.response, "API login: error");
            return Err(TwitterLoginError::ApiError {
                status,
                body: self.response.to_string(),
            });
        }
        Ok(())
    }

    pub async fn js_instrumentation(&mut self, client: &wreq::Client, ui_metrics_response: &str) -> Result<(), TwitterLoginError> {
        self.execute_task(client, api_subtasks::js_instrumentation(ui_metrics_response)).await
    }

    pub async fn enter_username(&mut self, client: &wreq::Client, username: &str) -> Result<(), TwitterLoginError> {
        self.execute_task(client, api_subtasks::enter_username(username)).await
    }

    pub async fn enter_password(&mut self, client: &wreq::Client, password: &str) -> Result<(), TwitterLoginError> {
        self.execute_task(client, api_subtasks::enter_password(password)).await
    }

    pub async fn enter_text(&mut self, client: &wreq::Client, subtask_id: &str, text: &str) -> Result<(), TwitterLoginError> {
        self.execute_task(client, api_subtasks::enter_text(subtask_id, text)).await
    }

    pub async fn duplication_check(&mut self, client: &wreq::Client) -> Result<(), TwitterLoginError> {
        self.execute_task(client, api_subtasks::duplication_check()).await
    }
}
