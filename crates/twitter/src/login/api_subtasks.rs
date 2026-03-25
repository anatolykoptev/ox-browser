//! JSON builders for Twitter login flow subtask inputs.

use serde_json::{json, Value};

pub(super) fn subtask_versions() -> Value {
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

pub(super) fn init_body() -> Value {
    json!({
        "input_flow_data": {
            "flow_context": {
                "debug_overrides": {},
                "start_location": { "location": "splash_screen" }
            }
        },
        "subtask_versions": subtask_versions()
    })
}

pub(super) fn task_body(flow_token: &str, subtask_data: Value) -> Value {
    json!({
        "flow_token": flow_token,
        "subtask_inputs": [subtask_data]
    })
}

pub(super) fn js_instrumentation() -> Value {
    json!({
        "subtask_id": "LoginJsInstrumentationSubtask",
        "js_instrumentation": { "response": "", "link": "next_link" }
    })
}

pub(super) fn enter_username(username: &str) -> Value {
    json!({
        "subtask_id": "LoginEnterUserIdentifierSSO",
        "settings_list": {
            "setting_responses": [{
                "key": "user_identifier",
                "response_data": { "text_data": { "result": username } }
            }],
            "link": "next_link"
        }
    })
}

pub(super) fn enter_password(password: &str) -> Value {
    json!({
        "subtask_id": "LoginEnterPassword",
        "enter_password": { "password": password, "link": "next_link" }
    })
}

pub(super) fn enter_text(subtask_id: &str, text: &str) -> Value {
    json!({
        "subtask_id": subtask_id,
        "enter_text": { "text": text, "link": "next_link" }
    })
}

pub(super) fn duplication_check() -> Value {
    json!({
        "subtask_id": "AccountDuplicationCheck",
        "check_logged_in_account": {
            "link": "AccountDuplicationCheck_false"
        }
    })
}
