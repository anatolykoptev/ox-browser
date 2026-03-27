//! MCP tool: chrome_interact — headless Chrome page interaction.

use ox_http::chrome_interact::{self, ChromeAction, CookieInput, InteractRequest};
use rmcp::model::*;
use rmcp::schemars::{self, JsonSchema};
use rmcp::ErrorData as McpError;
use serde::Deserialize;

use super::OxMcpServer;

fn default_timeout() -> u64 {
    30
}

/// Input for the chrome_interact MCP tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ChromeInteractInput {
    /// URL to navigate to.
    pub url: String,
    /// Sequential actions to perform on the page.
    pub actions: Vec<ChromeActionInput>,
    /// Total timeout in seconds (default 30).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Override proxy URL.
    #[serde(default)]
    pub proxy: Option<String>,
    /// Session ID for persistent Chrome sessions. Use "new" to create a new
    /// session; use an existing ID to reuse it. Omit for an ephemeral session.
    #[serde(default)]
    pub session_id: Option<String>,
}

fn default_wait() -> u64 {
    5000
}

/// A single Chrome action (MCP-compatible with JsonSchema).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChromeActionInput {
    /// Click an element by CSS selector.
    Click { selector: String },
    /// Type text into an input (React-safe via InsertText CDP).
    #[serde(rename = "type_text")]
    TypeText { selector: String, text: String },
    /// Wait for an element to appear.
    WaitFor {
        selector: String,
        #[serde(default = "default_wait")]
        timeout_ms: u64,
    },
    /// Take a screenshot (returned as base64).
    Screenshot { label: String },
    /// Evaluate JavaScript and return the result.
    Evaluate { js: String },
    /// Press a keyboard key (Enter, Tab, Escape, etc.).
    Press { key: String },
    /// Sleep for specified milliseconds.
    Sleep { ms: u64 },
    /// Get all cookies from the current page (returned in evaluations).
    GetCookies,
    /// Set cookies on the page via CDP.
    SetCookies { cookies: Vec<CookieInputMcp> },
    /// Destroy the current session after all actions complete.
    DestroySession,
    /// Get accessibility tree snapshot (lightweight, machine-readable).
    Snapshot {
        /// Optional label for the snapshot.
        #[serde(default)]
        label: Option<String>,
    },
}

fn default_cookie_path() -> String {
    "/".to_string()
}

/// Cookie to set on the page.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CookieInputMcp {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Cookie domain (e.g. ".example.com").
    pub domain: String,
    /// Cookie path (default "/").
    #[serde(default = "default_cookie_path")]
    pub path: String,
    /// Whether the cookie requires HTTPS.
    #[serde(default)]
    pub secure: bool,
    /// Whether the cookie is HTTP-only.
    #[serde(default)]
    pub http_only: bool,
}

impl From<ChromeActionInput> for ChromeAction {
    fn from(a: ChromeActionInput) -> Self {
        match a {
            ChromeActionInput::Click { selector } => Self::Click { selector },
            ChromeActionInput::TypeText { selector, text } => {
                Self::TypeText { selector, text }
            }
            ChromeActionInput::WaitFor {
                selector,
                timeout_ms,
            } => Self::WaitFor {
                selector,
                timeout_ms,
            },
            ChromeActionInput::Screenshot { label } => Self::Screenshot { label },
            ChromeActionInput::Evaluate { js } => Self::Evaluate { js },
            ChromeActionInput::Press { key } => Self::Press { key },
            ChromeActionInput::Sleep { ms } => Self::Sleep { ms },
            ChromeActionInput::GetCookies => Self::GetCookies,
            ChromeActionInput::SetCookies { cookies } => Self::SetCookies {
                cookies: cookies.into_iter().map(Into::into).collect(),
            },
            ChromeActionInput::DestroySession => Self::DestroySession,
            ChromeActionInput::Snapshot { label } => Self::Snapshot { label },
        }
    }
}

impl From<CookieInputMcp> for CookieInput {
    fn from(c: CookieInputMcp) -> Self {
        Self {
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            secure: c.secure,
            http_only: c.http_only,
        }
    }
}

impl From<ChromeInteractInput> for InteractRequest {
    fn from(i: ChromeInteractInput) -> Self {
        Self {
            url: i.url,
            actions: i.actions.into_iter().map(Into::into).collect(),
            timeout_secs: i.timeout_secs,
            proxy: i.proxy,
            session_id: i.session_id,
        }
    }
}

impl OxMcpServer {
    pub(crate) async fn do_chrome_interact(
        &self,
        input: ChromeInteractInput,
    ) -> Result<CallToolResult, McpError> {
        let req: InteractRequest = input.into();
        let resp =
            chrome_interact::execute(req, &self.chrome_config, &self.chrome_semaphore, &self.session_pool).await;

        let json = serde_json::to_string(&resp).unwrap_or_default();
        if resp.error.is_some() {
            Ok(CallToolResult::error(vec![Content::text(json)]))
        } else {
            Ok(CallToolResult::success(vec![Content::text(json)]))
        }
    }
}
