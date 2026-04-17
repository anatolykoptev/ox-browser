//! MCP tool: chrome_interact — headless Chrome page interaction via go-browser proxy.

use rmcp::ErrorData as McpError;
use rmcp::model::*;
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

use super::OxMcpServer;

fn default_timeout() -> u64 {
    30
}

/// Input for the chrome_interact MCP tool.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
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
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChromeActionInput {
    /// Click an element by CSS selector.
    Click {
        selector: String,
        /// Enable human-like Bezier mouse movement and random click offset.
        #[serde(default)]
        humanize: bool,
    },
    /// Type text into an input (React-safe via InsertText CDP).
    #[serde(rename = "type_text")]
    TypeText {
        selector: String,
        text: String,
        /// Enable human-like typing with variable delays.
        #[serde(default)]
        humanize: bool,
    },
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
    /// Accept or dismiss a JS dialog (alert/confirm/prompt).
    HandleDialog {
        /// Accept (true) or dismiss (false).
        accept: bool,
        /// Text for prompt() dialogs.
        #[serde(default)]
        prompt_text: Option<String>,
    },
    /// Hover over an element (triggers CSS :hover and JS mouseover).
    Hover {
        selector: String,
        /// Enable human-like mouse movement to element.
        #[serde(default)]
        humanize: bool,
    },
    /// Navigate back in browser history.
    GoBack,
    /// Get captured network requests and console messages.
    GetLogs,
}

/// Cookie to set on the page.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
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

fn default_cookie_path() -> String {
    "/".to_string()
}

impl OxMcpServer {
    pub(crate) async fn do_chrome_interact(
        &self,
        input: ChromeInteractInput,
    ) -> Result<CallToolResult, McpError> {
        let body = serde_json::to_value(&input)
            .map_err(|e| McpError::internal_error(format!("serialize: {e}"), None))?;
        let (_, resp) = self
            .gobrowser_proxy
            .forward("/api/v1/chrome/interact", &body)
            .await
            .map_err(|e| McpError::internal_error(e, None))?;
        let json = serde_json::to_string(&resp).unwrap_or_default();
        let has_error = resp.get("error").and_then(|v| v.as_str()).is_some();
        if has_error {
            return Ok(CallToolResult::error(vec![Content::text(json)]));
        }
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
