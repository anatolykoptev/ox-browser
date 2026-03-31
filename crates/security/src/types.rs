//! Shared types for security analysis modules.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Severity level for security findings.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Scan mode — adjusts which checks run and finding severity.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    /// Public pages: reconnaissance — what protects this site?
    #[default]
    Public,
    /// Login/registration: auth flow security expectations.
    Login,
    /// Post-auth: session security, token handling.
    Authenticated,
}
