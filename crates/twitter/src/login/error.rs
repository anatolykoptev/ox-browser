use std::path::PathBuf;
use std::fmt;

/// Which step of the login flow failed.
#[derive(Debug, Clone, Copy)]
pub enum FlowStep {
    Launch,
    Navigate,
    Username,
    ClickNext,
    DetectScreen,
    Password,
    ClickLogin,
    DetectPostLogin,
    TwoFactor,
    WaitHome,
    ExtractCookies,
}

impl fmt::Display for FlowStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Structured errors from the Twitter login flow.
#[derive(Debug, thiserror::Error)]
pub enum TwitterLoginError {
    #[error("chrome launch failed: {0}")]
    ChromeLaunch(String),

    #[error("navigation failed: {0}")]
    Navigation(String),

    #[error("element not found: {selector} at step {step}")]
    ElementNotFound {
        selector: String,
        step: FlowStep,
        screenshot: Option<PathBuf>,
    },

    #[error("wrong credentials: {message}")]
    WrongCredentials {
        message: String,
        screenshot: Option<PathBuf>,
    },

    #[error("account locked")]
    AccountLocked { screenshot: Option<PathBuf> },

    #[error("captcha required")]
    CaptchaRequired { screenshot: Option<PathBuf> },

    #[error("TOTP failed: {0}")]
    TotpFailed(String),

    #[error("email/phone required for username confirmation but not provided")]
    MissingEmail,

    #[error("auth_token or ct0 cookie not found after login")]
    CookiesNotFound,

    #[error("timeout at step {step}")]
    Timeout {
        step: FlowStep,
        screenshot: Option<PathBuf>,
    },

    #[error("API error: HTTP {status}")]
    ApiError { status: u16, body: String },

    #[error("rate limited")]
    RateLimited,

    #[error("email verification required (LoginAcid)")]
    EmailVerificationRequired,
}

impl TwitterLoginError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ChromeLaunch(_) => "chrome_launch",
            Self::Navigation(_) => "navigation",
            Self::ElementNotFound { .. } => "element_not_found",
            Self::WrongCredentials { .. } => "wrong_credentials",
            Self::AccountLocked { .. } => "account_locked",
            Self::CaptchaRequired { .. } => "captcha_required",
            Self::TotpFailed(_) => "totp_failed",
            Self::MissingEmail => "missing_email",
            Self::CookiesNotFound => "cookies_not_found",
            Self::Timeout { .. } => "timeout",
            Self::ApiError { .. } => "api_error",
            Self::RateLimited => "rate_limited",
            Self::EmailVerificationRequired => "email_verification_required",
        }
    }

    /// Permanent errors should not be retried with Chrome fallback.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::WrongCredentials { .. }
                | Self::AccountLocked { .. }
                | Self::MissingEmail
        )
    }

    pub fn screenshot(&self) -> Option<&PathBuf> {
        match self {
            Self::ElementNotFound { screenshot, .. }
            | Self::WrongCredentials { screenshot, .. }
            | Self::AccountLocked { screenshot, .. }
            | Self::CaptchaRequired { screenshot, .. }
            | Self::Timeout { screenshot, .. } => screenshot.as_ref(),
            _ => None,
        }
    }
}
