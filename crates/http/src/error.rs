use thiserror::Error;

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("retryable HTTP status: {0}")]
    RetryableStatus(u16),

    #[error("proxy pool error: {0}")]
    ProxyPool(String),
}

impl HttpError {
    /// Returns `true` if this error is retryable (transient failures).
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::RetryableStatus(_) => true,
            Self::Timeout(_) => true,
            Self::Request(e) => e.is_timeout() || e.is_connect(),
            Self::InvalidUrl(_) | Self::ProxyPool(_) => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, HttpError>;
