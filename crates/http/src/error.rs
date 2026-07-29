use thiserror::Error;

use crate::cloudflare::ChallengeType;

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("request failed: {0}")]
    Request(#[from] wreq::Error),

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("retryable HTTP status: {0}")]
    RetryableStatus(u16),

    #[error("proxy pool error: {0}")]
    ProxyPool(String),

    #[error("cloudflare {0} (HTTP {1}, ray {2})")]
    Cloudflare(ChallengeType, u16, String),

    #[error("response body exceeded cap: {observed} bytes > {limit} bytes limit")]
    BodyTooLarge { limit: u64, observed: u64 },

    #[error("body decode error: {0}")]
    BodyDecodeError(String),
}

impl HttpError {
    /// Returns `true` if this error is retryable (transient failures).
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::RetryableStatus(_) => true,
            Self::Timeout(_) => true,
            Self::Request(e) => e.is_timeout() || e.is_connect(),
            Self::Cloudflare(_, _, _) => true,
            Self::InvalidUrl(_)
            | Self::ProxyPool(_)
            | Self::BodyTooLarge { .. }
            | Self::BodyDecodeError(_) => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, HttpError>;
