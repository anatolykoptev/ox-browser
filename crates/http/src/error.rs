use thiserror::Error;

use crate::cloudflare::ChallengeType;
use crate::response::HttpResponse;

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("request failed: {0}")]
    Request(#[from] wreq::Error),

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("invalid HTTP method: {0}")]
    InvalidMethod(String),

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("retryable HTTP status: {0}")]
    RetryableStatus(u16),

    #[error("proxy pool error: {0}")]
    ProxyPool(String),

    /// Genuine Cloudflare challenge — detected from real CF markers
    /// (server: cloudflare, challenge-platform, cf-mitigated, etc.) with a
    /// ray id. CF intercepted the request; the origin never saw it. Safe to
    /// re-send on any method.
    #[error("cloudflare {0} (HTTP {1}, ray {2})")]
    Cloudflare(ChallengeType, u16, String),

    /// Anti-bot fallback INFERRED from a bare HTTP status (401/403/429/503)
    /// or a low-quality 200 — NOT from genuine Cloudflare markers. The origin
    /// MAY have processed the request, so re-sending a non-idempotent method
    /// (POST, PATCH) is a duplicate-mutation hazard. The re-sender gates on
    /// `is_idempotent`: idempotent methods are re-sent (solver/residential
    /// attempt the bypass); non-idempotent methods get the original response
    /// back. Carries the original response so the gate can return it with
    /// body and headers intact instead of synthesising an empty error.
    #[error("inferred anti-bot fallback (HTTP {0})")]
    CloudflareInferred(u16, Box<HttpResponse>),

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
            Self::CloudflareInferred(_, _) => true,
            Self::InvalidUrl(_)
            | Self::InvalidMethod(_)
            | Self::ProxyPool(_)
            | Self::BodyTooLarge { .. }
            | Self::BodyDecodeError(_) => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, HttpError>;
