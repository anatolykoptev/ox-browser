use thiserror::Error;

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),
}

pub type Result<T> = std::result::Result<T, HttpError>;
