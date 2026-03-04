use thiserror::Error;

#[derive(Error, Debug)]
pub enum BrowserError {
    #[error("navigation failed: {0}")]
    Navigate(String),

    #[error("render timeout")]
    Timeout,

    #[error("invalid selector: {0}")]
    Selector(String),

    #[error("form not found: {0}")]
    FormNotFound(String),

    #[error("element not found: {0}")]
    ElementNotFound(String),

    #[error(transparent)]
    Http(#[from] ox_http::HttpError),
}

pub type Result<T> = std::result::Result<T, BrowserError>;
