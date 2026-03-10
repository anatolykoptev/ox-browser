//! Shared HTTP client builder with proxy support.

use std::time::Duration;

use crate::MediaError;

/// Build a wreq client with optional proxy and timeout.
pub fn build_client(
    proxy_url: &str,
    timeout: Duration,
    error_context: &str,
) -> Result<wreq::Client, MediaError> {
    let mut builder = wreq::Client::builder().timeout(timeout);
    if !proxy_url.is_empty() {
        let proxy = wreq::Proxy::all(proxy_url)
            .map_err(|e| MediaError::DownloadFailed(format!("{error_context} proxy: {e}")))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| MediaError::DownloadFailed(format!("{error_context} client: {e}")))
}
