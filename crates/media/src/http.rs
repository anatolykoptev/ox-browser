//! Shared HTTP client builder with proxy support.

use std::time::Duration;

use crate::MediaError;

/// Redirect chain cap for media-download clients. Matches
/// `ox_http::HttpConfig::default().max_redirects` so the guarded media
/// download path and the guarded ox-http path behave identically.
const DEFAULT_MAX_REDIRECTS: usize = 10;

/// Build a wreq client with optional proxy and timeout.
///
/// SSRF-guarded: this client dials media URLs extracted from
/// caller-supplied or fetched-page content (see
/// `crate::download::download_to_file`), so it carries the same
/// connect-time DNS guard and redirect-hop guard as the main
/// `ox_http::HttpClient` path — see `ox_http::ssrf_connect` for why both
/// are needed (a pre-resolve check alone misses redirects and DNS-rebind).
/// Callers MUST also call `ox_http::validate_url` before invoking a
/// client built here, to catch a literal-IP/bad-scheme INITIAL target —
/// this builder alone only guards connect-time resolution and redirects,
/// mirroring what `ox_http::HttpClient`'s middleware chain + wreq client
/// combination provides together.
pub fn build_client(
    proxy_url: &str,
    timeout: Duration,
    error_context: &str,
) -> Result<wreq::Client, MediaError> {
    let mut builder = wreq::Client::builder()
        .timeout(timeout)
        .dns_resolver(ox_http::SsrfGuardedResolver)
        .redirect(ox_http::ssrf_redirect_policy(DEFAULT_MAX_REDIRECTS));
    if !proxy_url.is_empty() {
        let proxy = wreq::Proxy::all(proxy_url)
            .map_err(|e| MediaError::DownloadFailed(format!("{error_context} proxy: {e}")))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| MediaError::DownloadFailed(format!("{error_context} client: {e}")))
}
