//! Shared HTTP client builder with proxy support + browser identity.

use std::time::Duration;

use ox_http::BrowserProfile;

use crate::MediaError;

/// Redirect chain cap for media-download clients. Matches
/// `ox_http::HttpConfig::default().max_redirects` so the guarded media
/// download path and the guarded ox-http path behave identically.
const DEFAULT_MAX_REDIRECTS: usize = 10;

/// Build a wreq client carrying the same browser TLS/HTTP2 identity as
/// `ox_http::HttpClient` does for `profile`, plus the SSRF connect-time and
/// redirect-hop guards and an optional static proxy.
///
/// Issue #101: this previously built a bare `wreq::Client` with no emulation,
/// no profile, no User-Agent, no client hints. A WAF that saw a byte-perfect
/// Chrome fetch the page then saw a bare Rust client fetch the images or video
/// from the same origin — a one-visitor-two-clients correlation signal, and a
/// direct tell against InnerTube. The client now carries the profile's TLS/HTTP2
/// fingerprint via the shared `ox_http::build_profiled_wreq_client` seam (ONE
/// construction site, shared with `HttpClient`'s own builders — no duplicated
/// identity logic that could drift).
///
/// Headers are NOT set on the builder (mirroring PR #97: the emulation owns
/// TLS+HTTP/2 only, the profile owns the headers, set per-request by the
/// caller via `ox_http::browser_headers`). Callers MUST set the profile
/// headers on each request:
///   - `download::download_to_file` sets `browser_headers(profile)` — the
///     request always carries the profile's UA + client hints, with no code
///     path that can substitute a mismatched UA (the incoherence PR #97 made
///     unrepresentable for `HttpClient` is inherited here).
///   - `innertube::fetch_player_response` sets the ANDROID_VR UA — the
///     YouTube Innertube ANDROID_VR protocol identity (an Android-app
///     identity, not a browser one; Android's YouTube app uses Chrome's
///     BoringSSL stack, so the Chrome emulation is the correct TLS layer).
///
/// SSRF-guarded: this client dials media URLs extracted from caller-supplied
/// or fetched-page content (see `crate::download::download_to_file`), so it
/// carries the same connect-time DNS guard and redirect-hop guard as the main
/// `ox_http::HttpClient` path — see `ox_http::ssrf_connect` for why both are
/// needed (a pre-resolve check alone misses redirects and DNS-rebind).
/// Callers MUST also call `ox_http::validate_url` before invoking a client
/// built here, to catch a literal-IP/bad-scheme INITIAL target — this builder
/// alone only guards connect-time resolution and redirects, mirroring what
/// `ox_http::HttpClient`'s middleware chain + wreq client combination provides
/// together.
pub fn build_client(
    profile: &BrowserProfile,
    proxy_url: &str,
    timeout: Duration,
    error_context: &str,
) -> Result<wreq::Client, MediaError> {
    ox_http::build_profiled_wreq_client(profile, proxy_url, timeout, DEFAULT_MAX_REDIRECTS)
        .map_err(|e| MediaError::DownloadFailed(format!("{error_context} client: {e}")))
}
