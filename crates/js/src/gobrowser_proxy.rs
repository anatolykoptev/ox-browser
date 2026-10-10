//! Proxy Chrome operations to go-browser HTTP service.

use reqwest::header::HeaderMap;
use reqwest::{Client, RequestBuilder};
use serde_json::Value;
use std::time::Duration;

use crate::inbound_auth::InboundAuth;

/// Proxy client for forwarding requests to go-browser.
///
/// The bodies forwarded here are caller-shaped (`actions`, `proxy`,
/// `session_id` from `/chrome/interact` and the MCP `chrome_interact` tool),
/// so ox-browser's own go-wowa secret is attached ONLY when the inbound
/// caller was authenticated by the gate (`inbound_auth::Authenticated`).
/// A request let through by soft mode is forwarded with no credential, so
/// go-wowa sees it as the anonymous request it is, never as `ok_secret`.
#[derive(Clone)]
pub struct GoBrowserProxy {
    base_url: String,
    client: Client,
    auth_headers: HeaderMap,
}

impl GoBrowserProxy {
    /// `internal_secret` is ox-browser's go-wowa credential; empty = none.
    pub fn new(base_url: String, internal_secret: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            // Internal go-browser hop: never inherit an ambient
            // HTTP(S)_PROXY/ALL_PROXY from the operator's env.
            .no_proxy()
            // Never follow a redirect with a credentialed request (SEC-CR-010).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("proxy client");
        Self {
            base_url,
            client,
            auth_headers: ox_http::wowa_auth::headers(internal_secret),
        }
    }

    fn with_auth(&self, rb: RequestBuilder, authenticated: bool) -> RequestBuilder {
        if authenticated {
            rb.headers(self.auth_headers.clone())
        } else {
            rb
        }
    }

    /// Forward a JSON POST request to go-browser. `auth` is the inbound
    /// gate decision token (see the type docs) — the secret is attached iff
    /// the caller carried `ok_secret`.
    pub async fn forward(
        &self,
        path: &str,
        body: &Value,
        auth: InboundAuth,
    ) -> Result<(u16, Value), String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .with_auth(self.client.post(&url), auth.is_authenticated())
            .json(body)
            .send()
            .await
            .map_err(|e| format!("go-browser proxy: {e}"))?;
        let status = resp.status().as_u16();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("go-browser proxy parse: {e}"))?;
        Ok((status, body))
    }

    /// Forward a DELETE request (same credential rule as [`Self::forward`]).
    pub async fn delete(&self, path: &str, auth: InboundAuth) -> Result<(u16, Value), String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .with_auth(self.client.delete(&url), auth.is_authenticated())
            .send()
            .await
            .map_err(|e| format!("go-browser proxy delete: {e}"))?;
        let status = resp.status().as_u16();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("go-browser proxy parse: {e}"))?;
        Ok((status, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// go-wowa's secret goes out only for an authenticated inbound caller.
    ///
    /// Falsification: make `with_auth` ignore `authenticated` (always attach)
    /// and the anonymous request carries the secret → RED; never attach and
    /// the authenticated one lacks it → RED.
    #[tokio::test]
    async fn forward_attaches_secret_only_when_authenticated() {
        let (url, req) = ox_http::wowa_auth::capture_one(r#"{"status":"ok"}"#).await;
        let proxy = GoBrowserProxy::new(url, "s3cret");
        let authed = InboundAuth::from_marker(Some(&crate::inbound_auth::Authenticated));
        let (status, _) = proxy
            .forward("/api/v1/chrome/interact", &serde_json::json!({}), authed)
            .await
            .expect("forward");
        assert_eq!(status, 200);
        let head = req.await.expect("capture");
        assert!(head.starts_with("post /api/v1/chrome/interact "), "{head}");
        assert!(head.contains("x-internal-secret: s3cret"), "{head}");

        let (url, req) = ox_http::wowa_auth::capture_one(r#"{"status":"ok"}"#).await;
        let proxy = GoBrowserProxy::new(url, "s3cret");
        proxy
            .forward(
                "/api/v1/chrome/interact",
                &serde_json::json!({}),
                InboundAuth::from_marker(None),
            )
            .await
            .expect("forward");
        let head = req.await.expect("capture");
        assert!(
            !head.contains("x-internal-secret"),
            "anonymous caller relayed with the secret: {head}"
        );
    }

    /// A redirect from go-wowa is not followed with the credential (SEC-CR-010).
    ///
    /// Falsification: remove `.redirect(Policy::none())` and the client
    /// follows the 302 to the second server → RED.
    #[tokio::test]
    async fn forward_does_not_follow_redirects() {
        let (target, hit) = ox_http::wowa_auth::capture_one(r#"{"status":"ok"}"#).await;
        let redirector = ox_http::wowa_auth::redirect_once(target).await;
        let proxy = GoBrowserProxy::new(redirector, "s3cret");
        let _ = proxy
            .forward(
                "/api/v1/chrome/interact",
                &serde_json::json!({}),
                InboundAuth::from_marker(Some(&crate::inbound_auth::Authenticated)),
            )
            .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(300), hit)
                .await
                .is_err(),
            "redirect was followed"
        );
    }
}
