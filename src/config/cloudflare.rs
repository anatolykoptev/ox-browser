//! Cloudflare detection configuration.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct CloudflareSection {
    /// Enable Cloudflare challenge detection in responses.
    pub detect: bool,
}

impl Default for CloudflareSection {
    fn default() -> Self {
        Self { detect: true }
    }
}
