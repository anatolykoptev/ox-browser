//! Cookie cache configuration.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct CacheSection {
    /// Cookie cache TTL in seconds (default: 1500 = 25 minutes).
    pub cookie_ttl_secs: u64,
}

impl Default for CacheSection {
    fn default() -> Self {
        Self {
            cookie_ttl_secs: 25 * 60,
        }
    }
}
