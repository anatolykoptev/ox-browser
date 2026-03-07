//! Server bind/listen configuration.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    pub port: u16,
    pub bind: String,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            port: 8901,
            bind: "0.0.0.0".into(),
        }
    }
}
