//! Server bind/listen configuration.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    pub port: u16,
    pub bind: String,
    /// Extra `Host`/`host:port` entries admitted by the MCP Streamable HTTP
    /// server transport's DNS-rebinding guard (RUSTSEC-2026-0189).
    ///
    /// rmcp ≥ 1.4.0 rejects any inbound `Host` not in its allowlist; the
    /// default allowlist is loopback-only (`localhost`, `127.0.0.1`, `::1`).
    /// That protects loopback/private-network surfaces but silently 403s any
    /// fleet consumer reaching the container on a non-loopback address (e.g.
    /// `10.9.0.2:8901`). Operators who expose the MCP endpoint on a
    /// non-loopback interface list that authority here; the entries are ADDED
    /// to the loopback default so loopback access can never be locked out.
    ///
    /// Default empty → rmcp loopback-only default (most restrictive).
    /// Example: `mcp_allowed_hosts = ["10.9.0.2:8901"]`
    pub mcp_allowed_hosts: Vec<String>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            port: 8901,
            bind: "0.0.0.0".into(),
            mcp_allowed_hosts: Vec::new(),
        }
    }
}
