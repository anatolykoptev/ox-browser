//! Server bind/listen configuration.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    pub port: u16,
    pub bind: String,
    /// Extra `Host` / `host:port` authorities admitted by the MCP endpoint's
    /// DNS-rebinding guard (RUSTSEC-2026-0189), added to loopback, which is
    /// always admitted. Merged with the `OX_MCP_ALLOWED_HOSTS` env var
    /// (comma-separated). Empty = loopback only.
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

/// Env var holding extra comma-separated MCP `Host` authorities.
pub const MCP_ALLOWED_HOSTS_ENV: &str = "OX_MCP_ALLOWED_HOSTS";

impl ServerSection {
    /// Configured entries plus `raw_env` (comma-separated), blanks dropped.
    pub fn mcp_allowed_hosts_with(&self, raw_env: Option<&str>) -> Vec<String> {
        self.mcp_allowed_hosts
            .iter()
            .map(String::as_str)
            .chain(raw_env.unwrap_or_default().split(','))
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_owned)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_allowed_hosts_merges_toml_and_env_dropping_blanks() {
        let s = ServerSection {
            mcp_allowed_hosts: vec!["a.test".into()],
            ..Default::default()
        };
        assert_eq!(
            s.mcp_allowed_hosts_with(Some(" b.test:1, ,c.test ")),
            ["a.test", "b.test:1", "c.test"]
        );
        assert!(
            ServerSection::default()
                .mcp_allowed_hosts_with(None)
                .is_empty()
        );
    }
}
