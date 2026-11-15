//! Server bind/listen configuration.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    pub port: u16,
    pub bind: String,
    /// Extra `Host` / `host:port` authorities admitted on EVERY route (the
    /// DNS-rebinding guard, RUSTSEC-2026-0189), added to loopback, which is
    /// always admitted. Merged with the `OX_ALLOWED_HOSTS` and legacy
    /// `OX_MCP_ALLOWED_HOSTS` env vars (comma-separated). Empty = loopback
    /// only. `mcp_allowed_hosts` is the pre-0.9.2 key name.
    #[serde(alias = "mcp_allowed_hosts")]
    pub allowed_hosts: Vec<String>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            port: 8901,
            bind: "0.0.0.0".into(),
            allowed_hosts: Vec::new(),
        }
    }
}

/// Env var holding extra comma-separated `Host` authorities.
pub const ALLOWED_HOSTS_ENV: &str = "OX_ALLOWED_HOSTS";

/// Former name of [`ALLOWED_HOSTS_ENV`] from when the allowlist guarded only
/// `/mcp`; still honoured and merged with the new name.
pub const LEGACY_MCP_ALLOWED_HOSTS_ENV: &str = "OX_MCP_ALLOWED_HOSTS";

impl ServerSection {
    /// Configured entries plus the raw comma-separated env values, blanks
    /// dropped.
    pub fn allowed_hosts_with(&self, raw_envs: &[Option<&str>]) -> Vec<String> {
        self.allowed_hosts
            .iter()
            .map(String::as_str)
            .chain(
                raw_envs
                    .iter()
                    .flat_map(|e| e.unwrap_or_default().split(',')),
            )
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// [`Self::allowed_hosts_with`] fed from the process environment.
    pub fn allowed_hosts_from_env(&self) -> Vec<String> {
        let new = std::env::var(ALLOWED_HOSTS_ENV).ok();
        let legacy = std::env::var(LEGACY_MCP_ALLOWED_HOSTS_ENV).ok();
        self.allowed_hosts_with(&[new.as_deref(), legacy.as_deref()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_hosts_merges_toml_and_both_env_names_dropping_blanks() {
        let s = ServerSection {
            allowed_hosts: vec!["a.test".into()],
            ..Default::default()
        };
        assert_eq!(
            s.allowed_hosts_with(&[Some(" b.test:1, ,c.test "), Some("legacy.test")]),
            ["a.test", "b.test:1", "c.test", "legacy.test"]
        );
        assert!(
            ServerSection::default()
                .allowed_hosts_with(&[None, None])
                .is_empty()
        );
    }

    #[test]
    fn toml_accepts_the_legacy_key_name() {
        let s: ServerSection = toml::from_str(r#"mcp_allowed_hosts = ["old.test"]"#).unwrap();
        assert_eq!(s.allowed_hosts, ["old.test"]);
        let s: ServerSection = toml::from_str(r#"allowed_hosts = ["new.test"]"#).unwrap();
        assert_eq!(s.allowed_hosts, ["new.test"]);
    }
}
