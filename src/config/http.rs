//! HTTP client configuration: timeouts, redirects, TLS emulation.

use serde::Deserialize;
use wreq_util::{Emulation, Profile};

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct HttpSection {
    pub timeout_secs: u64,
    pub max_redirects: usize,
    pub emulation: String,
}

impl Default for HttpSection {
    fn default() -> Self {
        Self {
            timeout_secs: 20,
            max_redirects: 10,
            emulation: "chrome148".into(),
        }
    }
}

impl HttpSection {
    /// Parse the emulation string into wreq Emulation.
    /// Returns None for "none" or empty string (TLS fingerprinting disabled).
    pub fn emulation(&self) -> Option<Emulation> {
        let profile = match self.emulation.as_str() {
            "chrome148" => Profile::Chrome148,
            "chrome145" => Profile::Chrome145,
            "chrome136" => Profile::Chrome136,
            "chrome131" => Profile::Chrome131,
            "chrome127" => Profile::Chrome127,
            "chrome124" => Profile::Chrome124,
            "chrome120" => Profile::Chrome120,
            "chrome116" => Profile::Chrome116,
            "safari18" => Profile::Safari18,
            "safari17" => Profile::Safari17_0,
            "edge145" => Profile::Edge145,
            "edge127" => Profile::Edge127,
            "firefox135" => Profile::Firefox135,
            "none" | "" => return None,
            other => {
                tracing::warn!("unknown emulation '{other}', falling back to chrome148");
                Profile::Chrome148
            }
        };
        Some(Emulation::builder().profile(profile).build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let s = HttpSection::default();
        assert_eq!(s.timeout_secs, 20);
        assert_eq!(s.max_redirects, 10);
        assert_eq!(s.emulation, "chrome148");
    }

    #[test]
    fn emulation_parsing() {
        let s = HttpSection::default();
        assert!(s.emulation().is_some());

        let s2 = HttpSection {
            emulation: "none".into(),
            ..Default::default()
        };
        assert!(s2.emulation().is_none());

        let s3 = HttpSection {
            emulation: "safari18".into(),
            ..Default::default()
        };
        assert!(s3.emulation().is_some());
    }
}
