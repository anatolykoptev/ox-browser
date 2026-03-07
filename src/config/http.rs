//! HTTP client configuration: timeouts, redirects, TLS emulation.

use serde::Deserialize;
use wreq_util::Emulation;

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
            emulation: "chrome136".into(),
        }
    }
}

impl HttpSection {
    /// Parse the emulation string into wreq Emulation enum.
    pub fn emulation(&self) -> Option<Emulation> {
        match self.emulation.as_str() {
            "chrome136" => Some(Emulation::Chrome136),
            "chrome131" => Some(Emulation::Chrome131),
            "chrome127" => Some(Emulation::Chrome127),
            "chrome124" => Some(Emulation::Chrome124),
            "chrome116" => Some(Emulation::Chrome116),
            "chrome120" => Some(Emulation::Chrome120),
            "safari18" => Some(Emulation::Safari18),
            "safari17" => Some(Emulation::Safari17_0),
            "edge127" => Some(Emulation::Edge127),
            "none" | "" => None,
            other => {
                tracing::warn!("unknown emulation '{other}', falling back to chrome136");
                Some(Emulation::Chrome136)
            }
        }
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
        assert_eq!(s.emulation, "chrome136");
    }

    #[test]
    fn emulation_parsing() {
        let s = HttpSection::default();
        assert!(matches!(s.emulation(), Some(Emulation::Chrome136)));

        let mut s2 = HttpSection::default();
        s2.emulation = "none".into();
        assert!(s2.emulation().is_none());

        let mut s3 = HttpSection::default();
        s3.emulation = "safari18".into();
        assert!(matches!(s3.emulation(), Some(Emulation::Safari18)));
    }
}
