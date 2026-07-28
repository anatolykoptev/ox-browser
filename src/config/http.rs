//! HTTP client configuration: timeouts, redirects, browser profile.

use serde::Deserialize;

use ox_http::{BrowserProfile, ProfileFilter, random_profile};

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct HttpSection {
    pub timeout_secs: u64,
    pub max_redirects: usize,
    /// Browser profile name: "chrome", "firefox", "safari", "edge", or "none".
    ///
    /// A single profile name yields, atomically: TLS ClientHello, HTTP/2
    /// SETTINGS + pseudo-header order, the header LIST, the header ORDER,
    /// the User-Agent, and the client hints. A config naming one browser
    /// must not be able to produce another browser's headers — this is the
    /// one-identity invariant (Issue #81).
    ///
    /// For backward compat, old wreq-util preset strings ("chrome148",
    /// "chrome136", "safari18", etc.) are accepted: the browser name is
    /// extracted and a matching builtin profile is selected, with a
    /// deprecation warning.
    pub profile: String,
}

impl Default for HttpSection {
    fn default() -> Self {
        Self {
            timeout_secs: 20,
            max_redirects: 10,
            profile: "chrome".into(),
        }
    }
}

impl HttpSection {
    /// Resolve the profile string to a builtin BrowserProfile matching the
    /// host OS. Returns None for "none" or empty (no fingerprinting).
    pub fn profile(&self) -> Option<&'static BrowserProfile> {
        let name = self.profile.trim().to_ascii_lowercase();
        if name.is_empty() || name == "none" {
            return None;
        }

        let browser = normalize_browser_name(&name);
        let host_os = std::env::consts::OS;

        // Prefer a desktop profile matching the host OS.
        let filter = ProfileFilter {
            browser: Some(browser.to_string()),
            os: Some(host_os.to_string()),
            mobile: Some(false),
        };
        let profile = random_profile(&filter);

        // Sanity: the selected profile's browser must match what was asked
        // for. If random_profile fell back to an arbitrary profile (no match),
        // try without the OS filter.
        if profile.browser != browser {
            let filter = ProfileFilter {
                browser: Some(browser.to_string()),
                mobile: Some(false),
                ..Default::default()
            };
            let p2 = random_profile(&filter);
            if p2.browser == browser {
                return Some(p2);
            }
            tracing::warn!(
                requested = %name,
                selected_browser = %profile.browser,
                "no builtin profile for browser '{browser}'; fell back to {}",
                profile.browser
            );
        }
        Some(profile)
    }
}

/// Extract the browser family name from a config string.
///
/// Accepts both new-style names ("chrome", "firefox") and old-style
/// wreq-util preset strings ("chrome148", "chrome136", "safari18",
/// "edge145", "firefox135") for backward compatibility.
fn normalize_browser_name(s: &str) -> &str {
    if s.starts_with("chrome") {
        if s != "chrome" {
            tracing::warn!(
                old_value = s,
                "emulation preset strings are deprecated; use profile = \"chrome\" instead"
            );
        }
        "chrome"
    } else if s.starts_with("firefox") {
        if s != "firefox" {
            tracing::warn!(
                old_value = s,
                "emulation preset strings are deprecated; use profile = \"firefox\" instead"
            );
        }
        "firefox"
    } else if s.starts_with("safari") {
        if s != "safari" {
            tracing::warn!(
                old_value = s,
                "emulation preset strings are deprecated; use profile = \"safari\" instead"
            );
        }
        "safari"
    } else if s.starts_with("edge") {
        if s != "edge" {
            tracing::warn!(
                old_value = s,
                "emulation preset strings are deprecated; use profile = \"edge\" instead"
            );
        }
        "edge"
    } else {
        tracing::warn!(unknown = s, "unknown profile '{s}', falling back to chrome");
        "chrome"
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
        assert_eq!(s.profile, "chrome");
    }

    #[test]
    fn profile_parsing() {
        let s = HttpSection::default();
        assert!(s.profile().is_some());

        let s2 = HttpSection {
            profile: "none".into(),
            ..Default::default()
        };
        assert!(s2.profile().is_none());

        let s3 = HttpSection {
            profile: "safari".into(),
            ..Default::default()
        };
        assert!(s3.profile().is_some());
    }

    #[test]
    fn old_preset_strings_accepted() {
        let s = HttpSection {
            profile: "chrome136".into(),
            ..Default::default()
        };
        let p = s.profile().expect("chrome136 maps to a chrome profile");
        assert_eq!(p.browser, "chrome");
    }

    #[test]
    fn empty_string_disables() {
        let s = HttpSection {
            profile: "".into(),
            ..Default::default()
        };
        assert!(s.profile().is_none());
    }

    #[test]
    fn profile_matches_host_os() {
        let s = HttpSection::default();
        let p = s.profile().expect("default profile");
        // On Linux/macOS/Windows the profile should match the host OS.
        let host_os = std::env::consts::OS;
        // Android/iOS hosts won't have a desktop match, so only assert for
        // the common desktop OSes.
        if matches!(host_os, "linux" | "macos" | "windows") {
            assert_eq!(p.os, host_os, "default chrome profile should match host OS");
        }
    }

    #[test]
    fn all_builtin_profiles_covered() {
        // Every browser family in BUILTIN_PROFILES must be selectable.
        for browser in &["chrome", "firefox", "safari", "edge"] {
            let s = HttpSection {
                profile: browser.to_string(),
                ..Default::default()
            };
            let p = s
                .profile()
                .unwrap_or_else(|| panic!("no profile for browser '{browser}'"));
            assert_eq!(p.browser, *browser);
        }
    }
}
