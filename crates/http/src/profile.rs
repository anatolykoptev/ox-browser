use rand::seq::SliceRandom;
use wreq::Emulation;
#[cfg(test)]
use wreq_util::Profile;

/// Browser identity with user-agent and metadata for filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserProfile {
    pub user_agent: &'static str,
    pub browser: &'static str,
    pub os: &'static str,
    pub mobile: bool,
    pub accept_language: &'static str,
}

/// 16 built-in profiles matching go-stealth: Chrome/Firefox/Safari/Edge x OS.
/// Versions aligned with wreq-util Emulation profiles (rc.12).
pub static BUILTIN_PROFILES: &[BrowserProfile] = &[
    // Chrome 148 -- Windows
    bp(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "chrome",
        "windows",
        false,
        "en-US,en;q=0.9",
    ),
    bp(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "chrome",
        "windows",
        false,
        "en-US,en;q=0.9",
    ),
    // Chrome 148 -- macOS
    bp(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "chrome",
        "macos",
        false,
        "en-US,en;q=0.9",
    ),
    bp(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "chrome",
        "macos",
        false,
        "en-US,en;q=0.9",
    ),
    // Chrome 148 -- Linux
    bp(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "chrome",
        "linux",
        false,
        "en-US,en;q=0.9",
    ),
    bp(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "chrome",
        "linux",
        false,
        "en-US,en;q=0.9",
    ),
    // Chrome 148 -- Android
    bp(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36",
        "chrome",
        "android",
        true,
        "en-US,en;q=0.9",
    ),
    // Safari 18.5 -- macOS
    bp(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",
        "safari",
        "macos",
        false,
        "en-US,en;q=0.9",
    ),
    bp(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        "safari",
        "macos",
        false,
        "en-US,en;q=0.9",
    ),
    // Safari -- iOS
    bp(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
        "safari",
        "ios",
        true,
        "en-US,en;q=0.9",
    ),
    bp(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "safari",
        "ios",
        true,
        "en-US,en;q=0.9",
    ),
    // Firefox 148 -- Windows
    bp(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
        "firefox",
        "windows",
        false,
        "en-US,en;q=0.9",
    ),
    // Firefox 148 -- macOS
    bp(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0",
        "firefox",
        "macos",
        false,
        "en-US,en;q=0.9",
    ),
    // Firefox 148 -- Linux
    bp(
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0",
        "firefox",
        "linux",
        false,
        "en-US,en;q=0.9",
    ),
    // Edge 145 -- Windows
    bp(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
        "edge",
        "windows",
        false,
        "en-US,en;q=0.9",
    ),
    // Edge 145 -- macOS
    bp(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
        "edge",
        "macos",
        false,
        "en-US,en;q=0.9",
    ),
];

const fn bp(
    ua: &'static str,
    browser: &'static str,
    os: &'static str,
    mobile: bool,
    accept_language: &'static str,
) -> BrowserProfile {
    BrowserProfile {
        user_agent: ua,
        browser,
        os,
        mobile,
        accept_language,
    }
}

/// Filter criteria for selecting profiles.
#[derive(Debug, Default)]
pub struct ProfileFilter {
    pub browser: Option<String>,
    pub os: Option<String>,
    pub mobile: Option<bool>,
}

/// Returns a random profile matching the filter. Falls back to any profile.
pub fn random_profile(filter: &ProfileFilter) -> &'static BrowserProfile {
    let candidates: Vec<&BrowserProfile> = BUILTIN_PROFILES
        .iter()
        .filter(|p| {
            filter
                .browser
                .as_ref()
                .is_none_or(|b| p.browser == b.as_str())
        })
        .filter(|p| filter.os.as_ref().is_none_or(|o| p.os == o.as_str()))
        .filter(|p| filter.mobile.is_none_or(|m| p.mobile == m))
        .collect();

    let mut rng = rand::thread_rng();
    if candidates.is_empty() {
        BUILTIN_PROFILES
            .choose(&mut rng)
            .expect("profiles non-empty")
    } else {
        candidates.choose(&mut rng).expect("candidates non-empty")
    }
}

/// Returns a profile matching the runtime OS (desktop only).
pub fn platform_matched_profile() -> &'static BrowserProfile {
    let os = match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        "linux" => "linux",
        _ => return random_profile(&ProfileFilter::default()),
    };
    random_profile(&ProfileFilter {
        os: Some(os.to_owned()),
        mobile: Some(false),
        ..Default::default()
    })
}

/// Map a BrowserProfile to the corresponding wreq Emulation (TLS + HTTP/2
/// fingerprint). This is the critical link between the User-Agent string and
/// the actual TLS/HTTP/2 fingerprint — without it, CF sees "Chrome 148" in
/// the UA but a non-Chrome JA4 hash, which is an instant bot signal.
///
/// Returns None only for unknown browser names (shouldn't happen with
/// builtin profiles). The version is extracted from the User-Agent and
/// mapped to the closest available wreq-util Emulation variant.
///
/// Issue #77: enable TLS fingerprinting.
pub fn profile_to_emulation(profile: &BrowserProfile) -> Option<Emulation> {
    // Chrome and Edge: build Emulation from scratch via tls.rs for full
    // control over TLS extensions (both ALPS codepoints), HTTP/2 SETTINGS,
    // and header wire order. wreq-util's preset profiles are missing
    // APPLICATION_SETTINGS_OLD (51764) and don't control header order.
    // See Issue #80.
    match profile.browser {
        "chrome" => Some(crate::tls::chrome_emulation(profile)),
        "edge" => Some(crate::tls::edge_emulation(profile)),
        "firefox" => crate::tls::firefox_emulation(profile),
        "safari" => crate::tls::safari_emulation(profile),
        _ => None,
    }
}

/// Extract the major browser version from a User-Agent string.
/// Public version of extract_major_version for cross-module use (tls.rs).
pub fn extract_major_version_pub(ua: &str) -> Option<u32> {
    extract_major_version(ua)
}

fn extract_major_version(ua: &str) -> Option<u32> {
    // Chrome/Edge: "Chrome/148.0.0.0" or "Edg/145.0.0.0"
    if let Some(pos) = ua.find("Chrome/") {
        return parse_version_at(&ua[pos + 7..]);
    }
    if let Some(pos) = ua.find("Edg/") {
        return parse_version_at(&ua[pos + 4..]);
    }
    // Firefox: "rv:148.0"
    if let Some(pos) = ua.find("rv:") {
        return parse_version_at(&ua[pos + 3..]);
    }
    // Safari: "Version/18.5"
    if let Some(pos) = ua.find("Version/") {
        return parse_version_at(&ua[pos + 8..]);
    }
    None
}

fn parse_version_at(s: &str) -> Option<u32> {
    s.split('.').next()?.parse().ok()
}

/// Map Chrome major version to the closest available wreq-util Profile.
/// Falls back to Chrome148 (latest available) for versions beyond the range.
/// Used by tests; production code uses tls::chrome_emulation() instead.
#[cfg(test)]
fn chrome_profile(major: u32) -> Profile {
    match major {
        148 => Profile::Chrome148,
        147 => Profile::Chrome147,
        146 => Profile::Chrome146,
        145 => Profile::Chrome145,
        144 => Profile::Chrome144,
        143 => Profile::Chrome143,
        142 => Profile::Chrome142,
        141 => Profile::Chrome141,
        140 => Profile::Chrome140,
        139 => Profile::Chrome139,
        138 => Profile::Chrome138,
        137 => Profile::Chrome137,
        136 => Profile::Chrome136,
        135 => Profile::Chrome135,
        134 => Profile::Chrome134,
        133 => Profile::Chrome133,
        132 => Profile::Chrome132,
        131 => Profile::Chrome131,
        v if v > 148 => Profile::Chrome148,
        _ => Profile::Chrome131,
    }
}

/// Map Firefox major version to the closest available wreq-util Profile.
/// Used by tests; production code uses tls::firefox_emulation() instead.
#[cfg(test)]
fn firefox_profile(major: u32) -> Profile {
    match major {
        151 => Profile::Firefox151,
        150 => Profile::Firefox150,
        149 => Profile::Firefox149,
        148 => Profile::Firefox148,
        147 => Profile::Firefox147,
        146 => Profile::Firefox146,
        145 => Profile::Firefox145,
        144 => Profile::Firefox144,
        143 => Profile::Firefox143,
        142 => Profile::Firefox142,
        139 => Profile::Firefox139,
        136 => Profile::Firefox136,
        135 => Profile::Firefox135,
        133 => Profile::Firefox133,
        128 => Profile::Firefox128,
        117 => Profile::Firefox117,
        109 => Profile::Firefox109,
        v if v > 151 => Profile::Firefox151,
        _ => Profile::Firefox135,
    }
}

/// Map Safari version to wreq-util Profile. Distinguishes desktop Safari
/// from iOS Safari via the `os` field and `mobile` flag on the profile.
/// Used by tests; production code uses tls::safari_emulation() instead.
#[cfg(test)]
fn safari_profile(profile: &BrowserProfile, major: u32) -> Profile {
    if profile.mobile || profile.os == "ios" {
        match major {
            18 => Profile::SafariIos18_1_1,
            17 => Profile::SafariIos17_2,
            _ => Profile::SafariIos18_1_1,
        }
    } else {
        match major {
            26 => Profile::Safari26,
            18 => Profile::Safari18_5,
            17 => Profile::Safari17_6,
            16 => Profile::Safari16,
            v if v > 26 => Profile::Safari26,
            _ => Profile::Safari16,
        }
    }
}

/// Map Edge major version to the closest available wreq-util Profile.
/// Used by tests; production code uses tls::edge_emulation() instead.
#[cfg(test)]
fn edge_profile(major: u32) -> Profile {
    match major {
        146 => Profile::Edge146,
        145 => Profile::Edge145,
        144 => Profile::Edge144,
        143 => Profile::Edge143,
        142 => Profile::Edge142,
        141 => Profile::Edge141,
        140 => Profile::Edge140,
        139 => Profile::Edge139,
        138 => Profile::Edge138,
        137 => Profile::Edge137,
        136 => Profile::Edge136,
        135 => Profile::Edge135,
        134 => Profile::Edge134,
        131 => Profile::Edge131,
        127 => Profile::Edge127,
        122 => Profile::Edge122,
        101 => Profile::Edge101,
        v if v > 146 => Profile::Edge146,
        _ => Profile::Edge131,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_profiles_count() {
        assert_eq!(BUILTIN_PROFILES.len(), 16);
    }

    #[test]
    fn filter_by_browser() {
        let filter = ProfileFilter {
            browser: Some("firefox".into()),
            ..Default::default()
        };
        for _ in 0..20 {
            assert_eq!(random_profile(&filter).browser, "firefox");
        }
    }

    #[test]
    fn filter_by_os() {
        let filter = ProfileFilter {
            os: Some("macos".into()),
            ..Default::default()
        };
        for _ in 0..20 {
            assert_eq!(random_profile(&filter).os, "macos");
        }
    }

    #[test]
    fn filter_mobile_only() {
        let filter = ProfileFilter {
            mobile: Some(true),
            ..Default::default()
        };
        for _ in 0..20 {
            assert!(random_profile(&filter).mobile);
        }
    }

    #[test]
    fn filter_desktop_only() {
        let filter = ProfileFilter {
            mobile: Some(false),
            ..Default::default()
        };
        for _ in 0..20 {
            assert!(!random_profile(&filter).mobile);
        }
    }

    #[test]
    fn no_match_falls_back() {
        let filter = ProfileFilter {
            browser: Some("opera".into()),
            ..Default::default()
        };
        let p = random_profile(&filter);
        assert!(BUILTIN_PROFILES.contains(p));
    }

    #[test]
    fn platform_matched_returns_desktop() {
        let p = platform_matched_profile();
        assert!(!p.mobile);
    }

    #[test]
    fn combined_filter() {
        let filter = ProfileFilter {
            browser: Some("chrome".into()),
            os: Some("windows".into()),
            mobile: Some(false),
        };
        for _ in 0..20 {
            let p = random_profile(&filter);
            assert_eq!(p.browser, "chrome");
            assert_eq!(p.os, "windows");
            assert!(!p.mobile);
        }
    }

    #[test]
    fn all_builtin_profiles_map_to_emulation() {
        for p in BUILTIN_PROFILES {
            assert!(
                profile_to_emulation(p).is_some(),
                "profile {} {} has no Emulation mapping",
                p.browser,
                p.user_agent
            );
        }
    }

    #[test]
    fn chrome_profiles_map_to_chrome_profile() {
        for p in BUILTIN_PROFILES.iter().filter(|p| p.browser == "chrome") {
            let major = extract_major_version(p.user_agent).expect("version");
            let prof = chrome_profile(major);
            let prof_str = format!("{prof:?}");
            assert!(
                prof_str.contains("Chrome"),
                "chrome profile {major} mapped to non-Chrome Profile: {prof_str}"
            );
        }
    }

    #[test]
    fn firefox_profiles_map_to_firefox_profile() {
        for p in BUILTIN_PROFILES.iter().filter(|p| p.browser == "firefox") {
            let major = extract_major_version(p.user_agent).expect("version");
            let prof = firefox_profile(major);
            let prof_str = format!("{prof:?}");
            assert!(
                prof_str.contains("Firefox"),
                "firefox profile {major} mapped to non-Firefox Profile: {prof_str}"
            );
        }
    }

    #[test]
    fn safari_profiles_map_to_safari_profile() {
        for p in BUILTIN_PROFILES.iter().filter(|p| p.browser == "safari") {
            let major = extract_major_version(p.user_agent).expect("version");
            let prof = safari_profile(p, major);
            let prof_str = format!("{prof:?}");
            assert!(
                prof_str.contains("Safari"),
                "safari profile {major} mapped to non-Safari Profile: {prof_str}"
            );
        }
    }

    #[test]
    fn edge_profiles_map_to_edge_profile() {
        for p in BUILTIN_PROFILES.iter().filter(|p| p.browser == "edge") {
            let major = extract_major_version(p.user_agent).expect("version");
            let prof = edge_profile(major);
            let prof_str = format!("{prof:?}");
            assert!(
                prof_str.contains("Edge"),
                "edge profile {major} mapped to non-Edge Profile: {prof_str}"
            );
        }
    }

    #[test]
    fn extract_major_version_chrome() {
        assert_eq!(
            extract_major_version(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/148.0.0.0 Safari/537.36"
            ),
            Some(148)
        );
    }

    #[test]
    fn extract_major_version_firefox() {
        assert_eq!(
            extract_major_version(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Firefox/148.0"
            ),
            Some(148)
        );
    }

    #[test]
    fn extract_major_version_safari() {
        assert_eq!(
            extract_major_version(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/18.5 Safari/605.1.15"
            ),
            Some(18)
        );
    }

    #[test]
    fn extract_major_version_edge() {
        assert_eq!(
            extract_major_version(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/145.0.0.0 Edg/145.0.0.0"
            ),
            Some(145) // Chrome/ found first, which is correct — Edge uses Chrome's TLS stack
        );
    }
}
