use rand::seq::SliceRandom;

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
pub static BUILTIN_PROFILES: &[BrowserProfile] = &[
    // Chrome -- Windows
    bp("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", "chrome", "windows", false, "en-US,en;q=0.9"),
    bp("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", "chrome", "windows", false, "en-US,en;q=0.9"),
    // Chrome -- macOS
    bp("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", "chrome", "macos", false, "en-US,en;q=0.9"),
    bp("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", "chrome", "macos", false, "en-US,en;q=0.9"),
    // Chrome -- Linux
    bp("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", "chrome", "linux", false, "en-US,en;q=0.9"),
    bp("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", "chrome", "linux", false, "en-US,en;q=0.9"),
    // Chrome -- Android
    bp("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36", "chrome", "android", true, "en-US,en;q=0.9"),
    // Safari -- macOS
    bp("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15", "safari", "macos", false, "en-US,en;q=0.9"),
    bp("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15", "safari", "macos", false, "en-US,en;q=0.9"),
    // Safari -- iOS
    bp("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", "safari", "ios", true, "en-US,en;q=0.9"),
    bp("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "safari", "ios", true, "en-US,en;q=0.9"),
    // Firefox -- Windows
    bp("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0", "firefox", "windows", false, "en-US,en;q=0.9"),
    // Firefox -- macOS
    bp("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0", "firefox", "macos", false, "en-US,en;q=0.9"),
    // Firefox -- Linux
    bp("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0", "firefox", "linux", false, "en-US,en;q=0.9"),
    // Edge -- Windows
    bp("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0", "edge", "windows", false, "en-US,en;q=0.9"),
    // Edge -- macOS
    bp("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0", "edge", "macos", false, "en-US,en;q=0.9"),
];

const fn bp(ua: &'static str, browser: &'static str, os: &'static str, mobile: bool, accept_language: &'static str) -> BrowserProfile {
    BrowserProfile { user_agent: ua, browser, os, mobile, accept_language }
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
        .filter(|p| filter.browser.as_ref().is_none_or(|b| p.browser == b.as_str()))
        .filter(|p| filter.os.as_ref().is_none_or(|o| p.os == o.as_str()))
        .filter(|p| filter.mobile.is_none_or(|m| p.mobile == m))
        .collect();

    let mut rng = rand::thread_rng();
    if candidates.is_empty() {
        BUILTIN_PROFILES.choose(&mut rng).expect("profiles non-empty")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_profiles_count() {
        assert_eq!(BUILTIN_PROFILES.len(), 16);
    }

    #[test]
    fn filter_by_browser() {
        let filter = ProfileFilter { browser: Some("firefox".into()), ..Default::default() };
        for _ in 0..20 {
            assert_eq!(random_profile(&filter).browser, "firefox");
        }
    }

    #[test]
    fn filter_by_os() {
        let filter = ProfileFilter { os: Some("macos".into()), ..Default::default() };
        for _ in 0..20 {
            assert_eq!(random_profile(&filter).os, "macos");
        }
    }

    #[test]
    fn filter_mobile_only() {
        let filter = ProfileFilter { mobile: Some(true), ..Default::default() };
        for _ in 0..20 {
            assert!(random_profile(&filter).mobile);
        }
    }

    #[test]
    fn filter_desktop_only() {
        let filter = ProfileFilter { mobile: Some(false), ..Default::default() };
        for _ in 0..20 {
            assert!(!random_profile(&filter).mobile);
        }
    }

    #[test]
    fn no_match_falls_back() {
        let filter = ProfileFilter { browser: Some("opera".into()), ..Default::default() };
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
}
