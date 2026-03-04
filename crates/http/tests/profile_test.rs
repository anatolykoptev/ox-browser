use ox_http::{
    browser_headers, client_hints_headers, platform_matched_profile, random_profile,
    BrowserProfile, ProfileFilter, BUILTIN_PROFILES,
};

#[test]
fn builtin_profiles_all_valid() {
    assert_eq!(BUILTIN_PROFILES.len(), 16);
    for p in BUILTIN_PROFILES {
        assert!(!p.browser.is_empty(), "browser must not be empty");
        assert!(!p.os.is_empty(), "os must not be empty");
        assert!(
            p.user_agent.contains("Mozilla"),
            "UA must contain Mozilla: {}",
            p.user_agent
        );
    }
}

#[test]
fn random_profile_browser_filter() {
    let filter = ProfileFilter {
        browser: Some("firefox".into()),
        ..Default::default()
    };
    for _ in 0..20 {
        let p = random_profile(&filter);
        assert_eq!(p.browser, "firefox");
    }
}

#[test]
fn random_profile_empty_filter_returns_valid() {
    let filter = ProfileFilter::default();
    for _ in 0..10 {
        let p = random_profile(&filter);
        assert!(BUILTIN_PROFILES.contains(p));
    }
}

#[test]
fn platform_matched_returns_desktop() {
    let p = platform_matched_profile();
    assert!(!p.browser.is_empty());
    assert!(!p.mobile, "platform_matched should return desktop");
}

#[test]
fn browser_headers_non_empty_with_user_agent() {
    let chrome = BUILTIN_PROFILES
        .iter()
        .find(|p| p.browser == "chrome")
        .unwrap();
    let hdrs = browser_headers(chrome);
    assert!(!hdrs.is_empty());
    assert!(
        hdrs.iter().any(|(k, _)| k == "user-agent"),
        "headers must include user-agent"
    );
}

#[test]
fn client_hints_for_chrome_ua() {
    let chrome_ua = &BUILTIN_PROFILES[0]; // Chrome Windows
    let hints = client_hints_headers(chrome_ua.user_agent);
    assert!(
        hints.iter().any(|(k, _)| k == "sec-ch-ua"),
        "Chrome UA should produce sec-ch-ua header"
    );
    assert!(
        hints.iter().any(|(k, _)| k == "sec-ch-ua-platform"),
        "Chrome UA should produce sec-ch-ua-platform header"
    );
}

#[test]
fn client_hints_empty_for_safari() {
    let safari: &BrowserProfile = BUILTIN_PROFILES
        .iter()
        .find(|p| p.browser == "safari")
        .unwrap();
    let hints = client_hints_headers(safari.user_agent);
    assert!(hints.is_empty(), "Safari should not produce client hints");
}
