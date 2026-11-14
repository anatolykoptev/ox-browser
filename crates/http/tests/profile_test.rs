use ox_http::{
    BUILTIN_PROFILES, BrowserProfile, ProfileFilter, browser_headers, client_hints_headers,
    platform_matched_profile, random_profile,
};

fn chrome_profile(major: u32) -> BrowserProfile {
    BrowserProfile {
        user_agent: Box::leak(
            format!(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
            )
            .into_boxed_str(),
        ),
        browser: "chrome",
        os: "linux",
        mobile: false,
        accept_language: "en-US,en;q=0.9",
    }
}

/// The headers follow the profile's UA major and the handshake is fixed at
/// 148, so a newer UA must not become a client at all: a 156 header set over
/// a 148 ClientHello is a mismatch no caller asked for.
#[test]
fn profile_newer_than_the_tls_handshake_is_refused() {
    use ox_http::{
        HttpClient, HttpConfig, HttpError, build_profiled_wreq_client, profile_to_emulation,
    };
    use std::time::Duration;

    let newer: &'static BrowserProfile = Box::leak(Box::new(chrome_profile(156)));
    assert!(profile_to_emulation(newer).is_none());
    let err = HttpClient::new(HttpConfig {
        profile: Some(newer),
        ..HttpConfig::default()
    })
    .err()
    .expect("a 156 profile over the 148 handshake must be refused");
    assert!(matches!(err, HttpError::UnsupportedProfile(_)), "{err}");
    assert!(matches!(
        build_profiled_wreq_client(newer, "", Duration::from_secs(5), 5),
        Err(HttpError::UnsupportedProfile(_))
    ));

    // The handshake's own major and older ones still build.
    for major in [131, 145, 148] {
        let p: &'static BrowserProfile = Box::leak(Box::new(chrome_profile(major)));
        assert!(profile_to_emulation(p).is_some(), "{major}");
        HttpClient::new(HttpConfig {
            profile: Some(p),
            ..HttpConfig::default()
        })
        .unwrap_or_else(|e| panic!("{major}: {e}"));
    }
    // An Edge profile claiming a newer Chromium is refused the same way.
    let edge = BrowserProfile {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0",
        browser: "edge",
        ..chrome_profile(156)
    };
    assert!(profile_to_emulation(&edge).is_none());
}

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
