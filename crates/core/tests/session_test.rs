use std::thread;
use std::time::Duration;

use ox_core::{Session, SessionConfig};

#[test]
fn session_creation_default_config() {
    let session = Session::new(SessionConfig::default()).unwrap();
    assert_eq!(session.id.len(), 16, "ID should be 16 hex chars");
    assert!(
        session.id.chars().all(|c| c.is_ascii_hexdigit()),
        "ID should be valid hex"
    );
    assert_eq!(session.request_count(), 0);
}

#[test]
fn session_profile_is_set() {
    let session = Session::new(SessionConfig::default()).unwrap();
    let profile = session.profile();

    // Profile should be a real browser, not the ox-browser default UA.
    assert!(
        profile.user_agent.contains("Mozilla"),
        "profile UA should contain Mozilla, got: {}",
        profile.user_agent
    );
    assert!(
        !profile.browser.is_empty(),
        "profile browser should be non-empty"
    );
    assert!(!profile.os.is_empty(), "profile os should be non-empty");
}

#[test]
fn session_with_explicit_profile() {
    use ox_http::BUILTIN_PROFILES;

    // Pick the first Firefox profile.
    let firefox = BUILTIN_PROFILES
        .iter()
        .find(|p| p.browser == "firefox")
        .unwrap();

    let config = SessionConfig {
        profile: Some(firefox),
        ..SessionConfig::default()
    };
    let session = Session::new(config).unwrap();
    assert_eq!(session.profile().browser, "firefox");
    assert!(session.profile().user_agent.contains("Firefox"));
}

#[test]
fn session_unique_ids() {
    let s1 = Session::new(SessionConfig::default()).unwrap();
    let s2 = Session::new(SessionConfig::default()).unwrap();
    assert_ne!(s1.id, s2.id, "sessions should have unique IDs");
}

#[test]
fn session_age_increases() {
    let session = Session::new(SessionConfig::default()).unwrap();
    thread::sleep(Duration::from_millis(10));
    assert!(
        session.age() >= Duration::from_millis(10),
        "age should be >= 10ms, got {:?}",
        session.age()
    );
}

#[test]
fn session_idle_time_tracks() {
    let session = Session::new(SessionConfig::default()).unwrap();
    thread::sleep(Duration::from_millis(10));
    assert!(
        session.idle_time() >= Duration::from_millis(10),
        "idle_time should be >= 10ms, got {:?}",
        session.idle_time()
    );
}

#[test]
fn session_request_count_starts_at_zero() {
    let session = Session::new(SessionConfig::default()).unwrap();
    assert_eq!(session.request_count(), 0);
}

#[test]
fn session_last_used_near_creation() {
    let session = Session::new(SessionConfig::default()).unwrap();
    // last_used should be very close to created_at (within 1ms).
    let diff = session.last_used().duration_since(session.created_at);
    assert!(
        diff < Duration::from_millis(1),
        "last_used should be near created_at, diff: {:?}",
        diff
    );
}

#[test]
fn session_profile_consistent() {
    let session = Session::new(SessionConfig::default()).unwrap();
    let ua1 = session.profile().user_agent;
    let ua2 = session.profile().user_agent;
    assert_eq!(ua1, ua2, "profile should be consistent across calls");
}
