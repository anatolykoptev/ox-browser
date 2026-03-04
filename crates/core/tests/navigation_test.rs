use ox_core::{is_same_origin, resolve_url};

#[test]
fn test_resolve_absolute_path() {
    let result = resolve_url("https://example.com/page", "/about");
    assert_eq!(result, Some("https://example.com/about".into()));
}

#[test]
fn test_resolve_relative_path() {
    let result = resolve_url("https://example.com/dir/page", "other");
    assert_eq!(result, Some("https://example.com/dir/other".into()));
}

#[test]
fn test_resolve_full_url() {
    let result = resolve_url("https://example.com", "https://other.com/path");
    assert_eq!(result, Some("https://other.com/path".into()));
}

#[test]
fn test_resolve_with_query() {
    let result = resolve_url("https://example.com/page", "?q=search");
    assert_eq!(result, Some("https://example.com/page?q=search".into()));
}

#[test]
fn test_resolve_with_fragment() {
    let result = resolve_url("https://example.com/page", "#section");
    assert_eq!(result, Some("https://example.com/page#section".into()));
}

#[test]
fn test_resolve_invalid_base() {
    let result = resolve_url("not-a-url", "/about");
    assert!(result.is_none());
}

#[test]
fn test_same_origin_true() {
    assert!(is_same_origin(
        "https://example.com/a",
        "https://example.com/b"
    ));
}

#[test]
fn test_same_origin_different_paths() {
    assert!(is_same_origin(
        "https://example.com/foo/bar",
        "https://example.com/baz?q=1"
    ));
}

#[test]
fn test_same_origin_false() {
    assert!(!is_same_origin(
        "https://example.com",
        "https://other.com"
    ));
}

#[test]
fn test_same_origin_different_scheme() {
    assert!(!is_same_origin(
        "http://example.com",
        "https://example.com"
    ));
}

#[test]
fn test_same_origin_different_port() {
    assert!(!is_same_origin(
        "https://example.com:443",
        "https://example.com:8080"
    ));
}

#[test]
fn test_same_origin_invalid_url() {
    assert!(!is_same_origin("not-a-url", "https://example.com"));
}
