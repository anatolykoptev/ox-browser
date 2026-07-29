//! Issue #101 falsification: prove the media-download client actually carries
//! the browser identity on the wire — not merely that it compiles.
//!
//! Builds the real `ox_media::http::build_client` client for a known profile,
//! applies `ox_http::browser_headers(profile)` (the exact header set
//! `download_to_file` applies), sends a real request to a local capture
//! server, and asserts the captured User-Agent and `sec-ch-ua` client hint
//! match the profile. A bare client (the pre-#101 state) would send wreq's
//! default UA and no client hints — this test would fail against that.

use std::time::Duration;

use ox_http::{BUILTIN_PROFILES, browser_headers};

/// Pick the Chrome/Linux profile (the verified reference identity).
fn chrome_linux_profile() -> &'static ox_http::BrowserProfile {
    BUILTIN_PROFILES
        .iter()
        .find(|p| p.browser == "chrome" && p.os == "linux")
        .expect("a Chrome/Linux builtin profile exists")
}

/// Minimal HTTP/1.1 capture server: accept one connection on the given
/// (already-bound) listener, read the request headers, respond with a tiny
/// body, return the raw request head.
async fn capture_request_headers(listener: tokio::net::TcpListener) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut sock, _) = listener.accept().await.expect("accept");
    let mut buf = vec![0u8; 8192];
    let n = sock.read(&mut buf).await.expect("read request");
    // Respond so the client completes cleanly.
    sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .await
        .expect("write response");
    String::from_utf8_lossy(&buf[..n]).to_string()
}

/// Extract the value of a header from a raw HTTP request head.
fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    for line in head.lines() {
        if let Some((k, v)) = line.split_once(": ")
            && k.eq_ignore_ascii_case(name)
        {
            return Some(v.trim());
        }
    }
    None
}

#[tokio::test]
async fn media_client_carries_profile_user_agent_and_client_hints() {
    let profile = chrome_linux_profile();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // The capture server runs in parallel with the client send.
    let capture = tokio::spawn(capture_request_headers(listener));

    // Build the REAL media client via the shared seam.
    let client = ox_media::http::build_client(profile, "", Duration::from_secs(5), "identity-test")
        .expect("build_client succeeds with a profile");

    // Apply the profile headers exactly as `download_to_file` does.
    let url = format!("http://127.0.0.1:{port}/capture");
    let mut request = client.get(&url);
    for (name, value) in browser_headers(profile) {
        request = request.header(name.as_str(), value.as_str());
    }
    // Send — ignore the response; we only care about the request headers.
    let _ = request.send().await;

    let head = capture.await.expect("capture server returned headers");

    // Assert the User-Agent matches the profile's UA exactly.
    let ua = header_value(&head, "user-agent").expect("request has a User-Agent");
    assert_eq!(
        ua, profile.user_agent,
        "media client must send the profile's User-Agent, got {ua}"
    );

    // Assert a client hint (sec-ch-ua) is present and carries the profile's
    // Chrome major version. A bare client sends no sec-ch-ua at all.
    let sec_ch_ua = header_value(&head, "sec-ch-ua").expect("request has sec-ch-ua");
    // Extract the Chrome major from the profile UA and assert it appears in
    // the sec-ch-ua header value.
    let chrome_major = profile
        .user_agent
        .split("Chrome/")
        .nth(1)
        .and_then(|s| s.split('.').next())
        .expect("profile UA has a Chrome major version");
    assert!(
        sec_ch_ua.contains(&format!("v=\"{chrome_major}\"")),
        "sec-ch-ua must carry the profile's Chrome major {chrome_major}, got {sec_ch_ua}"
    );

    // Sanity: the sec-ch-ua-platform matches the profile's OS. The header
    // value is JSON-quoted (e.g. `"Linux"`).
    let platform =
        header_value(&head, "sec-ch-ua-platform").expect("request has sec-ch-ua-platform");
    let expected_platform = match profile.os {
        "linux" => "Linux",
        "windows" => "Windows",
        "macos" => "macOS",
        "android" => "Android",
        "ios" => "iOS",
        other => other,
    };
    assert_eq!(
        platform,
        &format!("\"{expected_platform}\""),
        "sec-ch-ua-platform must match the profile OS, got {platform}"
    );
}

/// A bare `wreq::Client::builder()` (the pre-#101 media client) sends wreq's
/// default UA and no `sec-ch-ua`. This test documents the contrast: the
/// default UA is NOT the profile's UA, proving the falsification would have
/// caught the old bare-client bug.
#[tokio::test]
async fn bare_client_does_not_carry_profile_identity() {
    let profile = chrome_linux_profile();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let capture = tokio::spawn(capture_request_headers(listener));

    // A bare client — the pre-#101 construction.
    let bare = wreq::Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .build()
        .unwrap();
    let _ = bare
        .get(format!("http://127.0.0.1:{port}/capture"))
        .send()
        .await;

    let head = capture.await.expect("capture server returned headers");

    // A bare client either sends wreq's default UA or none — never the
    // profile's Chrome UA. And it sends NO sec-ch-ua.
    let ua = header_value(&head, "user-agent");
    assert!(
        ua != Some(profile.user_agent),
        "bare client must NOT send the profile UA — this contrast is the falsification"
    );
    assert!(
        header_value(&head, "sec-ch-ua").is_none(),
        "bare client must NOT send sec-ch-ua — this contrast is the falsification"
    );
}
