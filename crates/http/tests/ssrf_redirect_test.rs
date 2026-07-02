//! Live integration test for the redirect-hop SSRF guard.
//!
//! Complements the unit tests in `ox_http::ssrf_connect` (which exercise the
//! pure `filter_allowed` logic and `SsrfGuardedResolver::resolve` directly)
//! with an end-to-end check that a REAL `wreq::Client`, wired the same way
//! `ox_http::client::HttpClient` wires it, actually refuses to follow a
//! redirect into a blocked target — and that the blocked target is never
//! contacted.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use ox_http::{SsrfGuardedResolver, ssrf_redirect_policy};

/// Spawns a raw HTTP/1.1 server on `127.0.0.1` that always replies with a
/// `302 Found` to `location`. Returns the bound address.
async fn spawn_redirect_server(location: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let location = location.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(body.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// Spawns a raw HTTP/1.1 server on `127.0.0.1` that sets `hit` and replies
/// `200 OK` — the "internal target" a redirect must never reach.
async fn spawn_target_server(hit: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let hit = hit.clone();
            tokio::spawn(async move {
                hit.store(true, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

fn guarded_client() -> wreq::Client {
    wreq::Client::builder()
        .timeout(Duration::from_secs(5))
        .dns_resolver(SsrfGuardedResolver)
        .redirect(ssrf_redirect_policy(10))
        .build()
        .expect("guarded client")
}

/// FALSIFICATION NOTE: this test must go RED if
/// `crates/http/src/client.rs` stops wiring `ssrf_redirect_policy` into the
/// client's redirect policy (or if `is_private_ip` is stubbed to always
/// return `false`) — verified manually during implementation by
/// temporarily reverting the wiring, confirming the failure, then
/// restoring it.
#[tokio::test]
async fn redirect_to_loopback_target_is_refused_and_never_contacted() {
    let hit = Arc::new(AtomicBool::new(false));
    let target_addr = spawn_target_server(hit.clone()).await;
    let redirector_addr = spawn_redirect_server(format!("http://{target_addr}/internal")).await;

    let client = guarded_client();
    let result = client
        .get(format!("http://{redirector_addr}/start"))
        .send()
        .await;

    assert!(
        result.is_err(),
        "expected the redirect to a loopback target to be refused, got: {result:?}"
    );
    // Give any (incorrectly) in-flight connection a moment to land before
    // asserting it never did.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !hit.load(Ordering::SeqCst),
        "the internal redirect target must never be contacted"
    );
}

/// Proves the escape hatch works in the redirect-policy layer too (not
/// just the pre-resolve `validate_url` layer) — an operator-configured
/// sidecar/test allowlist entry lets a specific loopback redirect target
/// through, everything else is still refused.
#[tokio::test]
#[serial(ssrf_allowlist_env)]
async fn redirect_to_allowlisted_loopback_target_is_followed() {
    let hit = Arc::new(AtomicBool::new(false));
    let target_addr = spawn_target_server(hit.clone()).await;
    let redirector_addr = spawn_redirect_server(format!("http://{target_addr}/internal")).await;

    // SAFETY: #[serial(ssrf_allowlist_env)] prevents any other test in this
    // binary that reads/writes OX_HTTP_PRIVATE_ALLOWLIST from running
    // concurrently.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{}", target_addr.port()),
        );
    }
    let client = guarded_client();
    let result = client
        .get(format!("http://{redirector_addr}/start"))
        .send()
        .await;
    unsafe {
        std::env::remove_var("OX_HTTP_PRIVATE_ALLOWLIST");
    }

    assert!(
        result.is_ok(),
        "an explicitly allowlisted redirect target must be followed, got: {result:?}"
    );
    assert!(
        hit.load(Ordering::SeqCst),
        "allowlisted target should have been contacted"
    );
}
