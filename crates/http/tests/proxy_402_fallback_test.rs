//! Integration test for the Webshare 402 → direct-connection fallback.
//!
//! Simulates the production failure mode: a proxy server that returns
//! HTTP 402 Payment Required during the CONNECT handshake (or for plain
//! HTTP). The client should:
//! 1. Detect 402 from the proxy.
//! 2. Retry the same request directly against the target.
//! 3. Bump the `oxbrowser_proxy_fallback_total` counter.
//!
//! We do NOT use TLS here — wreq honors the proxy for both `http://` and
//! `https://` targets; for plain HTTP the proxy receives an absolute-form
//! GET and returns the response directly. That's exactly what Webshare's
//! 402 looks like for non-CONNECT requests.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use ox_http::proxy_fallback::PROXY_FALLBACK_TOTAL;
use ox_http::{HttpClient, HttpConfig};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawn a fake "proxy" that returns HTTP 402 to every request.
async fn spawn_402_proxy() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let resp = "HTTP/1.1 402 Payment Required\r\n\
                    X-Webshare-Error: 402\r\n\
                    Content-Length: 18\r\n\
                    Connection: close\r\n\
                    \r\n\
                    quota exhausted!!!";
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    port
}

/// Spawn a target HTTP origin that returns 200 OK.
async fn spawn_ok_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let resp = "HTTP/1.1 200 OK\r\n\
                    Content-Length: 14\r\n\
                    Content-Type: text/plain\r\n\
                    Connection: close\r\n\
                    \r\n\
                    direct-success";
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
#[serial]
async fn falls_back_direct_when_proxy_returns_402() {
    let proxy_port = spawn_402_proxy().await;
    let origin_port = spawn_ok_origin().await;
    // Give the listeners a moment to be fully ready.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Allowlist both the fake proxy and origin so SSRF guard lets them through.
    // SAFETY: tests in this file rely on this env var; no other test in the
    // ox-http crate writes OX_HTTP_PRIVATE_ALLOWLIST.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{proxy_port},127.0.0.1:{origin_port}"),
        );
    }

    let before = PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed);

    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        proxy_url: Some(format!("http://127.0.0.1:{proxy_port}")),
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    let target = format!("http://127.0.0.1:{origin_port}/test");
    let resp = client.get(&target).await.expect("fallback should succeed");

    assert_eq!(resp.status, 200, "fallback should return target's 200");
    assert_eq!(resp.body, "direct-success", "body should come from origin");

    let after = PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed);
    assert!(
        after >= before + 1,
        "fallback counter must increment (before={before}, after={after})"
    );
}

#[tokio::test]
#[serial]
async fn no_fallback_when_no_proxy_configured() {
    // Sanity: target returns 402 directly. With no proxy, we must NOT retry —
    // a 402 from the target itself is not a Webshare-quota signal.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let resp = "HTTP/1.1 402 Payment Required\r\n\
                    Content-Length: 0\r\n\
                    Connection: close\r\n\
                    \r\n";
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in falls_back_direct_when_proxy_returns_402.
    unsafe {
        std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", format!("127.0.0.1:{port}"));
    }

    let before = PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed);

    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");
    let resp = client
        .get(&format!("http://127.0.0.1:{port}/"))
        .await
        .expect("request should complete");
    assert_eq!(resp.status, 402);

    let after = PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed);
    assert_eq!(after, before, "counter must NOT bump when no proxy is set");
}

// Keep `Arc` referenced so a dead-code lint doesn't trip future maintainers.
#[allow(dead_code)]
fn _arc_marker() -> Arc<()> {
    Arc::new(())
}
