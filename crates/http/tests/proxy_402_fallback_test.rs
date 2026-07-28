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

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ox_http::metrics::{PROXY_402_TOTAL, PROXY_DIAL_TOTAL, PROXY_USED_TOTAL};
use ox_http::proxy_fallback::{PROXY_DIAL_FALLBACK_TOTAL, PROXY_FALLBACK_TOTAL};
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
        after > before,
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

/// Fix 1: a residential-only config (no `proxy_url`, no `proxy_pool`) must
/// still attach the direct fallback. The residential middleware injects its
/// proxy per-request on a CF retry (`middleware_residential.rs:60` sets
/// `retry_req.proxy = Some(self.proxy_url)`), so a 402 during that retry flows
/// through `WreqHandler` with `req.proxy` set. We simulate that post-retry
/// state directly by building a `Request` whose `proxy` is already set to a
/// fake 402 proxy — what `ResidentialHandler` does on a CF retry. With the
/// fallback wired, the 402 degrades to the direct origin; without it (the
/// May-outage state) `needs_fallback` was false, `direct_client` was `None`,
/// and the 402 hard-failed.
#[tokio::test]
#[serial]
async fn residential_only_config_falls_back_direct_on_402() {
    use ox_http::Request;

    let proxy_port = spawn_402_proxy().await;
    let origin_port = spawn_ok_origin().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in falls_back_direct_when_proxy_returns_402.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{proxy_port},127.0.0.1:{origin_port}"),
        );
    }

    let before = PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed);

    // Residential-only: NO proxy_url, NO proxy_pool, ONLY residential_proxy.
    // Before Fix 1 this left needs_fallback=false -> no direct sibling.
    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        residential_proxy: Some(format!("http://127.0.0.1:{proxy_port}")),
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    // Simulate the post-CF-retry state: residential middleware has already
    // set req.proxy. (ResidentialHandler passes through unchanged when
    // req.proxy is already set, so this exercises the exact path a
    // residential CF-retry 402 takes through WreqHandler.)
    let req = Request {
        method: "GET".into(),
        url: format!("http://127.0.0.1:{origin_port}/test"),
        headers: vec![],
        body: None,
        proxy: Some(format!("http://127.0.0.1:{proxy_port}")),
    };
    let resp = client.execute(req).await.expect("fallback should succeed");

    assert_eq!(resp.status, 200, "fallback should return target's 200");
    assert_eq!(resp.body, "direct-success", "body should come from origin");

    let after = PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed);
    assert!(
        after > before,
        "fallback counter must increment (before={before}, after={after})"
    );
}

/// Fix 2, positive: a proxy pointed at a **closed** port (connect refused)
/// must degrade to direct and increment the dial-failure counter (NOT the
/// 402 counter). HTTP target so the classifier's forward-proxy path applies
/// (`is_proxy_connect()` is precisely a proxy-dial failure there).
///
/// F2: `max_redirects: 0` is required — the dial-failure classifier now
/// refuses when redirects are enabled (the failing hop's scheme is
/// unobservable after a redirect, so degrading could leak the real IP
/// through a healthy proxy).
#[tokio::test]
#[serial]
async fn falls_back_direct_when_proxy_is_dead() {
    // Reserve a port, then drop the listener so nothing accepts -> connect refused.
    let dead_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let origin_port = spawn_ok_origin().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in falls_back_direct_when_proxy_returns_402.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{dead_port},127.0.0.1:{origin_port}"),
        );
    }

    let dial_before = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);
    let p402_before = PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed);

    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        proxy_url: Some(format!("http://127.0.0.1:{dead_port}")),
        max_redirects: 0,
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    let target = format!("http://127.0.0.1:{origin_port}/test");
    let resp = client
        .get(&target)
        .await
        .expect("dead-proxy fallback should still succeed via direct");

    assert_eq!(resp.status, 200, "fallback should return target's 200");
    assert_eq!(resp.body, "direct-success", "body should come from origin");

    let dial_after = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);
    let p402_after = PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed);
    assert!(
        dial_after > dial_before,
        "dial-fallback counter must increment (before={dial_before}, after={dial_after})"
    );
    assert_eq!(
        p402_after, p402_before,
        "402 counter must NOT bump for a dead-proxy dial failure"
    );
}

/// Fix 2, negative (F3-rescoped): a **reachable** proxy that cannot reach the
/// origin must NOT trigger the dial fallback. The proxy is healthy (the dial
/// to it succeeded); the failure is on the origin side. Falling back to direct
/// here would expose the real IP for no benefit — exactly the case the
/// classifier is designed to refuse.
///
/// F3: the previous version of this test used an HTTP target + a proxy that
/// returns a 502 *response*. That produced `Ok(HttpResponse{status:502})`,
/// so neither classifier call site (which require `Err`) was ever reached —
/// the test was synthetic-green (replace the predicate with `|_,_| true` and
/// it still passed). This version uses an **HTTPS** target so the proxy
/// exercises the CONNECT-tunnel path: the proxy accepts the CONNECT, returns
/// 502 (origin unreachable), and wreq surfaces that as a `ProxyConnect` *Err*.
/// `max_redirects: 0` is set so the F2 redirect-guard does not pre-empt — the
/// refusal is exercised specifically via the HTTPS-scheme gate
/// (`is_http_target` is false). The error must surface to the caller and the
/// dial-fallback counter must NOT bump.
#[tokio::test]
#[serial]
async fn does_not_fallback_when_proxy_reachable_but_origin_unreachable() {
    // A reachable proxy that returns 502 to every CONNECT (simulating "origin
    // unreachable" from the proxy's perspective).
    let proxy_port = {
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
                    // Respond to CONNECT with 502 — reachable proxy, origin unreachable.
                    let resp = "HTTP/1.1 502 Bad Gateway\r\n\
                        Content-Length: 0\r\n\
                        Connection: close\r\n\
                        \r\n";
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        port
    };

    // A dead origin port — nothing listens. The proxy's CONNECT to it fails,
    // so the proxy returns 502.
    let dead_origin_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in falls_back_direct_when_proxy_returns_402.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{proxy_port},127.0.0.1:{dead_origin_port}"),
        );
    }

    let dial_before = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);

    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        proxy_url: Some(format!("http://127.0.0.1:{proxy_port}")),
        max_redirects: 0,
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    // HTTPS target through the proxy -> CONNECT -> proxy returns 502 -> Err.
    let target = format!("https://127.0.0.1:{dead_origin_port}/test");
    let result = client.get(&target).await;

    // The proxy's 502-to-CONNECT must surface as an Err (ProxyConnect), NOT
    // degrade to direct (which would hit the network with our real IP).
    assert!(
        result.is_err(),
        "reachable-proxy + unreachable-origin (HTTPS CONNECT 502) must surface \
         as an Err, not fall back to direct — got {:?}",
        result
    );

    let dial_after = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);
    assert_eq!(
        dial_after, dial_before,
        "dial-fallback counter must NOT bump when the proxy is reachable (before={dial_before}, after={dial_after})"
    );
}

// Keep `Arc` referenced so a dead-code lint doesn't trip future maintainers.
#[allow(dead_code)]
fn _arc_marker() -> Arc<()> {
    Arc::new(())
}

// ---------------------------------------------------------------------------
// F1: residential-only config, un-challenged first attempt must NOT be
// reported as proxied. An origin-side 402 (paywall, nothing to do with any
// proxy) must surface to the caller unchanged — exactly ONE origin request,
// zero proxy counters bump, no duplicate POST.
// ---------------------------------------------------------------------------

/// Spawn an HTTP origin that returns 402 and counts how many connections it
/// received (so the test can assert exactly ONE origin request).
async fn spawn_402_origin_with_counter() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count_clone = Arc::clone(&count);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            count_clone.fetch_add(1, Ordering::SeqCst);
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
    (port, count)
}

/// F1: a residential-only config (no `proxy_url`, no `proxy_pool`) must NOT
/// report an un-challenged first attempt as proxied. An origin-side 402 must
/// surface to the caller unchanged — no proxy counters bump, exactly ONE
/// origin request, no duplicate request through the direct sibling.
///
/// Before F1, `first_attempt_uses_proxy` derived "proxied" from
/// `direct_client.is_some()`, which is true for a residential-only config
/// (the direct sibling is attached). So every first attempt was falsely
/// reported as proxied: `PROXY_USED_TOTAL` bumped, and an origin 402 was
/// misclassified as a proxy-402 → `PROXY_402_TOTAL` + `PROXY_FALLBACK_TOTAL`
/// bumped + a duplicate request through the direct sibling replaced the
/// caller's real 402.
#[tokio::test]
#[serial]
async fn f1_residential_only_origin_402_not_treated_as_proxy_402() {
    let (origin_port, origin_hits) = spawn_402_origin_with_counter().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in falls_back_direct_when_proxy_returns_402.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{origin_port}"),
        );
    }

    let used_before = PROXY_USED_TOTAL.load(Ordering::Relaxed);
    let p402_before = PROXY_402_TOTAL.load(Ordering::Relaxed);
    let fb_before = PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed);

    // Residential-only: NO proxy_url, NO proxy_pool, ONLY residential_proxy.
    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        residential_proxy: Some("http://127.0.0.1:9999".into()),
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    let target = format!("http://127.0.0.1:{origin_port}/paywall");
    let resp = client.get(&target).await.expect("request should complete");

    // The origin's 402 must surface unchanged — NOT be replaced by a direct
    // sibling retry (which would duplicate the request and mask the real 402).
    assert_eq!(
        resp.status, 402,
        "origin-side 402 must surface to the caller, not be masked by a false proxy-402 fallback"
    );

    // Exactly ONE origin request — no duplicate through the direct sibling.
    assert_eq!(
        origin_hits.load(Ordering::SeqCst),
        1,
        "exactly one origin request — no duplicate direct-sibling retry"
    );

    // Zero proxy counters bump — the first attempt was NOT proxied.
    assert_eq!(
        PROXY_USED_TOTAL.load(Ordering::Relaxed),
        used_before,
        "PROXY_USED_TOTAL must NOT bump for an un-challenged residential-only first attempt"
    );
    assert_eq!(
        PROXY_402_TOTAL.load(Ordering::Relaxed),
        p402_before,
        "PROXY_402_TOTAL must NOT bump for an origin-side 402"
    );
    assert_eq!(
        PROXY_FALLBACK_TOTAL.load(Ordering::Relaxed),
        fb_before,
        "PROXY_FALLBACK_TOTAL must NOT bump — no fallback should occur"
    );
}

// ---------------------------------------------------------------------------
// F2: an http→https redirect through a reachable proxy that returns 502 to
// CONNECT must NOT degrade to direct. The classifier measures the PRE-redirect
// URL scheme (http), but the failing hop is https (CONNECT tunnel). With the
// F2 fix (max_redirects gate), the classifier refuses. Without it, the
// classifier would fire and leak the real IP.
// ---------------------------------------------------------------------------

/// F2 falsification: seed `http://` that 301s to `https://`, plus a reachable
/// proxy that answers CONNECT with 502. The proxy acts as both forward proxy
/// (returns 301 for the http GET) and CONNECT tunnel (returns 502). With the
/// default `max_redirects = 10`, the classifier must refuse —
/// `PROXY_DIAL_FALLBACK_TOTAL` must NOT bump and the error must surface.
#[tokio::test]
#[serial]
async fn f2_http_to_https_redirect_not_degraded() {
    let dead_https_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };

    // The fake proxy: for a plain HTTP GET it returns 301 -> https dead target;
    // for a CONNECT it returns 502 (reachable proxy, origin unreachable).
    let proxy_port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dead = dead_https_port;
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let d = dead;
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.starts_with("CONNECT") {
                        let resp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                        let _ = sock.write_all(resp.as_bytes()).await;
                    } else {
                        let loc = format!("https://127.0.0.1:{d}/hop2");
                        let resp = format!(
                            "HTTP/1.1 301 Moved Permanently\r\nLocation: {loc}\r\nContent-Length: 0\r\n\r\n"
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                    }
                    let _ = sock.shutdown().await;
                });
            }
        });
        port
    };

    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in falls_back_direct_when_proxy_returns_402.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{proxy_port},127.0.0.1:{dead_https_port}"),
        );
    }

    let dial_fb_before = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);

    // Default max_redirects = 10 — the classifier must refuse.
    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        proxy_url: Some(format!("http://127.0.0.1:{proxy_port}")),
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    let seed = format!("http://127.0.0.1:{proxy_port}/seed");
    let result = client.get(&seed).await;

    // The error must surface (not degrade to a direct connection).
    assert!(
        result.is_err(),
        "http→https redirect + reachable-proxy CONNECT 502 must surface as Err, \
         not degrade to direct — got {:?}",
        result
    );

    let dial_fb_after = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);
    assert_eq!(
        dial_fb_after, dial_fb_before,
        "PROXY_DIAL_FALLBACK_TOTAL must NOT bump — the classifier must refuse \
         when redirects are enabled (before={dial_fb_before}, after={dial_fb_after})"
    );
}

// ---------------------------------------------------------------------------
// F4: an HTTPS dead-proxy request must bump PROXY_DIAL_TOTAL (the metric
// counts all dial failures) but NOT PROXY_DIAL_FALLBACK_TOTAL (the
// degradation is refused for HTTPS). This is the gap #86 says needs watching.
// ---------------------------------------------------------------------------

/// F4: HTTPS target + dead proxy (connect refused). The metric site gates on
/// `is_proxy_connect()` alone (no scheme gate), so `PROXY_DIAL_TOTAL` bumps.
/// The degradation decision still gates on `is_http_target` (false for HTTPS),
/// so `PROXY_DIAL_FALLBACK_TOTAL` does NOT bump.
#[tokio::test]
#[serial]
async fn f4_https_dead_proxy_bumps_dial_total_not_fallback() {
    // Reserve a port, then drop it -> connect refused (dead proxy).
    let dead_proxy_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in falls_back_direct_when_proxy_returns_402.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{dead_proxy_port},127.0.0.1:443"),
        );
    }

    let dial_total_before = PROXY_DIAL_TOTAL.load(Ordering::Relaxed);
    let dial_fb_before = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);

    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        proxy_url: Some(format!("http://127.0.0.1:{dead_proxy_port}")),
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    // HTTPS target through a dead proxy -> ProxyConnect error.
    let result = client.get("https://example.com/test").await;

    assert!(
        result.is_err(),
        "HTTPS + dead proxy must surface as an Err — got {:?}",
        result
    );

    let dial_total_after = PROXY_DIAL_TOTAL.load(Ordering::Relaxed);
    let dial_fb_after = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);

    assert!(
        dial_total_after > dial_total_before,
        "PROXY_DIAL_TOTAL must bump for an HTTPS dead-proxy dial failure \
         (before={dial_total_before}, after={dial_total_after})"
    );
    assert_eq!(
        dial_fb_after, dial_fb_before,
        "PROXY_DIAL_FALLBACK_TOTAL must NOT bump for an HTTPS target — \
         the degradation is refused (before={dial_fb_before}, after={dial_fb_after})"
    );
}
