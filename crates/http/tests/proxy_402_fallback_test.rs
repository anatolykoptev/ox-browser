//! Integration tests for proxy fallback behaviour.
//!
//! The response-inferred 402 → direct-connection degradation has been
//! **removed** (issue #90). Three attempts to attribute a relayd `HTTP 402`
//! to the upstream proxy (by status code, by response header, by URL scheme)
//! were each bypassable — a plain-HTTP forward proxy relays the origin's own
//! headers, so the origin can forge any marker and trigger a direct re-send
//! of the identical request from the real IP. The tests below assert that a
//! 402 does NOT degrade, guarding against reintroduction.
//!
//! What survives is the **dial-failure fallback**: when the proxy host itself
//! is unreachable (connect refused / DNS / TLS handshake to the proxy), the
//! request is retried once through the direct sibling. The classifier uses
//! wreq's typed `is_proxy_connect()` predicate gated to HTTP targets with
//! `max_redirects == 0`.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ox_http::metrics::{
    PROXY_402_TOTAL, PROXY_ATTACH_INVALID_URL_TOTAL, PROXY_DIAL_TOTAL, PROXY_USED_TOTAL,
};
use ox_http::proxy_fallback::PROXY_DIAL_FALLBACK_TOTAL;
use ox_http::{HttpClient, HttpConfig};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Reserve a TCP port, then drop the listener so nothing accepts on it —
/// connect attempts to the returned port get "connection refused". Extracted
/// from the five hand-copied inline copies of this idiom in this PR.
async fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

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

/// Spawn an HTTP origin that returns 200 OK and counts how many connections
/// it received — so tests can assert ZERO direct-sibling retries.
async fn spawn_ok_origin_with_counter() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
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
    (port, count)
}

/// Spawn an HTTP origin that returns 402 and counts how many connections it
/// received (so the test can assert exactly ONE origin request — no duplicate
/// direct-sibling retry).
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

// ---------------------------------------------------------------------------
// A: a 402 — with or without a forged proxy marker — must NOT degrade to
// direct. The response-inferred 402 degradation was removed (issue #90)
// because a relayed response can never attribute a plain-HTTP forward-proxy
// failure. These tests are the regression guard for the whole class.
// ---------------------------------------------------------------------------

/// A (falsification): an http proxy returning 402 + a forged
/// `X-Webshare-Error` header must NOT degrade to direct. The proxy returns
/// 402 with the marker the old heuristic trusted; a direct sibling origin
/// returns 200. If the `Ok(resp) if resp.status == 402 && is_proxy_attributed_402`
/// degradation arm is reintroduced, this test FAILS: the 402 is re-sent
/// through the direct client, the direct origin receives 1 request (not 0),
/// and the response is 200 (not 402).
#[tokio::test]
#[serial]
async fn a_http_402_with_forged_marker_not_degraded() {
    let proxy_port = spawn_402_proxy().await;
    let (origin_port, origin_hits) = spawn_ok_origin_with_counter().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: tests in this file rely on this env var; no other test in the
    // ox-http crate writes OX_HTTP_PRIVATE_ALLOWLIST.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{proxy_port},127.0.0.1:{origin_port}"),
        );
    }

    let p402_before = PROXY_402_TOTAL.load(Ordering::Relaxed);

    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        proxy_url: Some(format!("http://127.0.0.1:{proxy_port}")),
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    // Request to the origin through the proxy. The proxy returns 402 + forged
    // X-Webshare-Error. The direct sibling (200) is attached but must NOT be
    // used.
    let target = format!("http://127.0.0.1:{origin_port}/paywall");
    let resp = client.get(&target).await.expect("request should complete");

    // The proxy's 402 must surface — NOT be replaced by a 200 from a direct
    // sibling retry (which would re-send the identical request from the real
    // IP to an origin that already saw the proxy IP for that exact request).
    assert_eq!(
        resp.status, 402,
        "402 with forged X-Webshare-Error must surface to the caller, not degrade to direct"
    );

    // The direct origin must receive ZERO requests — no direct retry.
    assert_eq!(
        origin_hits.load(Ordering::SeqCst),
        0,
        "direct origin must receive zero requests — no degradation to direct"
    );

    // PROXY_402_TOTAL must bump — we saw a 402 while proxied (observation-only
    // counter, no attribution guess).
    assert!(
        PROXY_402_TOTAL.load(Ordering::Relaxed) > p402_before,
        "PROXY_402_TOTAL must bump for a 402 while proxied (observation-only counter)"
    );
}

/// A: with no proxy configured, a 402 from the target itself must NOT retry
/// and must NOT bump any proxy counter. A 402 from the target is not a
/// proxy-quota signal.
#[tokio::test]
#[serial]
async fn no_fallback_when_no_proxy_configured() {
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

    // SAFETY: see note in a_http_402_with_forged_marker_not_degraded.
    unsafe {
        std::env::set_var("OX_HTTP_PRIVATE_ALLOWLIST", format!("127.0.0.1:{port}"));
    }

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
/// misclassified as a proxy-402 → `PROXY_402_TOTAL` bumped + a duplicate
/// request through the direct sibling replaced the caller's real 402.
#[tokio::test]
#[serial]
async fn f1_residential_only_origin_402_not_treated_as_proxy_402() {
    let (origin_port, origin_hits) = spawn_402_origin_with_counter().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in a_http_402_with_forged_marker_not_degraded.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{origin_port}"),
        );
    }

    let used_before = PROXY_USED_TOTAL.load(Ordering::Relaxed);
    let p402_before = PROXY_402_TOTAL.load(Ordering::Relaxed);

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
        "PROXY_402_TOTAL must NOT bump for an origin-side 402 (not proxied)"
    );
}

// ---------------------------------------------------------------------------
// Dial-failure fallback (surviving degradation path)
// ---------------------------------------------------------------------------

/// A proxy pointed at a **closed** port (connect refused) must degrade to
/// direct and increment the dial-failure counter. HTTP target so the
/// classifier's forward-proxy path applies (`is_proxy_connect()` is precisely
/// a proxy-dial failure there).
///
/// F2: `max_redirects: 0` is required — the dial-failure classifier now
/// refuses when redirects are enabled (the failing hop's scheme is
/// unobservable after a redirect, so degrading could leak the real IP
/// through a healthy proxy).
#[tokio::test]
#[serial]
async fn falls_back_direct_when_proxy_is_dead() {
    let dead_proxy_port = dead_port().await;
    let origin_port = spawn_ok_origin().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in a_http_402_with_forged_marker_not_degraded.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{dead_proxy_port},127.0.0.1:{origin_port}"),
        );
    }

    let dial_before = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);

    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        proxy_url: Some(format!("http://127.0.0.1:{dead_proxy_port}")),
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
    assert!(
        dial_after > dial_before,
        "dial-fallback counter must increment (before={dial_before}, after={dial_after})"
    );
}

/// F3-rescoped: a **reachable** proxy that cannot reach the origin must NOT
/// trigger the dial fallback. The proxy is healthy (the dial to it
/// succeeded); the failure is on the origin side. Falling back to direct
/// here would expose the real IP for no benefit — exactly the case the
/// classifier is designed to refuse.
///
/// F3: the previous version of this test used an HTTP target + a proxy that
/// returns a 502 *response*. That produced `Ok(HttpResponse{status:502})`,
/// so neither classifier call site (which require `Err`) was ever reached —
/// the test was synthetic-green. This version uses an **HTTPS** target so
/// the proxy exercises the CONNECT-tunnel path: the proxy accepts the
/// CONNECT, returns 502 (origin unreachable), and wreq surfaces that as a
/// `ProxyConnect` *Err*. `max_redirects: 0` is set so the F2 redirect-guard
/// does not pre-empt — the refusal is exercised specifically via the
/// HTTPS-scheme gate (`is_http_target` is false). The error must surface to
/// the caller and the dial-fallback counter must NOT bump.
#[tokio::test]
#[serial]
async fn does_not_fallback_when_proxy_reachable_but_origin_unreachable() {
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

    let dead_origin_port = dead_port().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in a_http_402_with_forged_marker_not_degraded.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{proxy_port},127.0.0.1:{dead_origin_port}"),
        );
    }

    let dial_before = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);
    // D: also capture PROXY_DIAL_TOTAL — a bump proves the error reached the
    // classifier as a ProxyConnect (the metric arm gates on is_proxy_connect()
    // alone, no scheme gate). Without this assertion the test passes vacuously
    // if wreq stops mapping TunnelError::TunnelUnsuccessful to ProxyConnect.
    let dial_total_before = PROXY_DIAL_TOTAL.load(Ordering::Relaxed);

    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        proxy_url: Some(format!("http://127.0.0.1:{proxy_port}")),
        max_redirects: 0,
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    let target = format!("https://127.0.0.1:{dead_origin_port}/test");
    let result = client.get(&target).await;

    assert!(
        result.is_err(),
        "reachable-proxy + unreachable-origin (HTTPS CONNECT 502) must surface \
         as an Err, not fall back to direct — got {:?}",
        result
    );

    // D: PROXY_DIAL_TOTAL must bump — proves the error was a ProxyConnect.
    let dial_total_after = PROXY_DIAL_TOTAL.load(Ordering::Relaxed);
    assert!(
        dial_total_after > dial_total_before,
        "PROXY_DIAL_TOTAL must bump — the error reached the classifier as a \
         ProxyConnect (before={dial_total_before}, after={dial_total_after})."
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
    let dead_https_port = dead_port().await;

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

    // SAFETY: see note in a_http_402_with_forged_marker_not_degraded.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{proxy_port},127.0.0.1:{dead_https_port}"),
        );
    }

    let dial_fb_before = PROXY_DIAL_FALLBACK_TOTAL.load(Ordering::Relaxed);
    // D: also capture PROXY_DIAL_TOTAL — a bump proves the error reached the
    // classifier as a ProxyConnect.
    let dial_total_before = PROXY_DIAL_TOTAL.load(Ordering::Relaxed);

    // Default max_redirects = 10 — the classifier must refuse.
    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        proxy_url: Some(format!("http://127.0.0.1:{proxy_port}")),
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    let seed = format!("http://127.0.0.1:{proxy_port}/seed");
    let result = client.get(&seed).await;

    assert!(
        result.is_err(),
        "http→https redirect + reachable-proxy CONNECT 502 must surface as Err, \
         not degrade to direct — got {:?}",
        result
    );

    // D: PROXY_DIAL_TOTAL must bump — proves the error was a ProxyConnect.
    let dial_total_after = PROXY_DIAL_TOTAL.load(Ordering::Relaxed);
    assert!(
        dial_total_after > dial_total_before,
        "PROXY_DIAL_TOTAL must bump — the error reached the classifier as a \
         ProxyConnect (before={dial_total_before}, after={dial_total_after})."
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
    let dead_proxy_port = dead_port().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in a_http_402_with_forged_marker_not_degraded.
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

// ---------------------------------------------------------------------------
// B: a proxy that fails to attach must fail CLOSED, not silently go direct.
// Each rejection reason gets its own counter and a tracing::warn! (issue:
// unobservable_enforcement).
// ---------------------------------------------------------------------------

/// B: an unparsable `req.proxy` must fail with an error, not silently drop
/// the proxy and proceed direct. `PROXY_USED_TOTAL` must NOT bump (the proxy
/// never attached). `PROXY_ATTACH_INVALID_URL_TOTAL` must bump (the rejection
//  is now observable). Reverting the fail-closed `?` (restoring the empty
/// `Err` branch) makes this test fail (the request proceeds direct and
/// returns 200 from the origin). Reverting the counter makes the
/// `PROXY_ATTACH_INVALID_URL_TOTAL` assertion fail.
#[tokio::test]
#[serial]
async fn b_invalid_proxy_url_fails_closed() {
    use ox_http::Request;

    let origin_port = spawn_ok_origin().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in a_http_402_with_forged_marker_not_degraded.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{origin_port}"),
        );
    }

    let used_before = PROXY_USED_TOTAL.load(Ordering::Relaxed);
    let invalid_before = PROXY_ATTACH_INVALID_URL_TOTAL.load(Ordering::Relaxed);

    // Residential-only config: NO proxy_url, NO proxy_pool. The base client
    // has NO static proxy (build_wreq_client calls .no_proxy()), so if the
    // per-request req.proxy is silently dropped, the request goes DIRECT and
    // reaches the origin (200). direct_client is attached because
    // needs_fallback covers residential_proxy.
    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        residential_proxy: Some("http://127.0.0.1:9999".into()),
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    let req = Request {
        method: "GET".into(),
        url: format!("http://127.0.0.1:{origin_port}/test"),
        headers: vec![],
        body: None,
        proxy: Some("not-a-valid-url".into()),
    };
    let result = client.execute(req).await;

    assert!(
        result.is_err(),
        "invalid req.proxy must fail closed, not silently go direct — got {:?}",
        result
    );

    assert_eq!(
        PROXY_USED_TOTAL.load(Ordering::Relaxed),
        used_before,
        "PROXY_USED_TOTAL must NOT bump when the proxy failed to attach"
    );

    // B: the rejection must be observable via its own counter.
    assert!(
        PROXY_ATTACH_INVALID_URL_TOTAL.load(Ordering::Relaxed) > invalid_before,
        "PROXY_ATTACH_INVALID_URL_TOTAL must bump — the fail-closed rejection \
         must be observable, not indistinguishable from any other InvalidUrl"
    );
}

// ---------------------------------------------------------------------------
// C: an ambient HTTP_PROXY must NOT silently proxy the base client when
// proxy_url is unset. build_wreq_client must call .no_proxy() in that case.
// ---------------------------------------------------------------------------

/// C: with `HTTP_PROXY` set to a dead port and no `proxy_url` configured,
/// the base client must NOT honor the ambient proxy. If `.no_proxy()` is
/// missing (the bug), the request tries the dead proxy and errors. With the
/// fix, the request goes direct and succeeds. Reverting the `.no_proxy()`
/// call makes this test fail (the request errors via the dead ambient proxy).
#[tokio::test]
#[serial]
async fn c_ambient_http_proxy_not_honored() {
    let dead_proxy_port = dead_port().await;
    let origin_port = spawn_ok_origin().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in a_http_402_with_forged_marker_not_degraded.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{origin_port}"),
        );
        std::env::set_var("HTTP_PROXY", format!("http://127.0.0.1:{dead_proxy_port}"));
    }

    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    // Clean up the env var — wreq already read it at build time.
    // SAFETY: no other thread reads HTTP_PROXY between here and the request
    // (all tests in this file are #[serial]).
    unsafe {
        std::env::remove_var("HTTP_PROXY");
    }

    let target = format!("http://127.0.0.1:{origin_port}/test");
    let result = client.get(&target).await;

    assert!(
        result.is_ok(),
        "ambient HTTP_PROXY must NOT silently proxy the base client when \
         proxy_url is unset — got {:?}",
        result
    );
    assert_eq!(
        result.unwrap().status,
        200,
        "request should reach the origin directly, not via the ambient proxy"
    );
}

// ---------------------------------------------------------------------------
// E: boundary test — max_redirects: 0 must block even the FIRST redirect.
// The F2 safety claim depends on this: the dial-failure classifier gates on
// max_redirects == 0, and the claim is that no redirect can occur at 0.
// ---------------------------------------------------------------------------

/// E: with `max_redirects: 0`, a 301 must NOT be followed. The ssrf_redirect
/// policy checks `attempt.previous.len() > max_redirects`; on the first
/// redirect `previous` includes the initial URI (len=1), so `1 > 0` blocks
/// with `SsrfBlockedError("too many redirects")`. If the redirect IS followed
/// (200 from the target), that is a finding — the F2 safety claim is
/// falsified. D: the error must specifically mention "too many redirects",
/// not just be any `Err(_)`.
#[tokio::test]
#[serial]
async fn e_max_redirects_zero_blocks_first_redirect() {
    let origin2_port = spawn_ok_origin().await;

    // First origin returns 301 -> origin2.
    let origin1_port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = format!("http://127.0.0.1:{origin2_port}/hop2");
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let t = target.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 301 Moved Permanently\r\n\
                         Location: {t}\r\n\
                         Content-Length: 0\r\n\
                         \r\n"
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        port
    };

    tokio::time::sleep(Duration::from_millis(50)).await;

    // SAFETY: see note in a_http_402_with_forged_marker_not_degraded.
    unsafe {
        std::env::set_var(
            "OX_HTTP_PRIVATE_ALLOWLIST",
            format!("127.0.0.1:{origin1_port},127.0.0.1:{origin2_port}"),
        );
    }

    let config = HttpConfig {
        timeout: Duration::from_secs(5),
        max_redirects: 0,
        ..Default::default()
    };
    let client = HttpClient::new(config).expect("build client");

    let target = format!("http://127.0.0.1:{origin1_port}/seed");
    let result = client.get(&target).await;

    // D: the redirect must NOT be followed. With max_redirects=0, the policy
    // blocks the first redirect (previous.len()=1 > 0) by returning
    // `SsrfBlockedError("too many redirects")`, which wreq wraps into an Err.
    // Assert the SPECIFIC error condition — not just `result.is_err()`, which
    // is non-discriminating (a network failure would also be Err).
    match result {
        Ok(resp) => {
            assert_ne!(
                resp.status, 200,
                "max_redirects=0 must block the first redirect — got 200 \
                 from the redirect target, the F2 safety claim is falsified"
            );
        }
        Err(e) => {
            // The error must specifically be the redirect-policy refusal,
            // not any other failure. `SsrfBlockedError("too many redirects")`
            // is wrapped by wreq into `HttpError::Request(_)`. Its Display
            // chain must contain "too many redirects".
            let msg = e.to_string();
            assert!(
                msg.contains("too many redirects"),
                "error must be the redirect-policy refusal (must contain \
                 'too many redirects'), got: {msg}"
            );
        }
    }
}
