//! Response body size cap — two-stage protection against unbounded allocation.
//!
//! ox-browser fetches attacker-chosen URLs. A multi-gigabyte response or a
//! decompression bomb (small gzip → unbounded expansion) would grow the process
//! until the container's memory limit kills it — taking every in-flight request
//! with it. This module enforces a per-call ceiling with two stages:
//!
//! 1. **Header stage** (optimisation): reject a `Content-Length` above the cap
//!    *before* allocating a buffer. This avoids the work of streaming a
//!    response whose size is honestly declared and too large.
//!
//! 2. **Stream stage** (the guarantee): stream via `bytes_stream()` with a
//!    saturating running total. This is the load-bearing stage because
//!    `Content-Length` can be absent or can lie (an attacker understating the
//!    real size, or a chunked-encoding response where Content-Length is
//!    ignored, or a decompression bomb where Content-Length reflects the
//!    compressed size but the decompressed size is unbounded).
//!
//! Both stages emit [`HttpError::BodyTooLarge`] so an operator can distinguish
//! "we hit the cap" from "the site is down" without reading code, and both bump
//! the `oxbrowser_body_cap_rejections_total` counter.
//!
//! Prior art: `0xMassi/webclaw` (Rust, wreq, same niche) caps at
//! `MAX_BODY_BYTES = 50 MB` with the same two-stage shape.

use futures_util::StreamExt;
use wreq::Response;

use crate::{HttpError, metrics};

/// Read a response body as text, enforcing a byte cap.
///
/// Stage 1: if `Content-Length` is present and exceeds `max_bytes`, reject
/// immediately (no allocation, no streaming). Stage 2: stream the body via
/// `bytes_stream()`, accumulating a running total; if it exceeds `max_bytes`,
/// abort and return [`HttpError::BodyTooLarge`]. On success, decode the
/// collected bytes as UTF-8 (lossy, matching wreq's `text()` behaviour without
/// the `charset` feature).
///
/// The `max_bytes` cap applies to the **decompressed** body size — wreq's
/// `bytes_stream()` yields bytes after gzip/brotli/zstd decompression, so a
/// decompression bomb (small compressed → huge decompressed) is caught at the
/// decompressed size, which is the size that would be allocated in memory.
pub async fn read_text_capped(response: Response, max_bytes: u64) -> Result<String, HttpError> {
    // Stage 1: header check (optimisation — avoids streaming an honestly
    // declared oversized response).
    if let Some(cl) = response.content_length()
        && cl > max_bytes
    {
        metrics::record_body_cap_rejection();
        tracing::warn!(
            content_length = cl,
            max_bytes,
            "body cap rejected: Content-Length exceeds limit (header stage)"
        );
        return Err(HttpError::BodyTooLarge {
            limit: max_bytes,
            observed: cl,
        });
    }

    // Stage 2: streaming running-total (the guarantee — catches absent or
    // lying Content-Length, and decompression bombs where CL reflects the
    // compressed size but the decompressed size exceeds the cap).
    let mut stream = response.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut total: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        total += chunk.len() as u64;
        if total > max_bytes {
            metrics::record_body_cap_rejection();
            tracing::warn!(
                observed = total,
                max_bytes,
                "body cap rejected: running total exceeds limit (stream stage)"
            );
            return Err(HttpError::BodyTooLarge {
                limit: max_bytes,
                observed: total,
            });
        }
        buf.extend_from_slice(&chunk);
    }

    // Decode as UTF-8 (lossy) — matches wreq's `text()` without the `charset`
    // feature (the http crate does not enable `charset`, so `text()` also
    // falls back to `String::from_utf8_lossy`).
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Read a reqwest response body as text, enforcing a byte cap.
///
/// Same two-stage shape as [`read_text_capped`] but for `reqwest::Response`
/// (the chrome-render fallback uses reqwest, not wreq). The cap applies to the
/// decompressed body — reqwest's `bytes_stream()` yields bytes after
/// decompression when the `gzip`/`brotli`/`zstd` features are enabled.
pub async fn read_text_capped_reqwest(
    response: reqwest::Response,
    max_bytes: u64,
) -> Result<String, HttpError> {
    if let Some(cl) = response.content_length()
        && cl > max_bytes
    {
        metrics::record_body_cap_rejection();
        tracing::warn!(
            content_length = cl,
            max_bytes,
            "body cap rejected: Content-Length exceeds limit (header stage, reqwest)"
        );
        return Err(HttpError::BodyTooLarge {
            limit: max_bytes,
            observed: cl,
        });
    }

    let mut stream = response.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut total: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| HttpError::BodyDecodeError(format!("reqwest stream: {e}")))?;
        total += chunk.len() as u64;
        if total > max_bytes {
            metrics::record_body_cap_rejection();
            tracing::warn!(
                observed = total,
                max_bytes,
                "body cap rejected: running total exceeds limit (stream stage, reqwest)"
            );
            return Err(HttpError::BodyTooLarge {
                limit: max_bytes,
                observed: total,
            });
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Decompress a gzipped byte slice with a cap on the **decompressed** byte
/// count.
///
/// This is the sitemap decompression-bomb guard. A `sitemap.xml.gz` fetched
/// from an attacker-chosen site may be a few KB on the wire but decompress
/// without limit — `read_to_end` on a `GzDecoder` would grow the buffer until
/// the container's memory limit kills the process. The cap applies to the
/// decompressed size, not the compressed size: capping the compressed size is
/// the mistake that makes a bomb guard useless (that is the entire attack).
///
/// Uses the same `HttpError::BodyTooLarge` error and
/// `oxbrowser_body_cap_rejections_total` counter as [`read_text_capped`] so
/// all body-cap rejections are observable through one metric.
pub fn gunzip_capped(input: &[u8], max_bytes: u64) -> Result<Vec<u8>, HttpError> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let mut decoder = GzDecoder::new(input);
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut total: u64 = 0;
    loop {
        let n = decoder
            .read(&mut tmp)
            .map_err(|e| HttpError::BodyDecodeError(format!("gzip decompression failed: {e}")))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max_bytes {
            metrics::record_body_cap_rejection();
            tracing::warn!(
                observed = total,
                max_bytes,
                "body cap rejected: decompressed size exceeds limit (gunzip stage)"
            );
            return Err(HttpError::BodyTooLarge {
                limit: max_bytes,
                observed: total,
            });
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    use serial_test::serial;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// Start a raw HTTP/1.1 server that sends a fixed response. The caller
    /// controls the exact raw bytes — including whether Content-Length is
    /// present, absent, or lying — which is what the cap tests need.
    ///
    /// The server reads one request (discards it), writes the raw response,
    /// and closes. Each connection gets the same `raw_response` bytes.
    async fn start_raw_server(raw_response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                // Read and discard the request (just enough to clear the
                // socket buffer — wreq sends a GET with headers).
                let mut buf = vec![0u8; 4096];
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(2), sock.readable()).await;
                let _ = sock.try_read(&mut buf);
                let _ = sock.write_all(&raw_response).await;
                let _ = sock.shutdown().await;
            }
        });
        // Give the server a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        format!("http://{addr}/")
    }

    /// Build a raw HTTP/1.1 response with `connection: close` and no
    /// Transfer-Encoding. `content_length_header`: None = omit the header
    /// entirely (body read until EOF), Some("123") = send that exact value.
    fn raw_response(content_length_header: Option<&str>, body: &str) -> Vec<u8> {
        let mut s = String::from("HTTP/1.1 200 OK\r\n");
        if let Some(cl) = content_length_header {
            s.push_str(&format!("content-length: {cl}\r\n"));
        }
        s.push_str("connection: close\r\n\r\n");
        s.push_str(body);
        s.into_bytes()
    }

    /// Build a raw HTTP/1.1 chunked response. Content-Length is present but
    /// lies (understates the real size) — RFC 7230 §3.3.3 says
    /// Transfer-Encoding: chunked takes precedence, so wreq reads the full
    /// chunked body, ignoring the lying Content-Length. This is the "CL lies"
    /// attack vector: a server declares a small Content-Length but sends a
    /// larger chunked body.
    fn raw_chunked_response_with_lying_cl(lying_content_length: &str, body: &str) -> Vec<u8> {
        let mut s = String::from("HTTP/1.1 200 OK\r\n");
        s.push_str(&format!("content-length: {lying_content_length}\r\n"));
        s.push_str("transfer-encoding: chunked\r\n");
        s.push_str("connection: close\r\n\r\n");
        // One chunk with the full body, then the terminating zero-length chunk.
        s.push_str(&format!("{:x}\r\n", body.len()));
        s.push_str(body);
        s.push_str("\r\n0\r\n\r\n");
        s.into_bytes()
    }

    /// Load-bearing test: Content-Length is ABSENT and the real body exceeds
    /// the cap. Without the streaming running-total check this would succeed
    /// (the optimisation stage has nothing to reject), so this test proves the
    /// stream stage is the actual guarantee.
    #[tokio::test]
    #[serial]
    async fn rejects_when_content_length_absent_and_body_exceeds_cap() {
        let before = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);

        let cap: u64 = 100;
        let body = "x".repeat(200);
        let url = start_raw_server(raw_response(None, &body)).await;

        let client = wreq::Client::builder().no_proxy().build().unwrap();
        let response = client.get(&url).send().await.unwrap();
        let err = read_text_capped(response, cap).await.unwrap_err();

        match err {
            HttpError::BodyTooLarge { limit, observed } => {
                assert_eq!(limit, cap, "error should name the limit");
                assert!(
                    observed > cap,
                    "observed ({observed}) should exceed cap ({cap})"
                );
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }

        let after = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);
        assert_eq!(after, before + 1, "counter must increment on rejection");
    }

    /// Content-Length LIES (understates the real size). The response uses
    /// chunked transfer encoding with a Content-Length header that declares a
    /// small size. RFC 7230 §3.3.3 makes Transfer-Encoding take precedence, so
    /// wreq reads the full chunked body (200 bytes) ignoring the lying
    /// Content-Length (50). The header stage passes (50 < cap), but the stream
    /// stage catches the real body.
    #[tokio::test]
    #[serial]
    async fn rejects_when_content_length_lies_and_body_exceeds_cap() {
        let before = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);

        let cap: u64 = 100;
        let body = "x".repeat(200);
        // Content-Length says 50, but chunked body is 200 bytes.
        let url = start_raw_server(raw_chunked_response_with_lying_cl("50", &body)).await;

        let client = wreq::Client::builder().no_proxy().build().unwrap();
        let response = client.get(&url).send().await.unwrap();
        let err = read_text_capped(response, cap).await.unwrap_err();

        match err {
            HttpError::BodyTooLarge { limit, observed } => {
                assert_eq!(limit, cap);
                assert!(
                    observed > cap,
                    "observed ({observed}) should exceed cap ({cap}) despite lying CL"
                );
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }

        let after = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);
        assert_eq!(after, before + 1);
    }

    /// A response just under the cap succeeds unchanged — the cap does not
    /// alter legitimate responses.
    #[tokio::test]
    #[serial]
    async fn succeeds_when_body_just_under_cap() {
        let before = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);

        let cap: u64 = 200;
        let body = "x".repeat(199);
        let url = start_raw_server(raw_response(Some("199"), &body)).await;

        let client = wreq::Client::builder().no_proxy().build().unwrap();
        let response = client.get(&url).send().await.unwrap();
        let text = read_text_capped(response, cap).await.unwrap();

        assert_eq!(text.len(), 199, "body should be returned unchanged");
        assert_eq!(text, "x".repeat(199));

        let after = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);
        assert_eq!(
            after, before,
            "counter must NOT increment on a successful read"
        );
    }

    /// The header stage rejects an honestly-declared oversized Content-Length
    /// before any streaming. This is the optimisation test — it proves the
    /// header stage works, but the absent-CL test above is the load-bearing one.
    ///
    /// When the header check is removed (mutation probe), this test still
    /// passes because the stream stage catches the same 200-byte body — it
    /// just wastes the work of streaming the first 100 bytes before rejecting.
    /// That confirms the header stage is genuinely only an optimisation.
    #[tokio::test]
    #[serial]
    async fn rejects_when_content_length_honestly_exceeds_cap() {
        let before = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);

        let cap: u64 = 100;
        let body = "x".repeat(200);
        // Content-Length honestly says 200, body is 200 bytes.
        let url = start_raw_server(raw_response(Some("200"), &body)).await;

        let client = wreq::Client::builder().no_proxy().build().unwrap();
        let response = client.get(&url).send().await.unwrap();
        let err = read_text_capped(response, cap).await.unwrap_err();

        match err {
            HttpError::BodyTooLarge { limit, observed } => {
                assert_eq!(limit, cap);
                // The header stage reports the CL value (200); the stream
                // stage reports the running total (101, the first chunk that
                // crosses the cap). Both are > cap, so we just check that.
                assert!(
                    observed > cap,
                    "observed ({observed}) should exceed cap ({cap})"
                );
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }

        let after = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);
        assert_eq!(after, before + 1);
    }

    /// `gunzip_capped` rejects a gzip-compressed input whose DECOMPRESSED size
    /// exceeds the cap. This is the decompression-bomb guard: the compressed
    /// input is small (well under the cap), but the decompressed output is
    /// large. Capping the compressed size would miss this — the cap must apply
    /// to the decompressed byte count.
    #[test]
    #[serial]
    fn gunzip_capped_rejects_decompressed_exceeds_cap() {
        let before = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);

        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        // 200 KB of repetitive data — compresses to ~200 bytes.
        let raw = "A".repeat(200_000);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(raw.as_bytes()).unwrap();
        let gzipped = encoder.finish().unwrap();

        // The compressed size is far below the cap — capping compressed bytes
        // would NOT catch this. The decompressed size (200 KB) exceeds the 1 KB
        // cap.
        let cap: u64 = 1024;
        assert!(
            gzipped.len() as u64 <= cap,
            "compressed size ({}) should be under cap ({cap}) — this is the bomb shape",
            gzipped.len()
        );

        let err = gunzip_capped(&gzipped, cap).unwrap_err();
        match err {
            HttpError::BodyTooLarge { limit, observed } => {
                assert_eq!(limit, cap, "error should name the limit");
                assert!(
                    observed > cap,
                    "observed ({observed}) should exceed cap ({cap})"
                );
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }

        let after = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);
        assert_eq!(after, before + 1, "counter must increment on rejection");
    }

    /// `gunzip_capped` succeeds when the decompressed size is under the cap.
    #[test]
    #[serial]
    fn gunzip_capped_succeeds_under_cap() {
        let before = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);

        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let raw = b"hello sitemap";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(raw).unwrap();
        let gzipped = encoder.finish().unwrap();

        let result = gunzip_capped(&gzipped, 1024).unwrap();
        assert_eq!(result, raw);

        let after = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);
        assert_eq!(after, before, "counter must NOT increment on success");
    }

    /// `read_text_capped_reqwest` rejects a body that exceeds the cap via the
    /// stream stage (Content-Length absent). Mirrors the wreq test but for the
    /// reqwest path used by the chrome-render fallback.
    #[tokio::test]
    #[serial]
    async fn read_text_capped_reqwest_rejects_when_body_exceeds_cap() {
        let before = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);

        let cap: u64 = 100;
        let body = "x".repeat(200);
        let url = start_raw_server(raw_response(None, &body)).await;

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client.get(&url).send().await.unwrap();
        let err = read_text_capped_reqwest(response, cap).await.unwrap_err();

        match err {
            HttpError::BodyTooLarge { limit, observed } => {
                assert_eq!(limit, cap, "error should name the limit");
                assert!(
                    observed > cap,
                    "observed ({observed}) should exceed cap ({cap})"
                );
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }

        let after = metrics::BODY_CAP_REJECTIONS_TOTAL.load(Ordering::Relaxed);
        assert_eq!(after, before + 1, "counter must increment on rejection");
    }
}
