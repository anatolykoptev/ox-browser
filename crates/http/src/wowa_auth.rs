//! Credential for calls to go-wowa (the go-browser Chrome service).
//!
//! go-wowa rejects requests without a credential on every route except
//! `/health`. ox-browser authenticates with the fleet's shared
//! `INTERNAL_SERVICE_SECRET`, sent as `X-Internal-Secret`.

use reqwest::header::{HeaderMap, HeaderValue};

/// Header go-wowa reads the internal secret from.
pub const SECRET_HEADER: &str = "x-internal-secret";

/// Environment variable holding the secret.
pub const SECRET_ENV: &str = "INTERNAL_SERVICE_SECRET";

/// Reads the secret from the environment; empty when unset.
pub fn secret_from_env() -> String {
    std::env::var(SECRET_ENV).unwrap_or_default()
}

/// Default headers for a reqwest client that talks to go-wowa. Empty when
/// `secret` is empty, or when it is not a valid header value (logged).
pub fn headers(secret: &str) -> HeaderMap {
    let mut map = HeaderMap::new();
    if secret.is_empty() {
        return map;
    }
    match HeaderValue::from_str(secret) {
        Ok(mut value) => {
            value.set_sensitive(true);
            map.insert(SECRET_HEADER, value);
        }
        Err(_) => tracing::warn!(
            "{SECRET_ENV} is not a valid HTTP header value; go-wowa calls will be unauthenticated"
        ),
    }
    map
}

/// Test helper: a one-shot HTTP server on 127.0.0.1 that answers with
/// `body` as JSON and hands back the raw request head it received, so a test
/// can assert which headers a go-wowa client sent.
#[cfg(any(test, feature = "test-utils"))]
pub async fn capture_one(body: &'static str) -> (String, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind capture server");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock.read(&mut chunk).await.expect("read");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = sock.write_all(resp.as_bytes()).await;
        String::from_utf8_lossy(&buf).to_ascii_lowercase()
    });
    (url, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_secret_yields_no_header() {
        assert!(headers("").is_empty());
    }

    #[test]
    fn secret_is_sent_and_marked_sensitive() {
        let h = headers("s3cret");
        let v = h.get(SECRET_HEADER).expect("header present");
        assert_eq!(v, "s3cret");
        assert!(v.is_sensitive());
    }

    #[test]
    fn invalid_secret_yields_no_header() {
        assert!(headers("bad\nvalue").is_empty());
    }
}
