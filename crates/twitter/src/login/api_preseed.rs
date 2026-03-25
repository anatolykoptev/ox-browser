//! Pre-seed cookies by visiting x.com before API login.
//!
//! Twitter's login flow expects a ct0 CSRF token from cookies.
//! This module fetches x.com to obtain it, falling back to random.

use super::error::TwitterLoginError;

/// Visit x.com to pre-seed cookies (especially ct0).
/// Falls back to a random hex ct0 if the site doesn't set one.
pub(super) async fn pre_seed_cookies(
    client: &wreq::Client,
) -> Result<String, TwitterLoginError> {
    let resp = client
        .get("https://x.com/")
        .header(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-site", "none")
        .header("sec-fetch-user", "?1")
        .header("upgrade-insecure-requests", "1")
        .send()
        .await
        .map_err(|e| TwitterLoginError::ApiError {
            status: 0,
            body: format!("pre-seed GET x.com: {e}"),
        })?;

    tracing::info!(
        status = resp.status().as_u16(),
        "API login: pre-seed GET x.com done"
    );

    // Try to extract ct0 from set-cookie headers
    for value in resp.headers().get_all("set-cookie").iter() {
        if let Ok(s) = value.to_str() {
            if let Some(ct0) = extract_ct0_from_set_cookie(s) {
                return Ok(ct0);
            }
        }
    }

    // Fallback: generate random ct0
    let ct0 = generate_random_ct0();
    tracing::info!("API login: no ct0 from x.com, using random");
    Ok(ct0)
}

fn extract_ct0_from_set_cookie(header: &str) -> Option<String> {
    // Format: "ct0=<value>; ..."
    if !header.starts_with("ct0=") {
        return None;
    }
    let value = &header[4..];
    let end = value.find(';').unwrap_or(value.len());
    let ct0 = &value[..end];
    if ct0.is_empty() {
        return None;
    }
    Some(ct0.to_string())
}

fn generate_random_ct0() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.r#gen();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ct0_basic() {
        let header = "ct0=abc123; Path=/; Domain=.x.com; Secure";
        assert_eq!(
            extract_ct0_from_set_cookie(header),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn extract_ct0_no_semicolon() {
        assert_eq!(
            extract_ct0_from_set_cookie("ct0=xyz"),
            Some("xyz".to_string())
        );
    }

    #[test]
    fn extract_ct0_wrong_name() {
        assert_eq!(extract_ct0_from_set_cookie("auth_token=abc"), None);
    }

    #[test]
    fn extract_ct0_empty_value() {
        assert_eq!(extract_ct0_from_set_cookie("ct0=; Path=/"), None);
    }

    #[test]
    fn random_ct0_is_32_hex_chars() {
        let ct0 = generate_random_ct0();
        assert_eq!(ct0.len(), 32);
        assert!(ct0.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
