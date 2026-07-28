//! Browser TLS + HTTP/2 fingerprint profiles built from scratch on wreq
//! (BoringSSL).
//!
//! This is a port of webclaw-fetch's `tls.rs`, adapted for ox-browser's
//! profile system. Each profile configures TLS options (cipher suites, curves,
//! extensions, PSK, ECH GREASE) and HTTP/2 options (SETTINGS order,
//! pseudo-header order, stream dependency, priorities) to match real browser
//! fingerprints.
//!
//! Why not use wreq-util's preset profiles? wreq-util's Chrome148 profile:
//!   - Sends 16 TLS extensions (missing `trust_anchors` / 0xca34), while real
//!     Chrome 148 sends 17. This makes JA4 `t13d1516h2` instead of
//!     `t13d1517h2`.
//!   - Uses `permute_extensions(true)` with no fixed `extension_permutation`,
//!     so the JA3 changes every connection (the oracle can't compare it).
//!   - Does not control header wire-order (that's in the Emulation's headers
//!     field, which wreq-util populates with a generic set).
//!
//! Building from scratch gives us:
//!   - 16 of Chrome's 17 extensions (ALPS codepoint 17613; the 17th,
//!     `trust_anchors` / 0xca34, has no wreq knob — tracked in issue #81)
//!   - A fixed extension order (matching bogdanfinn's stable JA3, which
//!     indeed.com's WAF allowlists)
//!   - HTTP/2 SETTINGS in Chrome's exact order
//!   - Headers in Chrome's exact wire order
//!
//! Issue #80: fix the 8 fingerprint fields the oracle found mismatched.

use wreq::http2::{
    Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId,
};
use wreq::tls::compress::CertificateCompressor;
use wreq::tls::{AlpnProtocol, AlpsProtocol, ExtensionType, TlsOptions, TlsVersion};
use wreq::{Emulation, Group, IntoEmulation};
use wreq_util::emulate::compress::BrotliCompressor;

use crate::profile::BrowserProfile;

// ── Chrome TLS constants ───────────────────────────────────────────────

/// Chrome cipher list (TLS 1.3 + TLS 1.2 in Chrome's exact order).
const CHROME_CIPHERS: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA";

/// Chrome signature algorithms.
const CHROME_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

/// Chrome curves (post-quantum ML-KEM + X25519 + P-256 + P-384).
const CHROME_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";

static CHROME_CERT_COMPRESSORS: &[&'static dyn CertificateCompressor] = &[&BrotliCompressor];

/// Chrome 148 TLS extension order. Real Chrome permutes extensions per
/// handshake, but a fixed order matching bogdanfinn's stable JA3 is
/// allowlisted by WAFs like indeed.com. GREASE slots are inserted by wreq.
///
/// NOTE: Real Chrome 148 sends 17 extensions. The 17th is `trust_anchors`
/// (0xca34 = 51764, draft-ietf-tls-trust-anchor-ids) — wreq exposes no way
/// to send it, so we emit 16. This produces JA4 `t13d1516h2` instead of
/// `t13d1517h2`. The 1-extension gap is a wreq limitation, not a
/// configuration error; tracked in issue #81. (51764 is `trust_anchors`,
/// NOT `application_settings_old` which is 17513 — `alps_use_new_codepoint`
/// below is already correct and selects 17613, the only ALPS codepoint real
/// Chrome 148 sends.)
fn chrome_extensions() -> Vec<ExtensionType> {
    vec![
        ExtensionType::CERTIFICATE_TIMESTAMP,                  // 18
        ExtensionType::STATUS_REQUEST,                         // 5
        ExtensionType::SESSION_TICKET,                         // 35
        ExtensionType::KEY_SHARE,                              // 51
        ExtensionType::SUPPORTED_GROUPS,                       // 10
        ExtensionType::PSK_KEY_EXCHANGE_MODES,                 // 45
        ExtensionType::EC_POINT_FORMATS,                       // 11
        ExtensionType::CERT_COMPRESSION,                       // 27
        ExtensionType::APPLICATION_SETTINGS,                   // 17613 (new ALPS)
        ExtensionType::SUPPORTED_VERSIONS,                     // 43
        ExtensionType::SIGNATURE_ALGORITHMS,                   // 13
        ExtensionType::SERVER_NAME,                            // 0
        ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, // 16
        ExtensionType::ENCRYPTED_CLIENT_HELLO,                 // 65037
        ExtensionType::RENEGOTIATE,                            // 65281
        ExtensionType::EXTENDED_MASTER_SECRET,                 // 23
    ]
}

fn chrome_tls() -> TlsOptions {
    TlsOptions::builder()
        .cipher_list(CHROME_CIPHERS)
        .sigalgs_list(CHROME_SIGALGS)
        .curves_list(CHROME_CURVES)
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .grease_enabled(true)
        .permute_extensions(false)
        .extension_permutation(chrome_extensions())
        .enable_ech_grease(true)
        .pre_shared_key(true)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        // HTTP/3 (QUIC) is NOT advertised — our wreq client can't match
        // Chrome's QUIC fingerprint, and the fingerprint oracle reference
        // was captured over HTTP/2. Advertising h3 would negotiate HTTP/3
        // when the server supports it, producing JA4 `h3` instead of `h2`.
        .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
        .alps_protocols([AlpsProtocol::HTTP2])
        .alps_use_new_codepoint(true)
        .aes_hw_override(true)
        .certificate_compressors(CHROME_CERT_COMPRESSORS)
        .build()
}

fn chrome_h2() -> Http2Options {
    Http2Options::builder()
        .initial_window_size(6_291_456)
        .initial_connection_window_size(15_728_640)
        .max_header_list_size(262_144)
        .header_table_size(65_536)
        .enable_push(false)
        .settings_order(
            SettingsOrder::builder()
                .extend([
                    SettingId::HeaderTableSize,
                    SettingId::EnablePush,
                    SettingId::InitialWindowSize,
                    SettingId::MaxHeaderListSize,
                ])
                .build(),
        )
        .headers_pseudo_order(
            PseudoOrder::builder()
                .extend([
                    PseudoId::Method,
                    PseudoId::Authority,
                    PseudoId::Scheme,
                    PseudoId::Path,
                ])
                .build(),
        )
        .headers_stream_dependency(StreamDependency::new(StreamId::zero(), 255, true))
        .build()
}

// ── Chrome headers in wire order ───────────────────────────────────────

/// Build Chrome headers in the exact wire order real Chrome emits, using the
/// profile's User-Agent and platform. Returns a Vec suitable for ox-browser's
/// Request.headers (which preserves insertion order for fingerprinting).
///
/// This replaces the generic `browser_headers()` set for Chrome/Edge profiles.
/// The key differences from the old `browser_headers()`:
///   - Adds `upgrade-insecure-requests: 1`
///   - Adds `sec-fetch-site/mode/user/dest` in the correct positions
///   - Adds `priority: u=0, i`
///   - `accept` uses `q=0.7` for signed-exchange (was `q=0.9`)
///   - `accept-encoding` includes `deflate` and `zstd` (was just `gzip,br`)
///   - Correct wire order: sec-ch-ua → sec-ch-ua-mobile → sec-ch-ua-platform →
///     upgrade-insecure-requests → user-agent → accept → sec-fetch-* →
///     accept-encoding → accept-language → priority
pub fn chrome_headers(profile: &BrowserProfile) -> Vec<(String, String)> {
    let ua = &profile.user_agent;
    let platform = extract_platform_from_ua(ua);
    let version = extract_chrome_major(ua);
    let mobile = if ua.contains("Mobile") { "?1" } else { "?0" };

    // GREASE brand — randomized per call to avoid static fingerprinting.
    let grease = pick_grease_brand();

    vec![
        (
            "sec-ch-ua".to_owned(),
            format!(
                r#""Google Chrome";v="{version}", "Chromium";v="{version}", {grease}"#
            ),
        ),
        ("sec-ch-ua-mobile".to_owned(), mobile.to_owned()),
        (
            "sec-ch-ua-platform".to_owned(),
            format!("\"{platform}\""),
        ),
        // Chrome 148 sends accept-language BEFORE upgrade-insecure-requests.
        // This differs from Chrome 133/145 order captured by webclaw.
        ("accept-language".to_owned(), "en-US,en;q=0.9".to_owned()),
        ("upgrade-insecure-requests".to_owned(), "1".to_owned()),
        ("user-agent".to_owned(), ua.to_string()),
        (
            "accept".to_owned(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_owned(),
        ),
        ("sec-fetch-site".to_owned(), "none".to_owned()),
        ("sec-fetch-mode".to_owned(), "navigate".to_owned()),
        ("sec-fetch-user".to_owned(), "?1".to_owned()),
        ("sec-fetch-dest".to_owned(), "document".to_owned()),
        ("accept-encoding".to_owned(), "gzip, deflate, br, zstd".to_owned()),
        ("priority".to_owned(), "u=0, i".to_owned()),
    ]
}

/// Edge headers — same as Chrome but with Edge brand in sec-ch-ua.
pub fn edge_headers(profile: &BrowserProfile) -> Vec<(String, String)> {
    let ua = &profile.user_agent;
    let platform = extract_platform_from_ua(ua);
    let chrome_version = extract_chrome_major(ua);
    let edge_version = extract_edge_major(ua);
    let mobile = if ua.contains("Mobile") { "?1" } else { "?0" };
    let grease = pick_grease_brand();

    vec![
        (
            "sec-ch-ua".to_owned(),
            format!(
                r#""Microsoft Edge";v="{edge_version}", "Chromium";v="{chrome_version}", {grease}"#
            ),
        ),
        ("sec-ch-ua-mobile".to_owned(), mobile.to_owned()),
        (
            "sec-ch-ua-platform".to_owned(),
            format!("\"{platform}\""),
        ),
        ("accept-language".to_owned(), "en-US,en;q=0.9".to_owned()),
        ("upgrade-insecure-requests".to_owned(), "1".to_owned()),
        ("user-agent".to_owned(), ua.to_string()),
        (
            "accept".to_owned(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_owned(),
        ),
        ("sec-fetch-site".to_owned(), "none".to_owned()),
        ("sec-fetch-mode".to_owned(), "navigate".to_owned()),
        ("sec-fetch-user".to_owned(), "?1".to_owned()),
        ("sec-fetch-dest".to_owned(), "document".to_owned()),
        ("accept-encoding".to_owned(), "gzip, deflate, br, zstd".to_owned()),
        ("priority".to_owned(), "u=0, i".to_owned()),
    ]
}

/// Build a wreq Emulation for Chrome from scratch (not using wreq-util
/// presets). This gives us full control over TLS extensions (ALPS codepoint
/// 17613; `trust_anchors` / 0xca34 is not emittable via wreq — issue #81),
/// HTTP/2 SETTINGS, and header wire order.
///
/// The Emulation's headers field is set to the Chrome wire-order set, but
/// ox-browser's middleware chain also sets headers via `browser_headers()`.
/// The middleware headers take precedence (they're applied per-request on top
/// of the Emulation defaults). Both must agree for the fingerprint to match.
pub fn chrome_emulation(profile: &BrowserProfile) -> Emulation {
    let headers = chrome_headers(profile);
    let header_map = build_header_map(&headers);

    Emulation::builder()
        .tls_options(chrome_tls())
        .http2_options(chrome_h2())
        .headers(header_map)
        .build(Group::default())
}

/// Build a wreq Emulation for Edge — same TLS/HTTP2 as Chrome, different
/// headers.
pub fn edge_emulation(profile: &BrowserProfile) -> Emulation {
    let headers = edge_headers(profile);
    let header_map = build_header_map(&headers);

    Emulation::builder()
        .tls_options(chrome_tls())
        .http2_options(chrome_h2())
        .headers(header_map)
        .build(Group::default())
}

/// Build a wreq Emulation for Firefox. Firefox uses wreq-util's preset
/// profile (the TLS fingerprint is correct for Firefox) with Platform
/// override.
pub fn firefox_emulation(profile: &BrowserProfile) -> Option<Emulation> {
    let ua = &profile.user_agent;
    let major = crate::profile::extract_major_version_pub(ua)?;
    let p = firefox_profile(major)?;
    Some(p.into_emulation())
}

/// Build a wreq Emulation for Safari. Safari uses wreq-util's preset profile
/// with Platform override.
pub fn safari_emulation(profile: &BrowserProfile) -> Option<Emulation> {
    let ua = &profile.user_agent;
    let major = crate::profile::extract_major_version_pub(ua)?;
    let p = safari_profile(profile, major)?;
    Some(p.into_emulation())
}

// ── Helpers ────────────────────────────────────────────────────────────

fn build_header_map(pairs: &[(String, String)]) -> wreq::header::HeaderMap {
    let mut map = wreq::header::HeaderMap::with_capacity(pairs.len());
    for (name, value) in pairs {
        if let (Ok(n), Ok(v)) = (
            wreq::header::HeaderName::from_bytes(name.as_bytes()),
            wreq::header::HeaderValue::from_str(value),
        ) {
            map.insert(n, v);
        }
    }
    map
}

fn extract_platform_from_ua(ua: &str) -> &'static str {
    if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Macintosh") || ua.contains("Mac OS X") {
        "macOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "Windows"
    }
}

fn extract_chrome_major(ua: &str) -> &str {
    if let Some(idx) = ua.find("Chrome/") {
        let rest = &ua[idx + 7..];
        match rest.find('.') {
            Some(dot) => &rest[..dot],
            None => rest,
        }
    } else {
        "148"
    }
}

fn extract_edge_major(ua: &str) -> &str {
    if let Some(idx) = ua.find("Edg/") {
        let rest = &ua[idx + 4..];
        match rest.find('.') {
            Some(dot) => &rest[..dot],
            None => rest,
        }
    } else {
        "145"
    }
}

const GREASE_BRANDS: &[&str] = &[
    r#""Not_A Brand";v="8""#,
    r#""Not/A)Brand";v="8""#,
    r#""Not A(Brand";v="99""#,
    r#""Not:A-Brand";v="99""#,
];

fn pick_grease_brand() -> &'static str {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    GREASE_BRANDS
        .choose(&mut rng)
        .copied()
        .unwrap_or(GREASE_BRANDS[0])
}

// ── Firefox/Safari profile mapping (delegated to wreq-util presets) ────

fn firefox_profile(major: u32) -> Option<wreq_util::Profile> {
    use wreq_util::Profile::*;
    let p = match major {
        148..=151 => Firefox148,
        142..=147 => Firefox142,
        139..=141 => Firefox139,
        136..=138 => Firefox136,
        135 => Firefox135,
        133..=134 => Firefox133,
        128..=132 => Firefox128,
        117..=127 => Firefox117,
        109..=116 => Firefox109,
        _ => Firefox148,
    };
    Some(p)
}

fn safari_profile(profile: &BrowserProfile, major: u32) -> Option<wreq_util::Profile> {
    use wreq_util::Profile::*;
    // iOS Safari
    if profile.os == "ios" {
        let p = match major {
            26 => SafariIos26,
            18 => SafariIos18_1_1,
            17 => SafariIos17_4_1,
            16 => SafariIos16_5,
            _ => SafariIos26,
        };
        return Some(p);
    }
    // Desktop Safari
    let p = match major {
        26 => Safari26,
        18..=25 => Safari18_5,
        17 => Safari17_0,
        16 => Safari16_5,
        _ => Safari18_5,
    };
    Some(p)
}

// ── Fingerprint oracle classification ───────────────────────────────────
//
// Pure verdict logic for the fingerprint oracle
// (crates/http/tests/fingerprint_oracle_test.rs). Extracted from the test so
// it can be unit-tested without the `fingerprint` feature, which needs live
// network access to tls.peet.ws / tls.browserleaks.com.

/// Bucket A — structurally non-comparable, permanent by policy.
///
/// `ja3_hash` and `ja4_o` are both order-sensitive. Chrome permutes
/// ClientHello extensions per handshake, so a reference capture is one sample
/// of a randomised order and can never be matched by any fixed-order client.
/// We deliberately choose a fixed extension order for WAF-allowlist stability
/// (the bogdanfinn approach). This is a policy decision, not a library
/// limitation, and these two fields never come off the list — a coincidental
/// match on a given run carries no signal, so bucket A is NOT self-expiring.
pub const FP_BUCKET_A: &[&str] = &["ja3_hash", "ja4_o"];

/// Bucket B — known gap, tracked and temporary.
///
/// `ja3n_hash`, `ja4`, and `peetprint_hash` all fail for one cause: the
/// missing `trust_anchors` extension (0xca34) leaves us at 16 extensions
/// instead of 17 (`t13d1516h2` vs `t13d1517h2`). Tracked in issue #81. When
/// that gap closes, every field in this bucket must be removed — the oracle
/// enforces this by FAILING if a bucket-B field now matches the reference
/// (see [`classify_fingerprint_diffs`]).
pub const FP_BUCKET_B: &[&str] = &["ja3n_hash", "ja4", "peetprint_hash"];

/// Verdict returned by [`classify_fingerprint_diffs`].
#[derive(Debug, Default)]
pub struct FingerprintVerdict {
    /// Bucket-A fields that differed (tolerated, permanent).
    pub tolerated_a: Vec<String>,
    /// Bucket-B fields that differed (tolerated, gap still open).
    pub tolerated_b: Vec<String>,
    /// Bucket-B fields that now MATCH the reference — the gap has closed and
    /// they MUST be removed from [`FP_BUCKET_B`]. A non-empty list is a
    /// FAILURE: a closed gap that keeps being ignored is a defect.
    pub gap_closed: Vec<String>,
    /// Diffs outside both buckets — hard failures, the profile is wrong.
    pub hard_failures: Vec<(String, String, String)>,
}

impl FingerprintVerdict {
    /// True if the verdict is clean (no hard failures, no closed gap).
    pub fn is_ok(&self) -> bool {
        self.hard_failures.is_empty() && self.gap_closed.is_empty()
    }
}

/// Classify fingerprint diffs against the two suppression buckets.
///
/// `diffs` is `(field, expected, observed)` for every field that differed.
/// `comparable_b` is the subset of [`FP_BUCKET_B`] fields that were actually
/// measured on both sides (reference non-empty) — a match is only meaningful
/// for those; a field with no reference value is not "matching", it's absent.
///
/// - A diff in bucket A → tolerated.
/// - A diff in bucket B → tolerated (gap still open).
/// - A bucket-B field in `comparable_b` with NO diff → `gap_closed` (FAIL).
/// - A diff outside both buckets → `hard_failures` (FAIL).
pub fn classify_fingerprint_diffs(
    diffs: &[(String, String, String)],
    comparable_b: &[&str],
) -> FingerprintVerdict {
    let mut v = FingerprintVerdict::default();
    for d in diffs {
        if FP_BUCKET_A.contains(&d.0.as_str()) {
            v.tolerated_a.push(d.0.clone());
        } else if FP_BUCKET_B.contains(&d.0.as_str()) {
            v.tolerated_b.push(d.0.clone());
        } else {
            v.hard_failures.push(d.clone());
        }
    }
    // Self-expiring: any comparable bucket-B field that did NOT diff has
    // matched the reference — the gap closed, it must leave the list.
    for field in comparable_b {
        if !FP_BUCKET_B.contains(field) {
            continue;
        }
        if !diffs.iter().any(|d| &d.0 == field) {
            v.gap_closed.push((*field).to_string());
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(field: &str, exp: &str, obs: &str) -> (String, String, String) {
        (field.to_string(), exp.to_string(), obs.to_string())
    }

    // Case 1: a diff in bucket A is tolerated.
    #[test]
    fn bucket_a_diff_is_tolerated() {
        let v = classify_fingerprint_diffs(&[d("ja3_hash", "a", "b")], &[]);
        assert!(v.is_ok());
        assert_eq!(v.tolerated_a, vec!["ja3_hash"]);
        assert!(v.tolerated_b.is_empty());
        assert!(v.gap_closed.is_empty());
        assert!(v.hard_failures.is_empty());
    }

    // Case 2: a diff in bucket B is tolerated (gap still open).
    #[test]
    fn bucket_b_diff_is_tolerated() {
        let v = classify_fingerprint_diffs(&[d("ja4", "t13d1517h2", "t13d1516h2")], &["ja4"]);
        assert!(v.is_ok());
        assert_eq!(v.tolerated_b, vec!["ja4"]);
        assert!(v.gap_closed.is_empty());
        assert!(v.hard_failures.is_empty());
    }

    // Case 3 (falsification): a comparable bucket-B field that MATCHED (no
    // diff) means the trust_anchors gap has closed → must FAIL. This is the
    // case that was silently green under the old single-bucket partition and
    // is now RED-on-match.
    #[test]
    fn bucket_b_match_signals_gap_closed() {
        let v = classify_fingerprint_diffs(&[], &["ja4"]);
        assert!(!v.is_ok(), "a closed gap must not be tolerated");
        assert_eq!(v.gap_closed, vec!["ja4"]);
        assert!(v.hard_failures.is_empty());
    }

    // Case 4: a diff outside both buckets is a hard failure.
    #[test]
    fn diff_outside_buckets_is_hard_fail() {
        let v = classify_fingerprint_diffs(&[d("http2_akamai", "x", "y")], &[]);
        assert!(!v.is_ok());
        assert_eq!(v.hard_failures.len(), 1);
        assert_eq!(v.hard_failures[0].0, "http2_akamai");
        assert!(v.gap_closed.is_empty());
    }

    // Bucket A is NOT self-expiring: a comparable-A field that matched must
    // NOT trip gap_closed (coincidental matches carry no signal).
    #[test]
    fn bucket_a_match_does_not_trip_gap_closed() {
        let v = classify_fingerprint_diffs(&[], &["ja3_hash"]);
        assert!(v.is_ok(), "bucket A has no gap-closed semantics");
        assert!(v.gap_closed.is_empty());
    }
}
