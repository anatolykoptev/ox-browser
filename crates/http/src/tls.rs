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
//!   - All 17 of Chrome's extensions, including `trust_anchors` (0xca34 =
//!     51764, draft-ietf-tls-trust-anchor-ids), sent via the patched wreq
//!     fork's `TlsOptions::requested_trust_anchors` (see workspace
//!     Cargo.toml `[patch.crates.io]`; tracked in issue #81). ALPS uses the
//!     new codepoint 17613 (the only ALPS codepoint real Chrome 148 sends).
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
/// Emits all 17 of real Chrome 148's extensions, including `trust_anchors`
/// (0xca34 = 51764, draft-ietf-tls-trust-anchor-ids). The extension is sent
/// via `TlsOptions::requested_trust_anchors` (see `chrome_tls`); listing it
/// here fixes its wire position. btls exposes no named constant for 51764,
/// so it is constructed via `ExtensionType::from`. (51764 is `trust_anchors`,
/// NOT `application_settings_old` which is 17513 — `alps_use_new_codepoint`
/// in `chrome_tls` is already correct and selects 17613, the only ALPS
/// codepoint real Chrome 148 sends.)
///
/// Position of 51764: the reference's wire order places it between
/// `ec_point_formats` (11) and `supported_versions` (43). Our list is a
/// deliberately fixed order that already differs from Chrome's per-handshake
/// permutation, so the exact slot only affects `ja3_hash`/`ja4_o` (bucket A,
/// permanently non-comparable). We insert 51764 immediately after
/// `EC_POINT_FORMATS` to preserve the reference's relative ordering
/// (51764 after 11, before 43).
fn chrome_extensions() -> Vec<ExtensionType> {
    vec![
        ExtensionType::CERTIFICATE_TIMESTAMP,                  // 18
        ExtensionType::STATUS_REQUEST,                         // 5
        ExtensionType::SESSION_TICKET,                         // 35
        ExtensionType::KEY_SHARE,                              // 51
        ExtensionType::SUPPORTED_GROUPS,                       // 10
        ExtensionType::PSK_KEY_EXCHANGE_MODES,                 // 45
        ExtensionType::EC_POINT_FORMATS,                       // 11
        ExtensionType::from(51764),                            // trust_anchors (0xca34)
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
        // trust_anchors (0xca34 = 51764, draft-ietf-tls-trust-anchor-ids) —
        // the 17th ClientHello extension real Chrome 148 sends. We request an
        // EMPTY trust-anchor list: per BoringSSL's `SSL_set1_requested_trust_anchors`
        // an empty list still sends the extension (signals support for the
        // retry flow without requesting any specific anchor). We are imitating
        // the ClientHello shape, not participating in the retry flow, so we do
        // not invent trust anchor IDs. Closes the JA4 t13d1516h2 -> t13d1517h2
        // gap (issue #81). Requires the patched wreq fork (see workspace
        // Cargo.toml [patch.crates.io]).
        .requested_trust_anchors(Vec::<u8>::new())
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
/// presets). This gives us full control over TLS extensions — all 17 of
/// Chrome's, including `trust_anchors` (0xca34 = 51764) via the patched wreq
/// fork's `requested_trust_anchors` (issue #81), and ALPS codepoint 17613 —
/// plus HTTP/2 SETTINGS, and header wire order.
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
/// The `trust_anchors` gap (issue #81) is CLOSED: since `chrome_tls` now
/// sends the `trust_anchors` extension (0xca34 = 51764) via the patched wreq
/// fork's `requested_trust_anchors`, the ClientHello carries all 17 of
/// Chrome 148's extensions and `ja3n_hash`, `ja4`, and `peetprint_hash` all
/// match the reference. The oracle confirmed this live — it FAILED with
/// `GAP-CLOSED` on all three, which is the self-expiring signal that they
/// had to leave the bucket. The bucket is now empty.
///
/// The constant and the self-expiring machinery are kept on purpose: an
/// empty bucket is meaningful (it asserts "no known gap"), and the next
/// gap will need the mechanism. Do NOT delete [`FP_BUCKET_B`] or
/// [`classify_fingerprint_diffs`]'s gap-closed path.
pub const FP_BUCKET_B: &[&str] = &[];

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
/// `comparable_b` is the subset of [`FP_BUCKET_B`] fields with a non-empty
/// reference value — a match is only meaningful for those; a field with no
/// reference value is not "matching", it's absent. The observed side is
/// checked in [`classify_with`]: a bucket-B diff with an empty observed
/// value is a hard failure (the metric could not be measured), not a
/// tolerated gap — so a partial 200 missing one key cannot silently disable
/// self-expiry.
///
/// - A diff in bucket A → tolerated.
/// - A diff in bucket B → tolerated (gap still open).
/// - A bucket-B field in `comparable_b` with NO diff → `gap_closed` (FAIL).
/// - A diff outside both buckets → `hard_failures` (FAIL).
///
/// This is a thin wrapper over [`classify_with`] that passes the production
/// [`FP_BUCKET_A`] / [`FP_BUCKET_B`]. Unit tests should call [`classify_with`]
/// with literal buckets so the gap-closed path stays exercised regardless of
/// what the production consts happen to contain (see F7).
pub fn classify_fingerprint_diffs(
    diffs: &[(String, String, String)],
    comparable_b: &[&str],
) -> FingerprintVerdict {
    classify_with(FP_BUCKET_A, FP_BUCKET_B, diffs, comparable_b)
}

/// Parameterized classifier — the actual verdict logic, decoupled from the
/// production bucket consts. `classify_fingerprint_diffs` is a thin wrapper
/// over this.
///
/// A `source:<field>` diff (emitted by the oracle's cross-service consistency
/// check) means the field could NOT be reliably compared — a tooling
/// disagreement, not a fingerprint match. Such a diff must NOT let the
/// field be reported as `gap_closed` (a closed gap means "matched"); the
/// `source:` diff itself is a hard failure (it is in neither bucket). See F4.
pub fn classify_with(
    bucket_a: &[&str],
    bucket_b: &[&str],
    diffs: &[(String, String, String)],
    comparable_b: &[&str],
) -> FingerprintVerdict {
    let mut v = FingerprintVerdict::default();
    for d in diffs {
        if bucket_a.contains(&d.0.as_str()) {
            v.tolerated_a.push(d.0.clone());
        } else if bucket_b.contains(&d.0.as_str()) {
            // Fix C: a bucket-B diff with an empty observed value means the
            // metric could not be measured — a partial 200 from an echo
            // service that is missing one key (e.g. browserleaks returns
            // 200 but `ja3n_hash` is absent from the JSON, so
            // `extract_browserleaks` sets it to ""). "We could not measure
            // it" is a hard failure, not "the known gap is still open" —
            // otherwise a missing key silently disables self-expiry while
            // the oracle reports green. The self-expiry can never fire on
            // an empty observed value because it never matches the
            // reference; the diff must not be tolerated either.
            //
            // Reachability: `ja4` has a non-empty assert in
            // `capture_with_client` that panics before `compare()` is
            // reached, so this guard is never hit for `ja4` on the live
            // path. The genuinely reachable inputs are `ja3n_hash` and
            // `peetprint_hash` — neither has an emptiness assert in
            // `capture_with_client`, so a partial 200 missing one of them
            // flows through to this guard. Adding symmetric asserts there
            // would make this guard unreachable on the live path for ALL
            // bucket-B fields, reducing it to a test-only safety net; the
            // current design keeps it as the only live defence for those
            // fields.
            if d.2.is_empty() {
                v.hard_failures.push(d.clone());
            } else {
                v.tolerated_b.push(d.0.clone());
            }
        } else {
            v.hard_failures.push(d.clone());
        }
    }
    // Self-expiring: any comparable bucket-B field that did NOT diff has
    // matched the reference — the gap closed, it must leave the list.
    // Collect the metric names that had a `source:` disagreement so they
    // can be excluded from gap_closed (F4): a source:<field> diff means the
    // field was not comparable, not that it matched.
    let source_disputed: Vec<&str> = diffs
        .iter()
        .filter_map(|d| d.0.strip_prefix("source:"))
        .collect();
    for field in comparable_b {
        if !bucket_b.contains(field) {
            continue;
        }
        if source_disputed.contains(field) {
            continue;
        }
        if !diffs.iter().any(|d| &d.0 == field) {
            v.gap_closed.push((*field).to_string());
        }
    }
    v
}

/// F3: does the reference's own ClientHello exhibit the `trust_anchors` gap?
///
/// A bucket-B field is only comparable if the reference EXHIBITS the gap —
/// i.e. the reference's own ClientHello sends extension `51764`
/// (`trust_anchors`, 0xca34 = draft-ietf-tls-trust-anchor-ids). References
/// captured from Chrome versions that do NOT send it (e.g. Chrome 131/133 —
/// 16 extensions, no 51764) have a correct 16-extension ClientHello by
/// construction; for those, a match is CORRECT and must NOT be reported as a
/// closed gap, or the operator would be told to delete suppression entries
/// in response to a correct result (which would then break Chrome 148).
///
/// The reference's JA3 string carries the full extension list as its third
/// `-`-joined component
/// (`<TLSVersion>,<Ciphers>,<Extensions>,<EllipticCurves>,<ECPointFormats>`).
/// Returns `false` if the JA3 string is absent or unparseable — never assume
/// the gap is exhibited.
pub fn reference_exhibits_gap(ja3: &str) -> bool {
    let parts: Vec<&str> = ja3.split(',').collect();
    if parts.len() < 3 || parts[2].is_empty() {
        return false;
    }
    parts[2].split('-').any(|e| e == "51764")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(field: &str, exp: &str, obs: &str) -> (String, String, String) {
        (field.to_string(), exp.to_string(), obs.to_string())
    }

    // Literal buckets decoupled from the production consts (F7): the
    // gap-closed path must stay exercised regardless of what FP_BUCKET_A /
    // FP_BUCKET_B happen to contain. If FP_BUCKET_B becomes empty (the
    // follow-up PR that closes the trust_anchors gap), tests that read the
    // consts directly would silently stop exercising the mechanism.
    const TEST_A: &[&str] = &["ja3_hash", "ja4_o"];
    const TEST_B: &[&str] = &["ja3n_hash", "ja4", "peetprint_hash"];

    // Case 1: a diff in bucket A is tolerated.
    #[test]
    fn bucket_a_diff_is_tolerated() {
        let v = classify_with(TEST_A, TEST_B, &[d("ja3_hash", "a", "b")], &[]);
        assert!(v.is_ok());
        assert_eq!(v.tolerated_a, vec!["ja3_hash"]);
        assert!(v.tolerated_b.is_empty());
        assert!(v.gap_closed.is_empty());
        assert!(v.hard_failures.is_empty());
    }

    // Case 2: a diff in bucket B is tolerated (gap still open).
    #[test]
    fn bucket_b_diff_is_tolerated() {
        let v = classify_with(
            TEST_A,
            TEST_B,
            &[d("ja4", "t13d1517h2", "t13d1516h2")],
            &["ja4"],
        );
        assert!(v.is_ok());
        assert_eq!(v.tolerated_b, vec!["ja4"]);
        assert!(v.gap_closed.is_empty());
        assert!(v.hard_failures.is_empty());
    }

    // Case 2b: the trust_anchors gap (issue #81) is CLOSED in production —
    // `chrome_tls` now sends extension 51764, so `ja4` matches the reference
    // and has been removed from FP_BUCKET_B (now empty). A `ja4` diff via the
    // real production wrapper is therefore no longer tolerated; it is a hard
    // failure. The oracle confirmed the close live (GAP-CLOSED on ja3n_hash,
    // ja4, peetprint_hash). `bucket_b_diff_is_tolerated` above deliberately
    // stays on literal buckets (F7) so that mechanism keeps being exercised
    // even though the production bucket is now empty — this test covers the
    // production wiring itself, which the literal-bucket test cannot.
    #[test]
    fn closed_gap_field_diff_is_now_hard_fail() {
        let v = classify_fingerprint_diffs(&[d("ja4", "t13d1517h2", "t13d1516h2")], &["ja4"]);
        assert!(
            !v.is_ok(),
            "ja4 is no longer in bucket B — a diff must fail"
        );
        assert!(v.tolerated_b.is_empty());
        assert!(v.gap_closed.is_empty());
        assert_eq!(v.hard_failures.len(), 1);
        assert_eq!(v.hard_failures[0].0, "ja4");
    }

    // Case 3 (falsification): a comparable bucket-B field that MATCHED (no
    // diff) means the trust_anchors gap has closed → must FAIL. This is the
    // case that was silently green under the old single-bucket partition and
    // is now RED-on-match.
    #[test]
    fn bucket_b_match_signals_gap_closed() {
        let v = classify_with(TEST_A, TEST_B, &[], &["ja4"]);
        assert!(!v.is_ok(), "a closed gap must not be tolerated");
        assert_eq!(v.gap_closed, vec!["ja4"]);
        assert!(v.hard_failures.is_empty());
    }

    // Case 3b: with production FP_BUCKET_B empty (gap closed), a matching
    // `ja4` does NOT trip gap_closed via the real wrapper — the field is no
    // longer tracked, so the self-expiring machinery correctly stays dormant.
    // The gap-closed path itself is retained in `classify_fingerprint_diffs`
    // for the next gap; it was proven to fire by the live oracle run
    // (GAP-CLOSED on all three fields before the bucket was emptied).
    #[test]
    fn empty_bucket_match_does_not_trip_gap_closed() {
        let v = classify_fingerprint_diffs(&[], &["ja4"]);
        assert!(v.is_ok(), "empty bucket → no gap-closed signal");
        assert!(v.gap_closed.is_empty());
        assert!(v.hard_failures.is_empty());
    }

    // Case 4: a diff outside both buckets is a hard failure.
    #[test]
    fn diff_outside_buckets_is_hard_fail() {
        let v = classify_with(TEST_A, TEST_B, &[d("http2_akamai", "x", "y")], &[]);
        assert!(!v.is_ok());
        assert_eq!(v.hard_failures.len(), 1);
        assert_eq!(v.hard_failures[0].0, "http2_akamai");
        assert!(v.gap_closed.is_empty());
    }

    // Bucket A is NOT self-expiring: a comparable-A field that matched must
    // NOT trip gap_closed (coincidental matches carry no signal).
    #[test]
    fn bucket_a_match_does_not_trip_gap_closed() {
        let v = classify_with(TEST_A, TEST_B, &[], &["ja3_hash"]);
        assert!(v.is_ok(), "bucket A has no gap-closed semantics");
        assert!(v.gap_closed.is_empty());
    }

    // F4: a `source:<field>` diff must NOT let a bucket-B field be reported
    // as gap_closed. The field could not be reliably compared (cross-service
    // tooling disagreement); the source: diff is itself a hard failure.
    #[test]
    fn source_prefix_diff_does_not_close_gap() {
        let v = classify_with(
            TEST_A,
            TEST_B,
            &[d(
                "source:ja4",
                "reference source=browserleaks",
                "observed source=peet",
            )],
            &["ja4"],
        );
        // ja4 must NOT appear in gap_closed — the source:ja4 diff means it
        // was not comparable, not that it matched.
        assert!(
            v.gap_closed.is_empty(),
            "source: diff must not close the gap"
        );
        // The source:ja4 diff is a hard failure (in neither bucket).
        assert_eq!(v.hard_failures.len(), 1);
        assert_eq!(v.hard_failures[0].0, "source:ja4");
        assert!(!v.is_ok());
    }

    // F6: bucket A and bucket B are disjoint — a field present in both would
    // be silently classified permanent (bucket A wins) and could never
    // expire. They are disjoint today; this pins it.
    #[test]
    fn bucket_a_and_b_are_disjoint() {
        assert!(
            FP_BUCKET_A.iter().all(|a| !FP_BUCKET_B.contains(a)),
            "FP_BUCKET_A and FP_BUCKET_B must be disjoint — a field in both \
             is silently permanent and can never expire"
        );
    }

    // F7: the public wrapper must agree with classify_with on the production
    // buckets — this keeps the production wiring itself covered.
    #[test]
    fn public_wrapper_matches_classify_with_production_buckets() {
        let diffs = &[d("ja4", "t13d1517h2", "t13d1516h2")];
        let via_wrapper = classify_fingerprint_diffs(diffs, &["ja4"]);
        let via_inner = classify_with(FP_BUCKET_A, FP_BUCKET_B, diffs, &["ja4"]);
        assert_eq!(via_wrapper.tolerated_a, via_inner.tolerated_a);
        assert_eq!(via_wrapper.tolerated_b, via_inner.tolerated_b);
        assert_eq!(via_wrapper.gap_closed, via_inner.gap_closed);
        assert_eq!(via_wrapper.hard_failures, via_inner.hard_failures);
    }

    // F3: a reference whose ClientHello sends extension 51764 (trust_anchors)
    // exhibits the gap — bucket-B fields ARE comparable for it. Chrome 148,
    // 144, 146 all send 51764 (17 extensions).
    #[test]
    fn reference_exhibits_gap_chrome148_true() {
        let ja3 = "771,4865-4866-4867-49195,10-0-23-65281-65037-45-27-11-51764-43-35-5-18-17613-13-16-51,4588-29-23-24,0";
        assert!(reference_exhibits_gap(ja3));
    }

    // F3: a reference whose ClientHello does NOT send 51764 does NOT exhibit
    // the gap — bucket-B fields are NOT comparable (a match is correct, not a
    // closed gap). Chrome 131/133 send 16 extensions, no 51764.
    #[test]
    fn reference_exhibits_gap_chrome131_false() {
        let ja3 = "771,4865-4866-4867-49195,18-45-16-11-51-13-65281-17613-0-23-5-27-35-43-65037-10,4588-29-23-24,0";
        assert!(!reference_exhibits_gap(ja3));
    }

    // F3: an absent or unparseable JA3 string must NOT be assumed to exhibit
    // the gap — return false so the field is treated as not comparable.
    #[test]
    fn reference_exhibits_gap_empty_ja3_false() {
        assert!(!reference_exhibits_gap(""));
    }

    #[test]
    fn reference_exhibits_gap_malformed_ja3_false() {
        // Only two components — no extension list to inspect.
        assert!(!reference_exhibits_gap("771,4865-4866"));
    }

    #[test]
    fn reference_exhibits_gap_empty_extension_list_false() {
        // Third component present but empty.
        assert!(!reference_exhibits_gap("771,4865-4866,,4588-29-23-24,0"));
    }
}
