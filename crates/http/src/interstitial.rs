//! Vendor-neutral classification of interstitial and access-denied responses.
//!
//! [`classify`] inspects one HTTP response and returns a typed
//! [`Interstitial`] verdict: which edge or WAF vendor produced it, what kind
//! of page it is (challenge / block / rate-limit) and how sure we are
//! (high / medium / low).
//!
//! Signals, in decreasing strength:
//!
//! 1. Body markers that only a vendor's interstitial carries (a challenge
//!    host, an incident-id line, a captcha script). Counted only on small
//!    bodies — a full article that embeds a vendor tag is not an interstitial.
//! 2. Vendor-specific response headers or cookie names *combined with* a
//!    blocking status. A vendor header on a plain 200 only says the site uses
//!    that vendor, not that this response is a challenge.
//! 3. A bare 403 / 429 with no vendor attribution (generic, low confidence).
//!
//! Cloudflare keeps its original detector ([`crate::cloudflare::detect_cloudflare`])
//! unchanged; this module delegates to it so that behaviour stays identical.
//!
//! The signal catalogue was assembled from public vendor documentation and
//! from live responses; Crawl4AI's response detector (Apache-2.0) was read
//! to see which signal classes exist. No code was taken from it.

use crate::HttpResponse;
use crate::cloudflare::{ChallengeType, detect_cloudflare};

/// Bodies larger than this are never treated as an interstitial on body
/// markers alone: challenge and block pages are small, real pages are not.
const MAX_MARKER_BODY: usize = 128 * 1024;

/// An interstitial served with a non-blocking status (200, 202) is a stub:
/// at most this many bytes of markup and this many visible characters.
const STUB_MAX_BYTES: usize = 16 * 1024;
const STUB_MAX_VISIBLE_CHARS: usize = 400;

/// How much of a body is scanned for markers.
const SCAN_LIMIT: usize = 128 * 1024;

/// Edge / WAF vendor behind an interstitial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Vendor {
    Cloudflare,
    DataDome,
    Akamai,
    PerimeterX,
    Imperva,
    Kasada,
    AwsWaf,
    /// No vendor attribution — a bare 403 / 429.
    Generic,
}

impl Vendor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::DataDome => "datadome",
            Self::Akamai => "akamai",
            Self::PerimeterX => "perimeterx",
            Self::Imperva => "imperva",
            Self::Kasada => "kasada",
            Self::AwsWaf => "aws_waf",
            Self::Generic => "generic",
        }
    }
}

/// What the page asks of the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A script or captcha the client is expected to complete.
    Challenge,
    /// A flat refusal ("access denied").
    Block,
    /// Too many requests.
    RateLimit,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Block => "block",
            Self::RateLimit => "rate_limit",
        }
    }
}

/// Confidence tier. Ordered: `Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Typed verdict for one interstitial response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interstitial {
    pub vendor: Vendor,
    pub kind: Kind,
    pub confidence: Confidence,
    /// Short name of the strongest signal that decided the verdict.
    pub signal: &'static str,
    /// Cloudflare ray id (empty for every other vendor).
    pub ray_id: String,
    /// The Cloudflare sub-type, set only when `vendor == Cloudflare`.
    pub cloudflare: Option<ChallengeType>,
}

impl Interstitial {
    fn new(vendor: Vendor, kind: Kind, confidence: Confidence, signal: &'static str) -> Self {
        Self {
            vendor,
            kind,
            confidence,
            signal,
            ray_id: String::new(),
            cloudflare: None,
        }
    }

    /// Whether the middleware chain should escalate this response to the
    /// solver tier instead of returning it as content. Low-confidence generic
    /// verdicts are reported but are not themselves an escalation reason —
    /// the existing status-based inference already handles bare 401/403/429/503.
    pub fn should_escalate(&self) -> bool {
        self.confidence >= Confidence::Medium
    }

    /// Compact `vendor:kind:confidence` form for logs and quality reasons.
    pub fn label(&self) -> String {
        format!(
            "{}:{}:{}",
            self.vendor.as_str(),
            self.kind.as_str(),
            self.confidence.as_str()
        )
    }
}

/// Everything the vendor rules look at, computed once per response.
struct Signals<'a> {
    status: u16,
    resp: &'a HttpResponse,
    server: String,
    /// Lowercased cookie names from every `Set-Cookie`.
    cookies: Vec<String>,
    /// Lowercased body prefix (≤ `SCAN_LIMIT`), entity-decoded when small.
    body: String,
    /// The body is small enough for marker-only decisions.
    small: bool,
    /// The body has the shape of an interstitial stub: tiny markup, almost
    /// no visible text.
    stub: bool,
}

impl<'a> Signals<'a> {
    fn new(resp: &'a HttpResponse) -> Self {
        let server = resp
            .headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let cookies = resp
            .headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|c| c.split('=').next())
            .map(|n| n.trim().to_ascii_lowercase())
            .collect();
        let small = resp.body.len() <= MAX_MARKER_BODY;
        let mut end = resp.body.len().min(SCAN_LIMIT);
        while !resp.body.is_char_boundary(end) {
            end -= 1;
        }
        let mut body = resp.body[..end].to_ascii_lowercase();
        if small && body.contains("&#") {
            body = decode_numeric_ascii_entities(&body);
        }
        let stub = resp.body.len() <= STUB_MAX_BYTES
            && crate::content_detect::visible_text_len(&resp.body) <= STUB_MAX_VISIBLE_CHARS;
        Self {
            status: resp.status,
            stub,
            resp,
            server,
            cookies,
            body,
            small,
        }
    }

    fn has_header(&self, name: &str) -> bool {
        self.resp.headers.contains_key(name)
    }

    fn header_lower(&self, name: &str) -> String {
        self.resp
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase()
    }

    fn has_cookie(&self, prefix: &str) -> bool {
        self.cookies.iter().any(|c| c.starts_with(prefix))
    }

    fn body_has(&self, marker: &str) -> bool {
        self.body.contains(marker)
    }

    /// Statuses a vendor uses for a refusal or challenge page.
    fn blocking_status(&self) -> bool {
        matches!(self.status, 401 | 403 | 405 | 429 | 503)
    }

    /// Whether `signals` independent pieces of evidence justify a verdict.
    ///
    /// With a blocking status the evidence only has to attribute the vendor.
    /// Without one (200, 202) the page must ALSO have the shape of a stub and
    /// carry at least two independent signals: a single marker or header on
    /// an ordinary page only says the site embeds the vendor's tag.
    fn gated(&self, signals: usize) -> bool {
        self.blocking_status() || (self.stub && signals >= 2)
    }

    fn kind_for_status(&self, default: Kind) -> Kind {
        if self.status == 429 {
            Kind::RateLimit
        } else {
            default
        }
    }
}

/// Replace `&#NN;` (decimal, ASCII range) with the character. Block pages of
/// one vendor encode every punctuation mark this way.
fn decode_numeric_ascii_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("&#") {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos + 2..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        let consumed = digits.len();
        let decoded = (consumed > 0 && consumed <= 3 && tail[consumed..].starts_with(';'))
            .then(|| digits.parse::<u8>().ok().filter(u8::is_ascii))
            .flatten();
        match decoded {
            Some(b) => {
                out.push(b as char);
                rest = &tail[consumed + 1..];
            }
            None => {
                out.push_str("&#");
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Classify a response as an interstitial. `None` means "ordinary response".
pub fn classify(resp: &HttpResponse) -> Option<Interstitial> {
    // Cloudflare first, through its unchanged detector.
    if let Some(cf) = detect_cloudflare(resp) {
        let kind = if cf.challenge_type == ChallengeType::Block {
            Kind::Block
        } else {
            Kind::Challenge
        };
        let mut v = Interstitial::new(Vendor::Cloudflare, kind, Confidence::High, "cloudflare");
        v.ray_id = cf.ray_id;
        v.cloudflare = Some(cf.challenge_type);
        return Some(v);
    }
    if let Some(v) = cloudflare_edge_challenge(resp) {
        return Some(v);
    }
    classify_other(resp)
}

/// Cloudflare challenge pages the legacy detector does not report: a managed
/// challenge served with HTTP 403 carries `cf-mitigated: challenge`, but the
/// legacy rules need a body marker (and the interstitial title is accepted as well). The `challenge-platform` beacon alone is
/// not used: Cloudflare injects it into ordinary pages too. Kept out of `detect_cloudflare` so its behaviour stays unchanged;
/// the solver escalation for these responses is the existing 403 inference.
fn cloudflare_edge_challenge(resp: &HttpResponse) -> Option<Interstitial> {
    let server = resp
        .headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !server.to_ascii_lowercase().contains("cloudflare") {
        return None;
    }
    let mitigated = resp
        .headers
        .get("cf-mitigated")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("challenge"));
    // The interstitial's own title; an ordinary page does not carry it.
    let titled = resp.body.len() <= MAX_MARKER_BODY
        && resp
            .body
            .to_ascii_lowercase()
            .contains("<title>just a moment...</title>");
    if !(mitigated || titled) {
        return None;
    }
    let signal = if mitigated {
        "cf-mitigated"
    } else {
        "challenge_title"
    };
    let mut v = Interstitial::new(
        Vendor::Cloudflare,
        Kind::Challenge,
        Confidence::High,
        signal,
    );
    v.ray_id = resp
        .headers
        .get("cf-ray")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_owned();
    v.cloudflare = Some(ChallengeType::ManagedChallenge);
    Some(v)
}

/// Classify while skipping Cloudflare. Used by call sites that already ran
/// `detect_cloudflare` and need provenance to stay distinct: a genuine CF
/// challenge raises `HttpError::Cloudflare`; everything here is inferred.
pub fn classify_non_cloudflare(resp: &HttpResponse) -> Option<Interstitial> {
    classify_other(resp)
}

fn classify_other(resp: &HttpResponse) -> Option<Interstitial> {
    let s = Signals::new(resp);
    let best = [
        datadome(&s),
        perimeterx(&s),
        kasada(&s),
        akamai(&s),
        imperva(&s),
        aws_waf(&s),
    ]
    .into_iter()
    .flatten()
    // `max_by_key` keeps the LAST maximum; reverse so the earlier rule wins ties.
    .rev()
    .max_by_key(|v| v.confidence);
    if best.is_some() {
        return best;
    }
    generic(&s)
}

fn datadome(s: &Signals) -> Option<Interstitial> {
    let header = s.has_header("x-datadome") || s.has_header("x-dd-b") || s.server == "datadome";
    let host = s.small && s.body_has("captcha-delivery.com");
    let config = s.small && s.body_has("var dd={");
    if host && s.gated(1 + usize::from(config) + usize::from(header)) {
        return Some(Interstitial::new(
            Vendor::DataDome,
            s.kind_for_status(Kind::Challenge),
            Confidence::High,
            "captcha_host",
        ));
    }
    if header && matches!(s.status, 401 | 403 | 429) {
        return Some(Interstitial::new(
            Vendor::DataDome,
            s.kind_for_status(Kind::Block),
            Confidence::Medium,
            "header+status",
        ));
    }
    None
}

fn perimeterx(s: &Signals) -> Option<Interstitial> {
    let header = s.header_lower("x-px-blocked") == "1";
    let markers = [
        "px-captcha",
        "pxcaptchasrc",
        "captcha.px-cdn.net",
        "captcha.px-cloud.net",
    ]
    .iter()
    .filter(|m| s.small && s.body_has(m))
    .count();
    if (header || markers > 0) && s.gated(usize::from(header) + markers) {
        return Some(Interstitial::new(
            Vendor::PerimeterX,
            s.kind_for_status(Kind::Challenge),
            Confidence::High,
            if header {
                "x-px-blocked"
            } else {
                "captcha_marker"
            },
        ));
    }
    if (s.has_cookie("_px") || s.has_header("x-px-blocked")) && matches!(s.status, 403 | 429) {
        return Some(Interstitial::new(
            Vendor::PerimeterX,
            s.kind_for_status(Kind::Block),
            Confidence::Medium,
            "cookie+status",
        ));
    }
    None
}

fn kasada(s: &Signals) -> Option<Interstitial> {
    if s.small && (s.body_has("kpsdk.now") || s.body_has("/ips.js")) && s.blocking_status() {
        return Some(Interstitial::new(
            Vendor::Kasada,
            s.kind_for_status(Kind::Challenge),
            Confidence::High,
            "kpsdk_script",
        ));
    }
    let header = s.has_header("x-kpsdk-ct") || s.has_header("x-kpsdk-r");
    if header && matches!(s.status, 403 | 429) {
        return Some(Interstitial::new(
            Vendor::Kasada,
            s.kind_for_status(Kind::Challenge),
            Confidence::Medium,
            "header+status",
        ));
    }
    None
}

fn akamai(s: &Signals) -> Option<Interstitial> {
    let akamai_server =
        s.server.contains("akamaighost") || s.server.contains("akamainetworkstorage");
    let error_host =
        s.small && (s.body_has("errors.edgesuite.net") || s.body_has("errors.akamai.com"));
    let denied_text =
        s.small && s.body_has("access denied") && s.body_has("don't have permission to access");
    if error_host && s.gated(1 + usize::from(denied_text) + usize::from(akamai_server)) {
        return Some(Interstitial::new(
            Vendor::Akamai,
            s.kind_for_status(Kind::Block),
            Confidence::High,
            "error_reference",
        ));
    }
    // The stock denial page is served by an Akamai edge even at HTTP 200.
    if akamai_server && denied_text && s.gated(3) {
        return Some(Interstitial::new(
            Vendor::Akamai,
            s.kind_for_status(Kind::Block),
            Confidence::High,
            "access_denied_page",
        ));
    }
    // Bot-manager interstitial script endpoints.
    let sensor = ["/_sec/cp_challenge/", "/_sec/verify?provider=", "bm-verify"]
        .iter()
        .filter(|m| s.small && s.body_has(m))
        .count();
    if sensor > 0
        && s.gated(sensor + usize::from(akamai_server) + usize::from(s.has_cookie("ak_bmsc")))
    {
        return Some(Interstitial::new(
            Vendor::Akamai,
            Kind::Challenge,
            Confidence::High,
            "bot_manager_interstitial",
        ));
    }
    if (akamai_server || s.header_lower("x-cdn") == "akamai") && s.status == 403 {
        return Some(Interstitial::new(
            Vendor::Akamai,
            Kind::Block,
            Confidence::Medium,
            "server+status",
        ));
    }
    None
}

fn imperva(s: &Signals) -> Option<Interstitial> {
    let edge = s.header_lower("x-cdn") == "imperva"
        || s.has_header("x-iinfo")
        || s.has_cookie("incap_ses_")
        || s.has_cookie("visid_incap_");
    let incident = s.small && s.body_has("incapsula incident id");
    // The resource endpoint is also embedded in ordinary protected pages, so
    // it only counts when the whole body is a stub.
    let resource = s.resp.body.len() <= 2048 && s.body_has("_incapsula_resource");
    if incident && s.gated(1 + usize::from(resource) + usize::from(edge)) {
        return Some(Interstitial::new(
            Vendor::Imperva,
            s.kind_for_status(Kind::Block),
            Confidence::High,
            "incident_id",
        ));
    }
    if resource && s.gated(1 + usize::from(edge)) {
        return Some(Interstitial::new(
            Vendor::Imperva,
            s.kind_for_status(Kind::Challenge),
            Confidence::Medium,
            "resource_stub",
        ));
    }
    if edge && matches!(s.status, 403 | 429) {
        return Some(Interstitial::new(
            Vendor::Imperva,
            s.kind_for_status(Kind::Block),
            Confidence::Medium,
            "header+status",
        ));
    }
    None
}

fn aws_waf(s: &Signals) -> Option<Interstitial> {
    let action = s.header_lower("x-amzn-waf-action");
    let header = action == "challenge" || action == "captcha";
    // The SDK script is embedded in ordinary pages that use the captcha
    // integration; it only counts on a stub.
    let integration = s.small && s.body_has("awswafintegration");
    let script = s.small && s.body_has("challenge.js");
    // 202 is the vendor's challenge status, so it is not a blocking one for
    // `gated`; it still has to be a stub with two signals.
    let signals = usize::from(header) + usize::from(integration) + usize::from(script);
    if (header || integration) && s.gated(signals) {
        return Some(Interstitial::new(
            Vendor::AwsWaf,
            s.kind_for_status(Kind::Challenge),
            Confidence::High,
            if header {
                "waf_action_header"
            } else {
                "sdk_stub"
            },
        ));
    }
    None
}

/// Bare 403 / 429 with no vendor attribution.
fn generic(s: &Signals) -> Option<Interstitial> {
    match s.status {
        403 => Some(Interstitial::new(
            Vendor::Generic,
            Kind::Block,
            Confidence::Low,
            "status_403",
        )),
        429 => Some(Interstitial::new(
            Vendor::Generic,
            Kind::RateLimit,
            Confidence::Low,
            "status_429",
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wreq::header::HeaderMap;

    fn resp(status: u16, body: &str, headers: &[(&str, &str)]) -> HttpResponse {
        let mut hm = HeaderMap::new();
        for (k, v) in headers {
            hm.append(
                wreq::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        HttpResponse {
            status,
            url: "https://example.test/".into(),
            headers: hm,
            body: body.to_owned(),
        }
    }

    #[test]
    fn entity_decoder_handles_ascii_only() {
        assert_eq!(decode_numeric_ascii_entities("a&#46;b&#47;"), "a.b/");
        // non-ASCII, unterminated and oversized sequences stay literal
        assert_eq!(decode_numeric_ascii_entities("&#955;"), "&#955;");
        assert_eq!(decode_numeric_ascii_entities("x&#46"), "x&#46");
        assert_eq!(decode_numeric_ascii_entities("&#;"), "&#;");
    }

    #[test]
    fn cloudflare_verdict_mirrors_detector() {
        let r = resp(
            503,
            "<script src=\"/cdn-cgi/challenge-platform/x.js\"></script>",
            &[("server", "cloudflare"), ("cf-ray", "abc-LAX")],
        );
        let v = classify(&r).unwrap();
        assert_eq!(v.vendor, Vendor::Cloudflare);
        assert_eq!(v.kind, Kind::Challenge);
        assert_eq!(v.confidence, Confidence::High);
        assert_eq!(v.ray_id, "abc-LAX");
        assert_eq!(v.cloudflare, Some(ChallengeType::JsChallenge));
        let b = resp(403, "you have been blocked", &[("server", "cloudflare")]);
        assert_eq!(classify(&b).unwrap().kind, Kind::Block);
    }

    #[test]
    fn non_cloudflare_entry_skips_cloudflare_rules() {
        let r = resp(
            503,
            "<script src=\"/cdn-cgi/challenge-platform/x.js\"></script>",
            &[("server", "cloudflare")],
        );
        assert!(
            classify_non_cloudflare(&r).is_none(),
            "503 is not a generic status"
        );
        let r403 = resp(403, "x", &[("server", "cloudflare")]);
        assert_eq!(
            classify_non_cloudflare(&r403).unwrap().vendor,
            Vendor::Generic
        );
    }

    #[test]
    fn plain_200_is_none() {
        assert!(classify(&resp(200, "<html>hello</html>", &[])).is_none());
    }

    #[test]
    fn bare_403_and_429_are_generic_low() {
        let v = classify(&resp(403, "nope", &[])).unwrap();
        assert_eq!(
            (v.vendor, v.kind, v.confidence),
            (Vendor::Generic, Kind::Block, Confidence::Low)
        );
        let v = classify(&resp(429, "slow down", &[])).unwrap();
        assert_eq!((v.vendor, v.kind), (Vendor::Generic, Kind::RateLimit));
        assert!(!v.should_escalate());
    }

    #[test]
    fn datadome_captcha_host_at_200() {
        // stub shape + captcha host + config object: two signals
        let stub = "<script>var dd={'host':'geo.captcha-delivery.com'}</script><script src=\"https://ct.captcha-delivery.com/c.js\"></script>";
        let v = classify(&resp(200, stub, &[])).unwrap();
        assert_eq!(
            (v.vendor, v.confidence),
            (Vendor::DataDome, Confidence::High)
        );
        // the same single marker on a 200 is not enough
        let one = "<script src=\"https://ct.captcha-delivery.com/c.js\"></script>";
        assert!(classify(&resp(200, one, &[])).is_none());
        // at a blocking status one marker attributes the vendor
        assert_eq!(
            classify(&resp(403, one, &[])).unwrap().vendor,
            Vendor::DataDome
        );
    }

    #[test]
    fn datadome_header_needs_blocking_status() {
        let h = [("x-datadome", "protected")];
        assert!(classify(&resp(200, "<html>fine</html>", &h)).is_none());
        let v = classify(&resp(403, "x", &h)).unwrap();
        assert_eq!(
            (v.vendor, v.confidence),
            (Vendor::DataDome, Confidence::Medium)
        );
        let v = classify(&resp(429, "x", &h)).unwrap();
        assert_eq!(v.kind, Kind::RateLimit);
    }

    #[test]
    fn large_body_with_marker_is_not_an_interstitial() {
        let body = format!("captcha-delivery.com{}", "x".repeat(MAX_MARKER_BODY + 10));
        assert!(classify(&resp(200, &body, &[])).is_none());
    }

    #[test]
    fn marker_beyond_scan_limit_on_multibyte_boundary_does_not_panic() {
        let body = "я".repeat(SCAN_LIMIT);
        assert!(classify(&resp(200, &body, &[])).is_none());
    }

    #[test]
    fn perimeterx_header_and_captcha_marker() {
        let v = classify(&resp(403, "x", &[("x-px-blocked", "1")])).unwrap();
        assert_eq!(
            (v.vendor, v.confidence),
            (Vendor::PerimeterX, Confidence::High)
        );
        // at 200: header + captcha marker on a stub, not either alone
        let stub = "<meta name=\"description\" content=\"px-captcha\">";
        assert!(classify(&resp(200, stub, &[])).is_none());
        assert!(classify(&resp(200, "x", &[("x-px-blocked", "1")])).is_none());
        let v = classify(&resp(200, stub, &[("x-px-blocked", "1")])).unwrap();
        assert_eq!(v.vendor, Vendor::PerimeterX);
        let v = classify(&resp(403, "x", &[("set-cookie", "_pxhd=abc; Path=/")])).unwrap();
        assert_eq!(
            (v.vendor, v.confidence),
            (Vendor::PerimeterX, Confidence::Medium)
        );
        assert!(classify(&resp(200, "ok", &[("set-cookie", "_pxhd=abc; Path=/")])).is_none());
    }

    #[test]
    fn kasada_script_and_header() {
        let v = classify(&resp(429, "window.KPSDK={};KPSDK.now=1;", &[])).unwrap();
        assert_eq!((v.vendor, v.confidence), (Vendor::Kasada, Confidence::High));
        let v = classify(&resp(429, "x", &[("x-kpsdk-ct", "t")])).unwrap();
        assert_eq!(
            (v.vendor, v.confidence, v.kind),
            (Vendor::Kasada, Confidence::Medium, Kind::RateLimit)
        );
        assert!(classify(&resp(200, "x", &[("x-kpsdk-ct", "t")])).is_none());
    }

    #[test]
    fn akamai_denial_page_even_at_200() {
        let body = "<html><title>Access Denied</title><h1>Access Denied</h1>You don't have permission to access \"/\" on this server.</html>";
        let v = classify(&resp(200, body, &[("server", "AkamaiGHost")])).unwrap();
        assert_eq!(
            (v.vendor, v.kind, v.confidence),
            (Vendor::Akamai, Kind::Block, Confidence::High)
        );
        // the same text from an unknown server is not attributed to Akamai
        assert!(classify(&resp(200, body, &[("server", "nginx")])).is_none());
    }

    #[test]
    fn akamai_entity_encoded_error_reference() {
        let body = "https&#58;&#47;&#47;errors&#46;edgesuite&#46;net&#47;18&#46;1";
        let v = classify(&resp(403, body, &[])).unwrap();
        assert_eq!((v.vendor, v.signal), (Vendor::Akamai, "error_reference"));
    }

    #[test]
    fn imperva_incident_stub_and_embedded_resource() {
        let stub = "<iframe src=\"/_Incapsula_Resource?CWUDNSAI=24\">Request unsuccessful. Incapsula incident ID: 1-2</iframe>";
        let v = classify(&resp(200, stub, &[])).unwrap();
        assert_eq!(
            (v.vendor, v.confidence),
            (Vendor::Imperva, Confidence::High)
        );
        // the incident line alone, or the resource alone, on a 200 is not enough
        assert!(
            classify(&resp(
                200,
                "Request unsuccessful. Incapsula incident ID: 1-2",
                &[]
            ))
            .is_none()
        );
        let res = "<iframe src=\"/_Incapsula_Resource?CWUDNSAI=24\"></iframe>";
        assert!(classify(&resp(200, res, &[])).is_none());
        // resource stub plus the vendor edge header: medium
        let v = classify(&resp(200, res, &[("x-iinfo", "1-2")])).unwrap();
        assert_eq!(v.confidence, Confidence::Medium);
        // the same endpoint inside a big page is just the vendor's sensor tag
        let page = format!(
            "<script src=\"/_Incapsula_Resource?SWJIYLWA=1\"></script>{}",
            "word ".repeat(2000)
        );
        assert!(classify(&resp(200, &page, &[("x-iinfo", "1-2")])).is_none());
    }

    #[test]
    fn aws_waf_header_and_stub() {
        let stub = "<script src=\"https://abc.edge.sdk.awswaf.com/abc/challenge.js\"></script><script>AwsWafIntegration.saveReferrer()</script>";
        let v = classify(&resp(202, stub, &[])).unwrap();
        assert_eq!((v.vendor, v.confidence), (Vendor::AwsWaf, Confidence::High));
        // header on a stub with one more signal
        let v = classify(&resp(
            202,
            "<script>AwsWafIntegration.x()</script>",
            &[("x-amzn-waf-action", "challenge")],
        ))
        .unwrap();
        assert_eq!(v.vendor, Vendor::AwsWaf);
        // a lone header, or a lone SDK reference, on a 200/202 is not enough
        let h = [("x-amzn-waf-action", "challenge")];
        assert!(classify(&resp(200, "<html>fine</html>", &h)).is_none());
        assert!(classify(&resp(202, "x", &h)).is_none());
        assert!(classify(&resp(200, "<script>AwsWafIntegration.x()</script>", &[])).is_none());
        // at a blocking status the header attributes the vendor
        assert_eq!(
            classify(&resp(403, "x", &h)).unwrap().vendor,
            Vendor::AwsWaf
        );
    }

    /// A healthy page that merely embeds a vendor's tag must stay unclassified,
    /// whatever markers its markup carries: it is too big and too full of text
    /// to be a stub, so no combination of signals can turn it into a verdict.
    #[test]
    fn large_page_embedding_each_vendor_tag_is_unclassified() {
        let article = "<p>The committee reviewed the annual report and discussed the budget.</p>\n"
            .repeat(400);
        let embeds: [(&str, &[(&str, &str)]); 5] = [
            (
                "<script>var dd={'host':'geo.captcha-delivery.com'}</script><script src=\"https://ct.captcha-delivery.com/c.js\"></script>",
                &[("x-datadome", "protected"), ("server", "DataDome")],
            ),
            (
                "<div id=\"px-captcha\"></div><script>var pxCaptchaSrc='/a/captcha/captcha.js'</script><script src=\"https://captcha.px-cdn.net/a/captcha.js\"></script>",
                &[("x-px-blocked", "1")],
            ),
            (
                "<a href=\"https://errors.edgesuite.net/x\">help</a><script src=\"/_sec/cp_challenge/ak-challenge.js\"></script><p>Access Denied: you don't have permission to access</p>",
                &[
                    ("server", "AkamaiGHost"),
                    ("set-cookie", "ak_bmsc=x; Path=/"),
                ],
            ),
            (
                "<script src=\"/_Incapsula_Resource?SWJIYLWA=1\"></script><!-- Incapsula incident ID: 1 -->",
                &[("x-iinfo", "1-2"), ("x-cdn", "Imperva")],
            ),
            (
                "<script src=\"https://a.sdk.awswaf.com/a/challenge.js\"></script><script>AwsWafIntegration.saveReferrer()</script>",
                &[("x-amzn-waf-action", "challenge")],
            ),
        ];
        for (tag, headers) in embeds {
            let body = format!("<html><body>{tag}{article}</body></html>");
            for status in [200, 202] {
                let r = resp(status, &body, headers);
                assert!(classify(&r).is_none(), "{status} {tag}: {:?}", classify(&r));
            }
            // and a SMALL page with real text is no stub either
            let text = "<p>The committee reviewed the annual report and discussed the budget.</p>"
                .repeat(12);
            let small = format!("<html><body>{tag}{text}</body></html>");
            assert!(
                classify(&resp(200, &small, headers)).is_none(),
                "small {tag}"
            );
        }
    }

    #[test]
    fn vendor_attribution_beats_generic() {
        let v = classify(&resp(
            403,
            "x",
            &[("server", "DataDome"), ("x-datadome", "protected")],
        ))
        .unwrap();
        assert_eq!(v.vendor, Vendor::DataDome);
    }

    #[test]
    fn label_format() {
        let v = Interstitial::new(Vendor::AwsWaf, Kind::Challenge, Confidence::High, "s");
        assert_eq!(v.label(), "aws_waf:challenge:high");
    }
}
