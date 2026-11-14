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
        Self {
            status: resp.status,
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
    if s.small && s.body_has("captcha-delivery.com") {
        return Some(Interstitial::new(
            Vendor::DataDome,
            s.kind_for_status(Kind::Challenge),
            Confidence::High,
            "captcha_host",
        ));
    }
    let header = s.has_header("x-datadome") || s.has_header("x-dd-b") || s.server == "datadome";
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
    if s.header_lower("x-px-blocked") == "1" {
        return Some(Interstitial::new(
            Vendor::PerimeterX,
            s.kind_for_status(Kind::Challenge),
            Confidence::High,
            "x-px-blocked",
        ));
    }
    if s.small
        && [
            "px-captcha",
            "pxcaptchasrc",
            "captcha.px-cdn.net",
            "captcha.px-cloud.net",
        ]
        .iter()
        .any(|m| s.body_has(m))
    {
        return Some(Interstitial::new(
            Vendor::PerimeterX,
            s.kind_for_status(Kind::Challenge),
            Confidence::High,
            "captcha_marker",
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
    if s.small && (s.body_has("errors.edgesuite.net") || s.body_has("errors.akamai.com")) {
        return Some(Interstitial::new(
            Vendor::Akamai,
            s.kind_for_status(Kind::Block),
            Confidence::High,
            "error_reference",
        ));
    }
    // The stock denial page is served by an Akamai edge even at HTTP 200.
    if akamai_server
        && s.small
        && s.body_has("access denied")
        && s.body_has("don't have permission to access")
    {
        return Some(Interstitial::new(
            Vendor::Akamai,
            s.kind_for_status(Kind::Block),
            Confidence::High,
            "access_denied_page",
        ));
    }
    // Bot-manager interstitial script endpoints.
    if s.small && (s.body_has("/_sec/cp_challenge/") || s.body_has("/_sec/verify?provider=")) {
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
    if s.small && s.body_has("incapsula incident id") {
        return Some(Interstitial::new(
            Vendor::Imperva,
            s.kind_for_status(Kind::Block),
            Confidence::High,
            "incident_id",
        ));
    }
    // The resource endpoint is also embedded in ordinary protected pages, so
    // it only counts when the whole body is a stub.
    if s.resp.body.len() <= 2048 && s.body_has("_incapsula_resource") {
        return Some(Interstitial::new(
            Vendor::Imperva,
            s.kind_for_status(Kind::Challenge),
            Confidence::Medium,
            "resource_stub",
        ));
    }
    let imperva_edge = s.header_lower("x-cdn") == "imperva"
        || s.has_header("x-iinfo")
        || s.has_cookie("incap_ses_")
        || s.has_cookie("visid_incap_");
    if imperva_edge && matches!(s.status, 403 | 429) {
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
    if action == "challenge" || action == "captcha" {
        return Some(Interstitial::new(
            Vendor::AwsWaf,
            Kind::Challenge,
            Confidence::High,
            "waf_action_header",
        ));
    }
    // The SDK script is embedded in ordinary pages that use the captcha
    // integration; only a stub served with a non-success status is a challenge.
    let sdk = s.body_has("awswafintegration") || s.body_has("awswaf.com");
    if s.small && sdk && (s.status == 202 || s.blocking_status()) {
        return Some(Interstitial::new(
            Vendor::AwsWaf,
            s.kind_for_status(Kind::Challenge),
            Confidence::High,
            "sdk_stub",
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
        let r = resp(
            200,
            "<script src=\"https://ct.captcha-delivery.com/c.js\"></script>",
            &[],
        );
        let v = classify(&r).unwrap();
        assert_eq!(
            (v.vendor, v.confidence),
            (Vendor::DataDome, Confidence::High)
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
        let v = classify(&resp(
            200,
            "<meta name=\"description\" content=\"px-captcha\">",
            &[],
        ))
        .unwrap();
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
        let v = classify(&resp(
            200,
            "Request unsuccessful. Incapsula incident ID: 1-2",
            &[],
        ))
        .unwrap();
        assert_eq!(
            (v.vendor, v.confidence),
            (Vendor::Imperva, Confidence::High)
        );
        let stub = "<iframe src=\"/_Incapsula_Resource?CWUDNSAI=24\"></iframe>";
        assert_eq!(
            classify(&resp(200, stub, &[])).unwrap().confidence,
            Confidence::Medium
        );
        // the same endpoint inside a big page is just the vendor's sensor tag
        let page = format!(
            "<script src=\"/_Incapsula_Resource?SWJIYLWA=1\"></script>{}",
            "word ".repeat(2000)
        );
        assert!(classify(&resp(200, &page, &[("x-iinfo", "1-2")])).is_none());
    }

    #[test]
    fn aws_waf_header_and_stub() {
        let v = classify(&resp(202, "x", &[("x-amzn-waf-action", "challenge")])).unwrap();
        assert_eq!((v.vendor, v.confidence), (Vendor::AwsWaf, Confidence::High));
        let stub = "<script src=\"https://abc.edge.sdk.awswaf.com/abc/challenge.js\"></script>";
        assert_eq!(
            classify(&resp(202, stub, &[])).unwrap().vendor,
            Vendor::AwsWaf
        );
        // SDK on a normal 200 page is not a challenge
        assert!(classify(&resp(200, stub, &[])).is_none());
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
