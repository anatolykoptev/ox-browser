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

/// Signal name of the AWS WAF token-wait stub, the one 202 shape that escalates.
const SIGNAL_TOKEN_WAIT: &str = "token_wait_stub";

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

    /// Whether this verdict is strong enough to label a page in the
    /// content-quality report. Low-confidence generic verdicts are not.
    pub fn reportable(&self) -> bool {
        self.confidence >= Confidence::Medium
    }

    /// Whether the middleware chain escalates this response to the solver tier
    /// beyond what the blocking-status inference already does.
    ///
    /// Only one non-blocking case escalates: the AWS WAF token-wait stub, a
    /// narrowly defined shape (HTTP 202, tiny body, inline script that waits
    /// for the token and reloads). Every other vendor verdict on a 200/202 page
    /// is report-only: a false positive costs a label, never a solver call.
    pub fn escalates_at(&self, status: u16) -> bool {
        self.vendor == Vendor::AwsWaf && status == 202 && self.signal == SIGNAL_TOKEN_WAIT
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

/// Evidence for one vendor, by class. At most one signal per class counts.
#[derive(Clone, Copy, Default)]
struct Evidence {
    /// A vendor response header.
    header: bool,
    /// A vendor cookie.
    cookie: bool,
    /// The challenge page's own structure: its iframe, form or container, or
    /// the stock denial page. Not a script include or a config blob.
    structure: bool,
    /// A status only this vendor uses for its challenge (AWS WAF 202).
    status: bool,
}

impl Evidence {
    fn classes(self) -> usize {
        usize::from(self.header)
            + usize::from(self.cookie)
            + usize::from(self.structure)
            + usize::from(self.status)
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
        matches!(self.status, 401 | 403 | 429 | 503)
    }

    /// Whether the evidence justifies a verdict for a vendor.
    ///
    /// With a blocking status, attributing the vendor is enough. Without one
    /// (200, 202) the page must have the shape of a stub AND the evidence must
    /// span at least two distinct CLASSES, one of which is the challenge page's
    /// own structure. Any number of markers that come from one script or config
    /// blob are one body signal, and a script include or config is never the
    /// structure: a landing page that embeds a vendor tag has both.
    fn gated(&self, e: Evidence) -> bool {
        self.blocking_status() || (self.stub && e.structure && e.classes() >= 2)
    }

    /// Whether `tag` (e.g. `<iframe`) appears with `needle` in its attributes.
    fn tag_with(&self, tag: &str, needle: &str) -> bool {
        self.small
            && self.body.match_indices(tag).any(|(i, _)| {
                let end = (i + 400).min(self.body.len());
                let mut end = end;
                while !self.body.is_char_boundary(end) {
                    end -= 1;
                }
                self.body[i..end]
                    .split('>')
                    .next()
                    .is_some_and(|t| t.contains(needle))
            })
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
    // Script include and config blob are two markers of ONE embedded script.
    let marker = s.small && (s.body_has("captcha-delivery.com") || s.body_has("var dd={"));
    let ev = Evidence {
        header,
        cookie: s.has_cookie("datadome"),
        structure: s.tag_with("<iframe", "captcha-delivery.com"),
        status: false,
    };
    if marker && s.gated(ev) {
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
    let marker = s.small
        && [
            "px-captcha",
            "pxcaptchasrc",
            "captcha.px-cdn.net",
            "captcha.px-cloud.net",
        ]
        .iter()
        .any(|m| s.body_has(m));
    let ev = Evidence {
        header,
        cookie: s.has_cookie("_px"),
        structure: s.tag_with("<div", "px-captcha"),
        status: false,
    };
    if (header || marker) && s.gated(ev) {
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
    // The stock denial page: title/heading plus the permission sentence. The
    // reference link to the error host belongs to the same page.
    let denied_text = s.small
        && s.body_has("<title>access denied</title>")
        && s.body_has("<h1>access denied</h1>")
        && s.body_has("you don't have permission to access \"");
    let ev = Evidence {
        header: akamai_server,
        cookie: s.has_cookie("ak_bmsc") || s.has_cookie("bm_sz"),
        structure: denied_text,
        status: false,
    };
    if (error_host || denied_text) && s.gated(ev) {
        return Some(Interstitial::new(
            Vendor::Akamai,
            s.kind_for_status(Kind::Block),
            Confidence::High,
            if denied_text {
                "access_denied_page"
            } else {
                "error_reference"
            },
        ));
    }
    // Bot-manager interstitial script endpoints: a script include is not a
    // page structure, so these attribute the vendor under a blocking status only.
    let sensor = s.small
        && ["/_sec/cp_challenge/", "/_sec/verify?provider=", "bm-verify"]
            .iter()
            .any(|m| s.body_has(m));
    if sensor && s.blocking_status() {
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
    let header = s.header_lower("x-cdn") == "imperva" || s.has_header("x-iinfo");
    let cookie = s.has_cookie("incap_ses_") || s.has_cookie("visid_incap_");
    let incident = s.small && s.body_has("incapsula incident id");
    // The resource endpoint is also embedded in ordinary protected pages, so
    // it only counts when the whole body is a stub.
    let resource = s.resp.body.len() <= 2048 && s.body_has("_incapsula_resource");
    let ev = Evidence {
        header,
        cookie,
        structure: s.tag_with("<iframe", "_incapsula_resource"),
        status: false,
    };
    if incident && s.gated(ev) {
        return Some(Interstitial::new(
            Vendor::Imperva,
            s.kind_for_status(Kind::Block),
            Confidence::High,
            "incident_id",
        ));
    }
    if resource && s.gated(ev) {
        return Some(Interstitial::new(
            Vendor::Imperva,
            s.kind_for_status(Kind::Challenge),
            Confidence::Medium,
            "resource_stub",
        ));
    }
    if (header || cookie) && matches!(s.status, 403 | 429) {
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
    // integration. The challenge stub is the page whose inline script waits for
    // the token and reloads.
    let sdk = s.small && (s.body_has("awswafintegration") || s.body_has("challenge.js"));
    let structure = s.small
        && s.body_has("awswafintegration")
        && (s.body_has("gettoken") || s.body_has("hastoken"))
        && s.body_has("reload");
    let ev = Evidence {
        header,
        cookie: s.has_cookie("aws-waf-token"),
        structure,
        status: s.status == 202,
    };
    if (header || sdk) && s.gated(ev) {
        return Some(Interstitial::new(
            Vendor::AwsWaf,
            s.kind_for_status(Kind::Challenge),
            Confidence::High,
            if structure && s.status == 202 {
                SIGNAL_TOKEN_WAIT
            } else if header {
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
        assert!(!v.reportable());
    }

    #[test]
    fn datadome_captcha_host_at_200() {
        // challenge iframe (structure) + vendor header: two classes on a stub
        let stub = "<iframe src=\"https://geo.captcha-delivery.com/captcha/?x=1\"></iframe>";
        let h = [("x-datadome", "protected")];
        let v = classify(&resp(200, stub, &h)).unwrap();
        assert_eq!(
            (v.vendor, v.confidence),
            (Vendor::DataDome, Confidence::High)
        );
        // structure alone is one class
        assert!(classify(&resp(200, stub, &[])).is_none());
        // script + config from one embed are ONE body signal, even with a header
        let script = "<script>var dd={'host':'geo.captcha-delivery.com'}</script><script src=\"https://ct.captcha-delivery.com/c.js\"></script>";
        assert!(classify(&resp(200, script, &h)).is_none());
        // at a blocking status one marker attributes the vendor
        assert_eq!(
            classify(&resp(403, script, &[])).unwrap().vendor,
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
        // at 200: the challenge container plus the header or cookie
        let stub = "<div id=\"px-captcha\"></div>";
        assert!(classify(&resp(200, stub, &[])).is_none());
        assert!(classify(&resp(200, "x", &[("x-px-blocked", "1")])).is_none());
        let v = classify(&resp(200, stub, &[("x-px-blocked", "1")])).unwrap();
        assert_eq!(v.vendor, Vendor::PerimeterX);
        // the captcha script + config are one body signal
        let embed = "<script>var pxCaptchaSrc='/a/captcha/captcha.js'</script><script src=\"https://captcha.px-cdn.net/a/captcha.js\"></script>";
        assert!(classify(&resp(200, embed, &[("x-px-blocked", "1")])).is_none());
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
        let body = "<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1>You don't have permission to access \"/\" on this server.</body></html>";
        let v = classify(&resp(200, body, &[("server", "AkamaiGHost")])).unwrap();
        assert_eq!(
            (v.vendor, v.kind, v.confidence),
            (Vendor::Akamai, Kind::Block, Confidence::High)
        );
        // the same text from an unknown server is not attributed to Akamai
        assert!(classify(&resp(200, body, &[("server", "nginx")])).is_none());
        // each part of the stock shape is required: change one at a time
        let ak = [("server", "AkamaiGHost")];
        for variant in [
            body.replace("<title>Access Denied</title>", "<title>Help</title>"),
            body.replace("<h1>Access Denied</h1>", "<h1>Help</h1>"),
            body.replace("access \"/\"", "access the page"),
        ] {
            assert!(classify(&resp(200, &variant, &ak)).is_none(), "{variant}");
        }
        // a help page that merely uses both phrases is not the stock page
        let help = "<html><head><title>Help center</title></head><body><h1>Troubleshooting</h1><p>If you see Access Denied, you don't have permission to access the page; contact support.</p></body></html>";
        assert!(classify(&resp(200, help, &[("server", "AkamaiGHost")])).is_none());
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
        let v = classify(&resp(200, stub, &[("x-iinfo", "1-2")])).unwrap();
        assert_eq!(
            (v.vendor, v.confidence),
            (Vendor::Imperva, Confidence::High)
        );
        // iframe alone is one class; the incident line without the iframe has no structure
        assert!(classify(&resp(200, stub, &[])).is_none());
        let line = "Request unsuccessful. Incapsula incident ID: 1-2";
        assert!(classify(&resp(200, line, &[("x-iinfo", "1-2")])).is_none());
        let res = "<script src=\"/_Incapsula_Resource?CWUDNSAI=24\"></script>";
        assert!(classify(&resp(200, res, &[("x-iinfo", "1-2")])).is_none());
        // the same endpoint inside a big page is just the vendor's sensor tag
        let page = format!(
            "<script src=\"/_Incapsula_Resource?SWJIYLWA=1\"></script>{}",
            "word ".repeat(2000)
        );
        assert!(classify(&resp(200, &page, &[("x-iinfo", "1-2")])).is_none());
    }

    #[test]
    fn aws_waf_header_and_stub() {
        // the token-wait stub: structure + the vendor's 202 status
        let stub = "<script src=\"https://abc.edge.sdk.awswaf.com/abc/challenge.js\"></script><script>AwsWafIntegration.getToken().then(() => location.reload())</script>";
        let v = classify(&resp(202, stub, &[])).unwrap();
        assert_eq!((v.vendor, v.confidence), (Vendor::AwsWaf, Confidence::High));
        // the same stub at 200 needs another class
        assert!(classify(&resp(200, stub, &[])).is_none());
        let v = classify(&resp(200, stub, &[("x-amzn-waf-action", "challenge")])).unwrap();
        assert_eq!(v.vendor, Vendor::AwsWaf);
        // SDK include + config, even with the header: one body signal, no structure
        let include = "<script src=\"https://a.sdk.awswaf.com/a/challenge.js\"></script><script>AwsWafIntegration.x()</script>";
        let h = [("x-amzn-waf-action", "challenge")];
        assert!(classify(&resp(200, include, &h)).is_none());
        assert!(classify(&resp(202, include, &h)).is_none());
        // a lone header on a plain page is not enough
        assert!(classify(&resp(200, "<html>fine</html>", &h)).is_none());
        assert!(classify(&resp(202, "x", &h)).is_none());
        // at a blocking status the header attributes the vendor
        assert_eq!(
            classify(&resp(403, "x", &h)).unwrap().vendor,
            Vendor::AwsWaf
        );
    }

    /// A small landing page (little text, under 16 KB) that embeds ONE vendor
    /// script carrying several recognised markers, plus that vendor's cookie or
    /// header, is not a challenge: markers from one script are one body signal
    /// and a script include is not a challenge structure.
    #[test]
    fn small_landing_page_embedding_one_vendor_script_is_unclassified() {
        let landing = |embed: &str| {
            format!(
                "<html><head><title>Hi</title></head><body><p>Welcome.</p>{embed}</body></html>"
            )
        };
        let cases: [(&str, &[(&str, &str)]); 5] = [
            (
                "<script>var dd={'host':'geo.captcha-delivery.com'}</script><script src=\"https://ct.captcha-delivery.com/c.js\"></script>",
                &[
                    ("x-datadome", "protected"),
                    ("set-cookie", "datadome=x; Path=/"),
                ],
            ),
            (
                "<script>var pxCaptchaSrc='/a/captcha/captcha.js';window._pxAppId='a'</script><script src=\"https://captcha.px-cdn.net/a/captcha.js\"></script>",
                &[("x-px-blocked", "1"), ("set-cookie", "_pxhd=x; Path=/")],
            ),
            (
                "<script src=\"/_sec/cp_challenge/ak.js\"></script><a href=\"https://errors.edgesuite.net/x\">help</a>",
                &[
                    ("server", "AkamaiGHost"),
                    ("set-cookie", "ak_bmsc=x; Path=/"),
                ],
            ),
            (
                "<script src=\"/_Incapsula_Resource?SWJIYLWA=1\"></script>",
                &[
                    ("x-iinfo", "1-2"),
                    ("set-cookie", "visid_incap_1=x; Path=/"),
                ],
            ),
            (
                "<script src=\"https://a.sdk.awswaf.com/a/challenge.js\"></script><script>AwsWafIntegration.saveReferrer()</script>",
                &[
                    ("x-amzn-waf-action", "challenge"),
                    ("set-cookie", "aws-waf-token=x; Path=/"),
                ],
            ),
        ];
        for (embed, headers) in cases {
            for status in [200, 202] {
                let r = resp(status, &landing(embed), headers);
                assert!(
                    classify(&r).is_none(),
                    "{status} {embed}: {:?}",
                    classify(&r)
                );
            }
        }
    }

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

    /// No captured vendor challenge was served with 405, so it is not a
    /// blocking status: one header on a 405 attributes nothing.
    #[test]
    fn status_405_is_not_a_blocking_status() {
        let h = [("x-amzn-waf-action", "challenge")];
        assert!(classify(&resp(405, "x", &h)).is_none());
    }

    #[test]
    fn label_format() {
        let v = Interstitial::new(Vendor::AwsWaf, Kind::Challenge, Confidence::High, "s");
        assert_eq!(v.label(), "aws_waf:challenge:high");
    }
}
