//! Content-quality verdict for an extracted page.
//!
//! Reports whether the text a caller is about to quote is real content or one
//! of the pages that look like content but are not: an interstitial, a login
//! wall, an access-denied page, a consent wall, a not-found page served with
//! HTTP 200, or an empty shell. It never changes what is returned; it only
//! labels it.
//!
//! Deterministic heuristics, applied in this order (first match wins):
//!
//! 1. an interstitial verdict from [`crate::interstitial`] at medium or higher
//!    confidence (report-only: it never causes a re-fetch);
//! 2. HTTP status 401 / 403 / 429 / 404 / 410;
//! 3. a `<title>` that EQUALS a verify-you-are-human phrase, an access-denied
//!    phrase or a not-found phrase, on a page whose body (outside title, header,
//!    nav and footer) has at most 15 words;
//! 4. a password form that dominates a short page;
//! 5. a cookie-consent title/heading with a form or an almost empty page;
//! 6. too little extracted text, absolutely or relative to the markup.
//!
//! The `login_required`, `access_denied`, `challenge` and `soft_404` labels
//! drive a DROP decision downstream, so they are precision-first: a miss is
//! acceptable, a dropped real page is not. A title or heading phrase alone never
//! yields `login_required`; a headline that merely CONTAINS or STARTS WITH a
//! phrase never yields a wall label; an `<h1>` alone never does either.
//! Phrases exist for English, Russian, German, French and Spanish.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

use crate::HttpResponse;
use crate::interstitial::{self, Interstitial, Kind};

/// A page with fewer effective words than this is "almost empty" for the
/// consent rule.
const SPARSE_WORDS: usize = 80;
/// A `<p>` with at least this many words is article-like.
const ARTICLE_PARA_WORDS: usize = 25;
/// A wall stub has at most this many body words (outside title, header, nav,
/// footer).
const STUB_BODY_WORDS: usize = 15;
/// A password form dominates a page below this many words.
const FORM_PAGE_WORDS: usize = 250;
/// Consent screens are mostly legal copy; when the title or a heading says so
/// they may be this long.
const CONSENT_TITLED_WORDS: usize = 700;
/// Minimum share of the main-content words that sit inside the password form.
const FORM_SHARE: f64 = 0.25;
/// A consent screen's form has at least this many visible controls.
const MAIN_FORM_CONTROLS: usize = 2;
/// Each visible form control counts as this many words of form content.
const CONTROL_WORDS: usize = 3;
/// Below this many effective words a page is empty.
const EMPTY_WORDS: usize = 15;
/// Markup this large with almost no text is an empty shell.
const SHELL_HTML_BYTES: usize = 20_000;
const SHELL_TEXT_RATIO: f64 = 0.005;
const SHELL_MAX_WORDS: usize = 30;
/// HTML scanned for headings, password inputs and visible text.
const SCAN_BYTES: usize = 512 * 1024;
/// Visible-text characters kept when the extractor returned nothing.
const FALLBACK_TEXT_CHARS: usize = 4000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Ok,
    Empty,
    LoginRequired,
    AccessDenied,
    ConsentWall,
    #[serde(rename = "soft_404")]
    Soft404,
    Challenge,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Empty => "empty",
            Self::LoginRequired => "login_required",
            Self::AccessDenied => "access_denied",
            Self::ConsentWall => "consent_wall",
            Self::Soft404 => "soft_404",
            Self::Challenge => "challenge",
        }
    }
}

/// The additive `quality` object of `/read` and `/fetch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContentQuality {
    pub verdict: Verdict,
    /// Bounded token naming the rule that fired.
    pub reason: String,
}

impl ContentQuality {
    fn new(verdict: Verdict, reason: impl Into<String>) -> Self {
        Self {
            verdict,
            reason: reason.into(),
        }
    }
}

/// Inputs of one assessment.
pub struct Input<'a> {
    pub status: u16,
    /// Final URL of the response (host hints only).
    pub url: &'a str,
    pub html: &'a str,
    /// Title the extractor produced (may be empty).
    pub title: &'a str,
    /// Extracted content in the requested format; empty when extraction found
    /// nothing, in which case visible text is read from `html` instead.
    pub text: &'a str,
    /// `text` is HTML (format=html) and must be stripped before counting.
    pub text_is_html: bool,
    pub interstitial: Option<&'a Interstitial>,
}

static PASSWORD_INPUT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)<input\b[^>]*\btype\s*=\s*["']?password\b"#).expect("static regex")
});
static H1: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?is)<h1\b[^>]*>(.*?)</h1>").expect("static regex"));
static PARAGRAPH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?is)<p\b[^>]*>(.*?)</p>").expect("static regex"));
static HTML_TITLE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?is)<title\b[^>]*>(.*?)</title>").expect("static regex"));
static NON_TEXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?is)<(script|style|noscript|template)\b[^>]*>.*?</(?:script|style|noscript|template)>",
    )
    .expect("static regex")
});
/// Page chrome: a login widget in these is site-wide, not the page itself.
static CHROME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)<(header|nav|footer|aside)\b[^>]*>.*?</(?:header|nav|footer|aside)>")
        .expect("static regex")
});
static FORM_CONTROL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)<(?:input|button|select)\b").expect("static regex"));
static HIDDEN_INPUT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)<input\b[^>]*\btype\s*=\s*["']?hidden"#).expect("static regex"));
static FORM: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?is)<form\b[^>]*>.*?(?:</form>|\z)").expect("static regex"));
static TAG: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)<[^>]*>").expect("static regex"));

// --- marker phrases ---------------------------------------------------------
//
// Wall labels (challenge, denied, not-found): the whole `<title>` must EQUAL one
// of these after the site suffix, a leading error code and surrounding
// punctuation are trimmed (see `title_equals`). Phrases are stored in that
// normalised form.

const CHALLENGE_TITLES: &[&str] = &[
    "just a moment",
    "attention required",
    "are you a robot",
    "are you human",
    "verify you are human",
    "verify you are a human",
    "checking your browser",
    "security verification",
    "making sure you're not a bot",
    "client challenge",
    "ich bin kein roboter",
    "êtes-vous un robot",
    "eres un robot",
    "вы не робот",
    "подтвердите, что вы не робот",
];

const DENIED_TITLES: &[&str] = &[
    "access denied",
    "access forbidden",
    "request blocked",
    "zugriff verweigert",
    "zugang verweigert",
    "accès refusé",
    "acceso denegado",
    "доступ запрещен",
    "доступ запрещён",
    "в доступе отказано",
];

const NOT_FOUND_TITLES: &[&str] = &[
    "page not found",
    "not found",
    "page cannot be found",
    "page can't be found",
    "page could not be found",
    "page doesn't exist",
    "page does not exist",
    "this page isn't available",
    "this page is no longer available",
    "seite nicht gefunden",
    "nicht gefunden",
    "page introuvable",
    "page non trouvée",
    "introuvable",
    "página no encontrada",
    "страница не найдена",
    "не найдена",
];

// Consent labels: a phrase in the title or an `<h1>` on word boundaries, plus a
// form with controls or an almost empty page.

const CONSENT_TITLES: &[&str] = &[
    "before you continue to",
    "your privacy choices",
    "privacy choices",
    "cookie settings",
    "cookie consent",
    "cookie preferences",
    "we use cookies",
    "this website uses cookies",
    "this site uses cookies",
    "wir verwenden cookies",
    "diese website verwendet cookies",
    "nous utilisons des cookies",
    "ce site utilise des cookies",
    "utilizamos cookies",
    "usamos cookies",
    "este sitio utiliza cookies",
    "мы используем файлы cookie",
    "мы используем cookie",
    "этот сайт использует файлы cookie",
];

/// Hosts that exist only to serve consent screens.
const CONSENT_HOST_PREFIXES: &[&str] = &["consent.", "guce."];

/// Assess one extracted page.
pub fn assess(input: &Input<'_>) -> ContentQuality {
    // 1. interstitial vendor verdict
    if let Some(v) = input.interstitial
        && v.reportable()
    {
        let verdict = match v.kind {
            Kind::Challenge => Verdict::Challenge,
            Kind::Block | Kind::RateLimit => Verdict::AccessDenied,
        };
        return ContentQuality::new(verdict, format!("interstitial:{}", v.vendor.as_str()));
    }

    let html = clip(input.html, SCAN_BYTES);
    let text = if input.text_is_html {
        visible_text(input.text, usize::MAX)
    } else {
        normalise(clip(input.text, SCAN_BYTES))
    };
    // The extractor can come back empty on pages that are all chrome (login
    // forms, shells); read the visible text of the markup in that case.
    let body_text = if text.trim().is_empty() {
        visible_text(html, FALLBACK_TEXT_CHARS)
    } else {
        text
    };
    let words = effective_words(&body_text);
    let fields = title_fields(input, html);
    let article = article_like(html);
    let sparse = !article && words < SPARSE_WORDS;

    // Statuses that carry a verdict of their own.
    match input.status {
        401 => return ContentQuality::new(Verdict::LoginRequired, "http_401"),
        403 => return ContentQuality::new(Verdict::AccessDenied, "http_403"),
        429 => return ContentQuality::new(Verdict::AccessDenied, "http_429_rate_limited"),
        404 | 410 => return ContentQuality::new(Verdict::Soft404, "http_not_found_status"),
        _ => {}
    }

    // A wall stub: the `<title>` IS the announcement and the body has next to
    // nothing else. The extractor's title and `<h1>` are not consulted.
    let title = html_title(html);
    let stub = stub_body_words(html) <= STUB_BODY_WORDS;
    if stub && title_equals(&title, CHALLENGE_TITLES) {
        return ContentQuality::new(Verdict::Challenge, "challenge_title");
    }

    if words < FORM_PAGE_WORDS && form_dominates(html, true) {
        return ContentQuality::new(Verdict::LoginRequired, "password_form_dominates");
    }

    if stub && title_equals(&title, DENIED_TITLES) {
        return ContentQuality::new(Verdict::AccessDenied, "denied_title");
    }

    if is_consent_host(input.url) && words < FORM_PAGE_WORDS {
        return ContentQuality::new(Verdict::ConsentWall, "consent_host");
    }
    if words < CONSENT_TITLED_WORDS
        && any_field(&fields, |f| contains_phrase(f, CONSENT_TITLES))
        && (sparse || has_main_form(html))
    {
        return ContentQuality::new(Verdict::ConsentWall, "consent_title");
    }

    if stub && title_equals(&title, NOT_FOUND_TITLES) {
        return ContentQuality::new(Verdict::Soft404, "not_found_title");
    }

    if words < EMPTY_WORDS {
        return ContentQuality::new(Verdict::Empty, "too_little_text");
    }
    if input.html.len() >= SHELL_HTML_BYTES
        && words < SHELL_MAX_WORDS
        && (body_text.chars().filter(|c| !c.is_whitespace()).count() as f64)
            / (input.html.len() as f64)
            < SHELL_TEXT_RATIO
    {
        return ContentQuality::new(Verdict::Empty, "low_text_to_markup_ratio");
    }

    ContentQuality::new(Verdict::Ok, "content")
}

/// Assess a raw HTTP response (the `/fetch` path): extracts text with the
/// shared extractor, then runs [`assess`]. `None` for bodies that are not
/// HTML (JSON, plain text, binary-ish) — those have no page to judge.
pub fn assess_response(resp: &HttpResponse) -> Option<ContentQuality> {
    let ctype = resp
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let looks_html = ctype.contains("html") || {
        let head = resp.body.trim_start();
        head.get(..1) == Some("<")
    };
    if !looks_html || resp.body.is_empty() {
        return None;
    }
    let verdict = interstitial::classify(resp);
    let extracted = crate::content::extract_content(
        clip(&resp.body, SCAN_BYTES * 4),
        &resp.url,
        crate::content::ContentFormat::Text,
    );
    Some(assess(&Input {
        status: resp.status,
        url: &resp.url,
        html: &resp.body,
        title: &extracted.title,
        text: &extracted.content,
        text_is_html: false,
        interstitial: verdict.as_ref(),
    }))
}

/// [`assess_response`] on the blocking pool: extraction of a large body must
/// not stall an async worker. Returns the response untouched alongside the
/// verdict.
pub async fn assess_response_blocking(
    resp: HttpResponse,
) -> (HttpResponse, Option<ContentQuality>) {
    let shared = std::sync::Arc::new(resp);
    let job = std::sync::Arc::clone(&shared);
    let quality = tokio::task::spawn_blocking(move || assess_response(&job))
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "quality assessment task failed");
            None
        });
    match std::sync::Arc::try_unwrap(shared) {
        Ok(resp) => (resp, quality),
        // The job has finished, so this is the only owner; copy defensively
        // rather than panic if that ever stops being true.
        Err(shared) => (
            HttpResponse {
                status: shared.status,
                url: shared.url.clone(),
                headers: shared.headers.clone(),
                body: shared.body.clone(),
            },
            quality,
        ),
    }
}

// --- helpers ---------------------------------------------------------------

fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Lowercase, collapse whitespace, fold typographic apostrophes.
fn normalise(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(64 * 1024));
    let mut last_space = true;
    for c in s.chars() {
        let c = match c {
            '\u{2019}' | '\u{2018}' | '\u{02bc}' => '\'',
            c => c,
        };
        if c.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.extend(c.to_lowercase());
            last_space = false;
        }
    }
    out
}

fn decode_entities(s: &str) -> String {
    s.replace("&nbsp;", " ")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

/// Visible text of markup, normalised, at most `limit` characters.
fn visible_text(html: &str, limit: usize) -> String {
    let stripped = NON_TEXT.replace_all(clip(html, SCAN_BYTES), " ");
    let no_tags = TAG.replace_all(&stripped, " ");
    let mut text = normalise(&decode_entities(&no_tags));
    if text.chars().count() > limit {
        text = text.chars().take(limit).collect();
    }
    text
}

/// Whitespace words plus half the CJK characters, so a short Chinese or
/// Japanese paragraph is not mistaken for an empty page.
fn effective_words(text: &str) -> usize {
    let words = text.split_whitespace().count();
    let cjk = text
        .chars()
        .filter(|c| {
            matches!(*c as u32,
                0x3040..=0x30FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xAC00..=0xD7AF)
        })
        .count();
    words + cjk / 2
}

fn h1_texts(html: &str) -> Vec<String> {
    H1.captures_iter(html)
        .take(3)
        .map(|c| visible_text(c.get(1).map_or("", |m| m.as_str()), 200))
        .collect()
}

fn html_title(html: &str) -> String {
    HTML_TITLE
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| normalise(&decode_entities(m.as_str())))
        .unwrap_or_default()
}

/// The places a page announces what it is: the extractor's title, the
/// `<title>` and the first `<h1>`s, each normalised and kept separate so a
/// phrase can never be assembled across two of them.
fn title_fields(input: &Input<'_>, html: &str) -> Vec<String> {
    let mut f = vec![normalise(&decode_entities(input.title)), html_title(html)];
    f.extend(h1_texts(html));
    f.retain(|x| !x.is_empty());
    f
}

fn any_field(fields: &[String], pred: impl Fn(&str) -> bool) -> bool {
    fields.iter().any(|f| pred(f))
}

fn word_edge_before(hay: &str, i: usize) -> bool {
    hay[..i]
        .chars()
        .next_back()
        .is_none_or(|c| !c.is_alphanumeric())
}

fn word_edge_after(hay: &str, j: usize) -> bool {
    hay[j..].chars().next().is_none_or(|c| !c.is_alphanumeric())
}

/// `phrase` occurs in `hay` as whole words ("acceso" is not in "accesorios").
fn contains_phrase(hay: &str, phrases: &[&str]) -> bool {
    phrases.iter().any(|p| {
        hay.match_indices(p)
            .any(|(i, _)| word_edge_before(hay, i) && word_edge_after(hay, i + p.len()))
    })
}

/// The `<title>` equals one of `phrases` once the site suffix ("… | Site",
/// "… - Site"), a leading three-digit error code ("404: …") and surrounding
/// punctuation are trimmed. A longer headline that merely contains or starts
/// with a phrase does not equal it.
fn title_equals(title: &str, phrases: &[&str]) -> bool {
    let mut t = title.trim();
    for sep in [" | ", " - ", " – ", " — ", " · ", " :: ", " « "] {
        if let Some((head, _)) = t.split_once(sep) {
            t = head;
        }
    }
    let code = t
        .split_once(|c: char| c == ':' || c == '-' || c.is_whitespace())
        .filter(|(c, _)| c.len() == 3 && c.chars().all(|d| d.is_ascii_digit()));
    if let Some((_, rest)) = code {
        t = rest;
    }
    let t = t.trim_matches(|c: char| !c.is_alphanumeric());
    !t.is_empty() && phrases.contains(&t)
}

/// Words of body text outside the title, header, nav, footer and aside.
fn stub_body_words(html: &str) -> usize {
    let all = clip(html, SCAN_BYTES);
    let no_title = HTML_TITLE.replace_all(all, " ");
    let no_chrome = CHROME.replace_all(&no_title, " ");
    effective_words(&visible_text(&no_chrome, FALLBACK_TEXT_CHARS))
}

/// Any paragraph with real prose in it: the mark of an article, not a wall.
fn article_like(html: &str) -> bool {
    PARAGRAPH
        .captures_iter(clip(html, SCAN_BYTES))
        .take(200)
        .any(|c| {
            effective_words(&visible_text(c.get(1).map_or("", |m| m.as_str()), 2000))
                >= ARTICLE_PARA_WORDS
        })
}

/// A password form counts as the page's purpose only when it sits in the main
/// content (not in a header, nav, footer or aside) and holds a real share of
/// the text left there. A site-wide sign-in widget on an otherwise short public
/// page fails both tests.
/// Words in a form plus a few per control: a login form is mostly inputs, which
/// carry no text of their own.
fn form_weight(form: &str) -> usize {
    let controls = FORM_CONTROL
        .find_iter(form)
        .count()
        .saturating_sub(HIDDEN_INPUT.find_iter(form).count());
    effective_words(&visible_text(form, FALLBACK_TEXT_CHARS)) + controls * CONTROL_WORDS
}

/// `password_only`: only forms with a password input count.
fn form_dominates(html: &str, password_only: bool) -> bool {
    let main = main_markup(html);
    let main_words = effective_words(&visible_text(&main, FALLBACK_TEXT_CHARS * 4)).max(1);
    FORM.find_iter(&main)
        .filter(|f| !password_only || PASSWORD_INPUT.is_match(f.as_str()))
        .filter(|f| FORM_CONTROL.is_match(f.as_str()))
        .map(|f| form_weight(f.as_str()))
        .any(|form_words| (form_words as f64) / (main_words as f64) >= FORM_SHARE)
}

/// A form with real controls in the main content (consent screens are mostly
/// legal copy, so the form is a small share of the page, but it is there).
fn has_main_form(html: &str) -> bool {
    FORM.find_iter(&main_markup(html)).any(|f| {
        FORM_CONTROL
            .find_iter(f.as_str())
            .count()
            .saturating_sub(HIDDEN_INPUT.find_iter(f.as_str()).count())
            >= MAIN_FORM_CONTROLS
    })
}

/// The markup without header, nav, footer and aside blocks — unless that
/// would remove over 40% of the text (a site wrapping its content in them).
fn main_markup(html: &str) -> std::borrow::Cow<'_, str> {
    let all = clip(html, SCAN_BYTES);
    let stripped = CHROME.replace_all(all, " ");
    let stripped_words = effective_words(&visible_text(&stripped, FALLBACK_TEXT_CHARS * 4));
    let all_words = effective_words(&visible_text(all, FALLBACK_TEXT_CHARS * 4));
    if stripped_words * 5 < all_words * 3 {
        std::borrow::Cow::Borrowed(all)
    } else {
        stripped
    }
}

fn is_consent_host(url: &str) -> bool {
    let Some(rest) = url.split("://").nth(1) else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    CONSENT_HOST_PREFIXES.iter().any(|p| host.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(title: &str, body: &str) -> String {
        format!("<html><head><title>{title}</title></head><body>{body}</body></html>")
    }

    fn judge(html: &str, text: &str) -> ContentQuality {
        assess(&Input {
            status: 200,
            url: "https://example.test/x",
            html,
            title: "",
            text,
            text_is_html: false,
            interstitial: None,
        })
    }

    fn prose(n: usize) -> String {
        "The committee reviewed the annual report and discussed the budget. ".repeat(n)
    }

    #[test]
    fn effective_words_counts_cjk() {
        assert_eq!(effective_words("a b c"), 3);
        assert_eq!(effective_words("光合作用始于太古宙"), 5);
    }

    #[test]
    fn long_article_mentioning_markers_is_ok() {
        let body = format!(
            "<h1>Security notes</h1><p>{} When the proxy says access denied, the user must log in to continue. We use cookies in this example.</p>",
            prose(30)
        );
        let h = page("Security notes", &body);
        assert_eq!(judge(&h, &prose(30)).verdict, Verdict::Ok);
    }

    #[test]
    fn short_access_denied_page() {
        let h = page(
            "Access Denied",
            "<h1>Access Denied</h1><p>You don't have permission to access this page.</p>",
        );
        let q = judge(
            &h,
            "Access Denied You don't have permission to access this page. Reference 18.2",
        );
        assert_eq!(q.verdict, Verdict::AccessDenied);
    }

    #[test]
    fn password_form_marks_login() {
        let h = page(
            "Welcome",
            "<form><input name=u><input type=\"password\" name=p></form>",
        );
        assert_eq!(
            judge(&h, "Username Password").verdict,
            Verdict::LoginRequired
        );
    }

    #[test]
    fn password_input_on_long_page_is_ok() {
        let h = page(
            "Docs",
            &format!("<p>{}</p><input type=password>", prose(40)),
        );
        assert_eq!(judge(&h, &prose(40)).verdict, Verdict::Ok);
    }

    #[test]
    fn consent_wall_and_host() {
        let h = page(
            "We use cookies",
            "<p>We use cookies and data to deliver our services.</p>",
        );
        assert_eq!(
            judge(&h, "We use cookies and data to deliver our services.").verdict,
            Verdict::ConsentWall
        );
        let q = assess(&Input {
            status: 200,
            url: "https://consent.example.test/m?x=1",
            html: &page("x", "<p>choose</p>"),
            title: "",
            text: "choose which data we may use",
            text_is_html: false,
            interstitial: None,
        });
        assert_eq!(q.reason, "consent_host");
    }

    #[test]
    fn soft_404_and_numeric_code() {
        let h = page(
            "Page Not Found",
            "<h1>Page Not Found</h1><p>Try the search.</p>",
        );
        assert_eq!(
            judge(&h, "Page Not Found Try the search.").verdict,
            Verdict::Soft404
        );
        // A bare "404" or "error 404" is not a not-found phrase.
        let text = "A short history of the band, their first record and the tour that followed it.";
        for title in [
            "Error 404: the band",
            "404 (album)",
            "Route A4040 timetable",
        ] {
            let h = page(title, &format!("<h1>{title}</h1><p>{text}</p>"));
            let q = judge(&h, &format!("{title} {text} {text}"));
            assert_eq!(q.verdict, Verdict::Ok, "{title}: {q:?}");
        }
        // "not found" in prose is not a not-found page; in a title it is.
        let h = page(
            "Field notes",
            "<p>The missing letter was not found in the archive.</p>",
        );
        assert_eq!(
            judge(
                &h,
                "The missing letter was not found in the archive, and so the case rested for another long year."
            )
            .verdict,
            Verdict::Ok
        );
        let h = page(
            "Not Found",
            "<h1>Not Found</h1><p>The requested URL was not on this server.</p>",
        );
        assert_eq!(
            judge(&h, "Not Found The requested URL was not on this server.").verdict,
            Verdict::Soft404
        );
    }

    #[test]
    fn site_wide_login_widget_does_not_make_a_login_page() {
        let widget = "<header><form action=/login><input name=u><input type=password name=p><button>Log in</button></form></header>";
        let article = "<main><article><h1>Opening hours</h1><p>The reading room is open on weekdays from nine until five, and the archive can be visited by appointment on Saturdays.</p></article></main>";
        let h = page("Opening hours", &format!("{widget}{article}"));
        let q = judge(
            &h,
            "Opening hours The reading room is open on weekdays from nine until five, and the archive can be visited by appointment on Saturdays.",
        );
        assert_eq!(q.verdict, Verdict::Ok, "{q:?}");
        // the same form as the main content is a login page
        let h = page(
            "Welcome",
            "<main><form action=/login><input name=u><input type=password name=p><button>Go</button></form></main>",
        );
        assert_eq!(
            judge(&h, "Username Password Go").verdict,
            Verdict::LoginRequired
        );
        // content wrapped in <header> is still judged: the form is the page
        let h = page(
            "Welcome",
            "<header><form action=/login><input name=u><input type=password name=p><button>Go</button></form></header>",
        );
        assert_eq!(
            judge(&h, "Username Password Go").verdict,
            Verdict::LoginRequired
        );
        // a form that is a small share of a short main section is not
        let filler =
            "The reading room is open on weekdays and the archive can be visited by appointment. "
                .repeat(8);
        let h = page(
            "Hours",
            &format!("<main><p>{filler}</p><form><input type=password name=p></form></main>"),
        );
        assert_eq!(judge(&h, &filler).verdict, Verdict::Ok);
    }

    /// A headline that merely contains a wall phrase is not a wall, even on a
    /// stub-sized page: only a `<title>` that EQUALS the phrase counts.
    #[test]
    fn headline_containing_a_wall_phrase_is_not_a_wall() {
        let text = "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen";
        let cases = [
            (
                "Марафон: перекрытия",
                "<h1>Доступ запрещён в центр на время марафона</h1><p>В воскресенье с семи утра центр закрыт.</p>",
            ),
            (
                "Council budget",
                "<h1>Council: page not found on budget site</h1><p>A short note.</p>",
            ),
            (
                "Council: page not found on budget site",
                "<p>A short note.</p>",
            ),
            ("Access denied for the new stadium?", "<p>Fans protest.</p>"),
            ("Sign in to buy — Widget 3", "<p>Price 19 dollars.</p>"),
            ("Login Festival 2026 tickets", "<p>Three days in July.</p>"),
        ];
        for (title, body) in cases {
            let h = page(title, body);
            let q = judge(&h, text);
            assert_eq!(q.verdict, Verdict::Ok, "{title}: {q:?}");
        }
        // the title alone equalling the phrase, after the site suffix, is a wall
        let h = page("Access Denied | Example", "<p>Reference 18.2</p>");
        assert_eq!(judge(&h, text).verdict, Verdict::AccessDenied);
        let h = page("404: Page Not Found", "<p>Nothing here.</p>");
        assert_eq!(judge(&h, text).verdict, Verdict::Soft404);
        // but not when the body is a real page
        let long = format!("<p>{}</p>", prose(3));
        let h = page("Access Denied", &long);
        assert_eq!(judge(&h, &prose(3)).verdict, Verdict::Ok);
    }

    #[test]
    fn every_static_regex_compiles() {
        for re in [
            &*PASSWORD_INPUT,
            &*H1,
            &*PARAGRAPH,
            &*HTML_TITLE,
            &*NON_TEXT,
            &*TAG,
            &*CHROME,
            &*FORM,
        ] {
            assert!(!re.as_str().is_empty());
        }
    }

    #[test]
    fn empty_and_shell() {
        assert_eq!(judge("<html></html>", "").verdict, Verdict::Empty);
        let shell = format!(
            "<html><body><div id=app></div><script>{}</script></body></html>",
            "x".repeat(30_000)
        );
        let q = judge(
            &shell,
            "Loading the application now please wait for a while ok fine and thanks for the patience",
        );
        assert_eq!(q.reason, "low_text_to_markup_ratio");
    }

    #[test]
    fn interstitial_verdict_wins_only_at_medium_plus() {
        use crate::interstitial::{Confidence, Kind, Vendor};
        let mk = |c| Interstitial {
            vendor: Vendor::Akamai,
            kind: Kind::Block,
            confidence: c,
            signal: "t",
            ray_id: String::new(),
            cloudflare: None,
        };
        let h = page("T", &format!("<p>{}</p>", prose(30)));
        let mut input = Input {
            status: 200,
            url: "https://example.test/",
            html: &h,
            title: "",
            text: &prose(30),
            text_is_html: false,
            interstitial: None,
        };
        let medium = mk(Confidence::Medium);
        input.interstitial = Some(&medium);
        // Akamai Block maps to access_denied, reason names the vendor
        let q = assess(&input);
        assert_eq!(
            (q.verdict, q.reason.as_str()),
            (Verdict::AccessDenied, "interstitial:akamai")
        );
        let low = mk(Confidence::Low);
        input.interstitial = Some(&low);
        assert_eq!(assess(&input).verdict, Verdict::Ok);
    }

    #[test]
    fn html_format_text_is_stripped() {
        let html = page("T", &format!("<p>{}</p>", prose(5)));
        let q = assess(&Input {
            status: 200,
            url: "https://example.test/",
            html: &html,
            title: "",
            text: &format!("<article><p>{}</p></article>", prose(5)),
            text_is_html: true,
            interstitial: None,
        });
        assert_eq!(q.verdict, Verdict::Ok);
    }

    #[test]
    fn status_verdicts() {
        let mk = |s| {
            assess(&Input {
                status: s,
                url: "https://example.test/",
                html: "<p>x</p>",
                title: "",
                text: "x",
                text_is_html: false,
                interstitial: None,
            })
        };
        assert_eq!(mk(401).verdict, Verdict::LoginRequired);
        assert_eq!(mk(403).verdict, Verdict::AccessDenied);
        assert_eq!(mk(404).verdict, Verdict::Soft404);
    }

    #[test]
    fn verdict_serialises_snake_case() {
        let q = ContentQuality::new(Verdict::Soft404, "r");
        assert_eq!(
            serde_json::to_string(&q).unwrap(),
            r#"{"verdict":"soft_404","reason":"r"}"#
        );
        let q = ContentQuality::new(Verdict::LoginRequired, "r");
        assert!(
            serde_json::to_string(&q)
                .unwrap()
                .contains("login_required")
        );
    }
}
