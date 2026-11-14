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
//!    confidence, or a generic "verify you are human" title;
//! 2. a password form that dominates a short page, or a sign-in title/heading;
//! 3. an access-denied title/heading;
//! 4. a cookie-consent title/heading on a short page;
//! 5. a not-found title/heading on a short page;
//! 6. too little extracted text, absolutely or relative to the markup.
//!
//! Marker phrases are only read from the places a page announces what it is —
//! the title, the first headings and the opening of the text — and only on
//! short pages, so an article that merely mentions "access denied" or "log in"
//! in prose stays `ok`. Phrases exist for English, Russian, German, French and
//! Spanish.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

use crate::HttpResponse;
use crate::interstitial::{self, Interstitial};

/// Pages with at least this many effective words are never judged by marker
/// phrases alone (login / denied / consent / not-found walls are short).
const SHORT_PAGE_WORDS: usize = 150;
/// A password form dominates a page below this many words.
const FORM_PAGE_WORDS: usize = 250;
/// Consent screens are mostly legal copy; when the title or a heading says so
/// they may be this long.
const CONSENT_TITLED_WORDS: usize = 700;
/// Not-found pages carry site navigation, so they get more room.
const NOT_FOUND_WORDS: usize = 200;
/// A title that names the page itself as missing may sit on a page with a
/// large navigation/footer.
const NOT_FOUND_TITLED_WORDS: usize = 600;
/// Minimum share of the main-content words that sit inside the password form.
const FORM_SHARE: f64 = 0.25;
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
/// Characters of text read as "the opening of the page".
const LEAD_CHARS: usize = 300;
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
static HEADING: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?is)<(h1|h2)\b[^>]*>(.*?)</(?:h1|h2)>").expect("static regex"));
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
    Lazy::new(|| Regex::new(r"(?is)<form\b[^>]*>.*?</form>").expect("static regex"));
static TAG: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)<[^>]*>").expect("static regex"));

// --- marker phrases (matched against normalised, lowercased text) ---------

const CHALLENGE_MARKERS: &[&str] = &[
    "just a moment",
    "checking your browser",
    "are you a robot",
    "are you human",
    "verify you are human",
    "verify you are a human",
    "security verification",
    "i'm not a robot",
    "ich bin kein roboter",
    "bist du ein roboter",
    "sind sie ein roboter",
    "êtes-vous un robot",
    "etes-vous un robot",
    "vérification de sécurité",
    "¿eres un robot",
    "eres un robot",
    "вы не робот",
    "подтвердите, что вы не робот",
    "проверка безопасности",
    "please enable js and disable any ad blocker",
];

const LOGIN_MARKERS: &[&str] = &[
    "sign in to",
    "log in to",
    "login to",
    "please log in",
    "please sign in",
    "please login",
    "login required",
    "sign in required",
    "you must be logged in",
    "you must log in",
    "log in or sign up",
    "login or sign up",
    "sign in or sign up",
    "log in to continue",
    "sign in to continue",
    "bitte melden sie sich an",
    "bitte loggen sie sich ein",
    "melden sie sich an",
    "anmelden oder registrieren",
    "veuillez vous connecter",
    "connectez-vous",
    "identifiez-vous",
    "inicia sesión",
    "iniciar sesión",
    "debes iniciar sesión",
    "войдите",
    "для просмотра необходимо войти",
    "необходимо авторизоваться",
    "авторизуйтесь",
    "don't have an account",
    "forgot your password",
    "forgot password",
    "continue with google",
    "passwort vergessen",
    "mot de passe oublié",
    "olvidaste tu contraseña",
    "забыли пароль",
];

/// Titles that ARE a login page when they start with these words.
const LOGIN_TITLE_PREFIX: &[&str] = &[
    "login",
    "log in",
    "sign in",
    "signin",
    "anmelden",
    "einloggen",
    "anmeldung",
    "connexion",
    "se connecter",
    "iniciar sesión",
    "acceso",
    "вход",
    "войти",
    "авторизация",
];

const DENIED_MARKERS: &[&str] = &[
    "access denied",
    "access to this page has been denied",
    "access forbidden",
    "403 forbidden",
    "error 403",
    "you don't have permission to access",
    "you do not have permission to access",
    "request blocked",
    "your request has been blocked",
    "unusual traffic",
    "zugriff verweigert",
    "zugang verweigert",
    "zugriff nicht gestattet",
    "accès refusé",
    "acces refuse",
    "accès interdit",
    "acceso denegado",
    "acceso prohibido",
    "доступ запрещ",
    "доступ ограничен",
    "в доступе отказано",
    "доступ закрыт",
];

const CONSENT_MARKERS: &[&str] = &[
    "we use cookies",
    "this site uses cookies",
    "this website uses cookies",
    "accept all cookies",
    "accept cookies",
    "cookie settings",
    "cookie consent",
    "cookie preferences",
    "your privacy choices",
    "privacy choices",
    "manage consent",
    "before you continue",
    "wir verwenden cookies",
    "diese website verwendet cookies",
    "cookies akzeptieren",
    "datenschutzeinstellungen",
    "nous utilisons des cookies",
    "ce site utilise des cookies",
    "accepter les cookies",
    "gérer les cookies",
    "avant de continuer",
    "utilizamos cookies",
    "usamos cookies",
    "este sitio utiliza cookies",
    "aceptar cookies",
    "antes de ir a",
    "мы используем файлы cookie",
    "мы используем cookie",
    "этот сайт использует файлы cookie",
    "принять все cookie",
    "принять cookie",
    "согласие на использование",
];

/// Bare not-found words: trusted in a title or heading only, never in prose.
const NOT_FOUND_TITLE_ONLY: &[&str] = &["not found", "nicht gefunden", "introuvable", "не найдена"];

const NOT_FOUND_MARKERS: &[&str] = &[
    "page not found",
    "page cannot be found",
    "can't be found",
    "can't find that page",
    "page can't be found",
    "page could not be found",
    "page doesn't exist",
    "page does not exist",
    "this page isn't available",
    "this page is no longer available",
    "no longer available",
    "seite nicht gefunden",
    "seite wurde nicht gefunden",
    "page introuvable",
    "page non trouvée",
    "page non trouvee",
    "página no encontrada",
    "pagina no encontrada",
    "no se encontró la página",
    "страница не найдена",
    "страница не существует",
];

/// Hosts that exist only to serve consent screens.
const CONSENT_HOST_PREFIXES: &[&str] = &["consent.", "guce."];

/// Assess one extracted page.
pub fn assess(input: &Input<'_>) -> ContentQuality {
    // 1. interstitial vendor verdict
    if let Some(v) = input.interstitial
        && v.should_escalate()
    {
        return ContentQuality::new(Verdict::Challenge, format!("interstitial:{}", v.label()));
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
    let titles = title_text(input, html);
    let lead = format!(
        "{titles} {}",
        body_text.chars().take(LEAD_CHARS).collect::<String>()
    );

    // Statuses that carry a verdict of their own.
    match input.status {
        401 => return ContentQuality::new(Verdict::LoginRequired, "http_401"),
        403 => return ContentQuality::new(Verdict::AccessDenied, "http_403"),
        429 => return ContentQuality::new(Verdict::AccessDenied, "http_429_rate_limited"),
        404 | 410 => return ContentQuality::new(Verdict::Soft404, "http_not_found_status"),
        _ => {}
    }

    if words < SHORT_PAGE_WORDS && any_marker(&lead, CHALLENGE_MARKERS) {
        return ContentQuality::new(Verdict::Challenge, "challenge_marker");
    }

    if words < FORM_PAGE_WORDS && password_form_dominates(html) {
        return ContentQuality::new(Verdict::LoginRequired, "password_form_dominates");
    }
    if words < SHORT_PAGE_WORDS
        && (any_marker(&lead, LOGIN_MARKERS) || title_starts_with(input, html, LOGIN_TITLE_PREFIX))
    {
        return ContentQuality::new(Verdict::LoginRequired, "login_marker");
    }

    if words < SHORT_PAGE_WORDS && any_marker(&lead, DENIED_MARKERS) {
        return ContentQuality::new(Verdict::AccessDenied, "denied_marker");
    }

    if is_consent_host(input.url) && words < FORM_PAGE_WORDS {
        return ContentQuality::new(Verdict::ConsentWall, "consent_host");
    }
    if (words < FORM_PAGE_WORDS && any_marker(&lead, CONSENT_MARKERS))
        || (words < CONSENT_TITLED_WORDS && any_marker(&titles, CONSENT_MARKERS))
    {
        return ContentQuality::new(Verdict::ConsentWall, "consent_marker");
    }

    if (words < NOT_FOUND_WORDS && any_marker(&lead, NOT_FOUND_MARKERS))
        || (words < NOT_FOUND_WORDS && any_marker(&titles, NOT_FOUND_TITLE_ONLY))
        || (words < NOT_FOUND_TITLED_WORDS && titled_not_found(&titles))
    {
        return ContentQuality::new(Verdict::Soft404, "not_found_marker");
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

fn heading_texts(html: &str) -> Vec<String> {
    HEADING
        .captures_iter(html)
        .take(4)
        .map(|c| visible_text(c.get(2).map_or("", |m| m.as_str()), 200))
        .collect()
}

fn html_title(html: &str) -> String {
    HTML_TITLE
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| normalise(&decode_entities(m.as_str())))
        .unwrap_or_default()
}

/// Title(s) + first headings: where a page says what it is.
fn title_text(input: &Input<'_>, html: &str) -> String {
    let mut t = normalise(&decode_entities(input.title));
    t.push(' ');
    t.push_str(&html_title(html));
    for h in heading_texts(html) {
        t.push(' ');
        t.push_str(&h);
    }
    t
}

fn any_marker(lead: &str, markers: &[&str]) -> bool {
    markers.iter().any(|m| lead.contains(m))
}

/// Not-found phrases that name "the page" itself, so a headline that merely
/// contains "not found" does not qualify for the larger word budget.
fn titled_not_found(titles: &str) -> bool {
    const PAGE_WORDS: [&str; 5] = ["page", "seite", "página", "pagina", "страниц"];
    NOT_FOUND_MARKERS
        .iter()
        .filter(|m| PAGE_WORDS.iter().any(|w| m.contains(w)))
        .any(|m| titles.contains(m))
}

fn title_starts_with(input: &Input<'_>, html: &str, prefixes: &[&str]) -> bool {
    let titles = [normalise(&decode_entities(input.title)), html_title(html)];
    titles
        .iter()
        .any(|t| prefixes.iter().any(|p| t.starts_with(p)))
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

fn password_form_dominates(html: &str) -> bool {
    let all = clip(html, SCAN_BYTES);
    let stripped = CHROME.replace_all(all, " ");
    let stripped_words = effective_words(&visible_text(&stripped, FALLBACK_TEXT_CHARS * 4));
    // A site that wraps its content in <header> or <nav> would lose the page;
    // when stripping removes over 40% of the text, judge the unstripped markup.
    let all_words = effective_words(&visible_text(all, FALLBACK_TEXT_CHARS * 4));
    let main: std::borrow::Cow<'_, str> = if stripped_words * 5 < all_words * 3 {
        std::borrow::Cow::Borrowed(all)
    } else {
        stripped
    };
    let main_words = effective_words(&visible_text(&main, FALLBACK_TEXT_CHARS * 4)).max(1);
    FORM.find_iter(&main)
        .filter(|f| PASSWORD_INPUT.is_match(f.as_str()))
        .map(|f| form_weight(f.as_str()))
        .any(|form_words| (form_words as f64) / (main_words as f64) >= FORM_SHARE)
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
            "Before you continue",
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

    #[test]
    fn every_static_regex_compiles() {
        for re in [
            &*PASSWORD_INPUT,
            &*HEADING,
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
        assert_eq!(assess(&input).verdict, Verdict::Challenge);
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
