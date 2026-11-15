//! Fixture-driven tests for the interstitial classifier and the content-quality
//! verdict. Fixtures live in `tests/fixtures/interstitial/` (see its README for
//! provenance; the `imperva_*` ones are synthetic, the rest are captured).

use ox_http::HttpResponse;
use ox_http::content_quality::{Verdict, assess_response};
use ox_http::interstitial::{Confidence, Kind, Vendor, classify};
use wreq::header::{HeaderMap, HeaderName, HeaderValue};

fn dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("interstitial")
}

fn load(name: &str) -> HttpResponse {
    let path = dir().join(format!("{name}.http"));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    let (head, body) = raw.split_once("\n\n").expect("fixture has a blank line");
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.strip_prefix("HTTP "))
        .and_then(|s| s.trim().parse().ok())
        .expect("status line");
    let mut headers = HeaderMap::new();
    for l in lines {
        let (k, v) = l.split_once(':').expect("header line");
        headers.append(
            HeaderName::from_bytes(k.trim().as_bytes()).unwrap(),
            HeaderValue::from_str(v.trim()).unwrap(),
        );
    }
    HttpResponse {
        status,
        url: "https://example.test/".into(),
        headers,
        body: body.to_owned(),
    }
}

fn quality(name: &str) -> Verdict {
    let q = assess_response(&load(name))
        .unwrap_or_else(|| panic!("{name}: no quality verdict (not html?)"));
    eprintln!("{name}: {q:?}");
    q.verdict
}

struct Expect {
    fixture: &'static str,
    vendor: Vendor,
    kind: Kind,
    min_confidence: Confidence,
}

const fn x(
    fixture: &'static str,
    vendor: Vendor,
    kind: Kind,
    min_confidence: Confidence,
) -> Expect {
    Expect {
        fixture,
        vendor,
        kind,
        min_confidence,
    }
}

#[test]
fn vendor_interstitials_are_classified() {
    use Confidence::{High, Medium};
    use Kind::{Block, Challenge, RateLimit};
    use Vendor::*;
    let table = [
        x("datadome_captcha_403", DataDome, Challenge, High),
        x("datadome_captcha_401", DataDome, Challenge, High),
        x("datadome_captcha_403_b", DataDome, Challenge, High),
        x("datadome_header_403", DataDome, Challenge, High),
        x("datadome_cf_403", DataDome, Challenge, High),
        x("perimeterx_denied_403", PerimeterX, Challenge, High),
        x("perimeterx_robot_403", PerimeterX, Challenge, High),
        x("perimeterx_behind_cdn_403", PerimeterX, Challenge, High),
        x("kasada_429", Kasada, RateLimit, High),
        x("akamai_denied_403", Akamai, Block, High),
        x("akamai_denied_200", Akamai, Block, High),
        x("akamai_custom_403", Akamai, Block, Medium),
        x("akamai_edgesuite_foreign_server_403", Akamai, Block, High),
        x("aws_waf_202", AwsWaf, Challenge, High),
        x("aws_waf_401", AwsWaf, Challenge, High),
        x("imperva_incident_200", Imperva, Block, High),
        x("imperva_block_403", Imperva, Block, High),
        x("cloudflare_managed_403", Cloudflare, Challenge, High),
        x("cloudflare_managed_200", Cloudflare, Challenge, High),
        x("cloudflare_just_a_moment_403", Cloudflare, Challenge, High),
    ];
    for e in table {
        let r = load(e.fixture);
        let v = classify(&r).unwrap_or_else(|| panic!("{}: not classified", e.fixture));
        assert_eq!(v.vendor, e.vendor, "{}: vendor ({v:?})", e.fixture);
        assert_eq!(v.kind, e.kind, "{}: kind ({v:?})", e.fixture);
        assert!(
            v.confidence >= e.min_confidence,
            "{}: confidence {:?} < {:?}",
            e.fixture,
            v.confidence,
            e.min_confidence
        );
    }
}

#[test]
fn unattributed_blocks_fall_back_to_generic_low() {
    for name in ["unattributed_403_a", "unattributed_403_b"] {
        let v = classify(&load(name)).unwrap_or_else(|| panic!("{name}: not classified"));
        assert_eq!(v.vendor, Vendor::Generic, "{name}: {v:?}");
        assert_eq!(v.confidence, Confidence::Low, "{name}");
        assert!(!v.reportable(), "{name}");
    }
}

#[test]
fn ordinary_pages_from_vendors_are_not_interstitials() {
    for name in [
        "ok_vendor_own_site",
        "ok_usps",
        "ok_bank_home",
        "ok_login_link_social_post",
        "ok_profile_with_signin_chrome",
        "ok_walmart",
    ] {
        let r = load(name);
        assert!(classify(&r).is_none(), "{name}: {:?}", classify(&r));
        assert_eq!(quality(name), Verdict::Ok, "{name}: quality");
    }
}

#[test]
fn vendor_cookie_on_a_plain_200_is_not_an_interstitial() {
    // The page carries bot-manager cookies but is an ordinary (if empty) response.
    assert!(classify(&load("empty_airline_shell")).is_none());
}

#[test]
fn quality_verdicts_on_real_pages() {
    let table = [
        ("login_hn", Verdict::LoginRequired),
        ("consent_yahoo", Verdict::ConsentWall),
        ("empty_instagram", Verdict::Empty),
        ("cloudflare_managed_200", Verdict::Challenge),
        ("empty_airline_shell", Verdict::Empty),
        ("empty_video_shell", Verdict::Empty),
        ("akamai_denied_200", Verdict::AccessDenied),
        ("datadome_captcha_403", Verdict::Challenge),
        ("aws_waf_202", Verdict::Challenge),
        ("imperva_incident_200", Verdict::AccessDenied),
    ];
    for (name, want) in table {
        assert_eq!(quality(name), want, "{name}");
    }
}

// --- false-positive guards on prose and existing fixtures ------------------

fn existing(name: &str) -> String {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn html_response(body: String) -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("text/html"));
    HttpResponse {
        status: 200,
        url: "https://example.test/article".into(),
        headers,
        body,
    }
}

#[test]
fn existing_real_page_fixtures_are_ok() {
    for name in [
        "www.bbc.com_news.html",
        "github.com_torvalds.html",
        "nextjs.org.html",
        "vercel.com.html",
        "craigslist.org_sfbay_fbh.html",
        "news.ycombinator.com_38765228.html",
        "ja.wikipedia.org_buffett.html",
        "thin_page.html",
    ] {
        let q = assess_response(&html_response(existing(name))).unwrap();
        assert_eq!(q.verdict, Verdict::Ok, "{name}: {q:?}");
    }
}

#[test]
fn non_english_prose_pages_are_ok() {
    let prose_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("llm")
        .join("testdata");
    for name in [
        "prose_ru.txt",
        "prose_ru_long.txt",
        "prose_ru_sparse.txt",
        "prose_de.txt",
        "prose_tr.txt",
        "prose_tr_sparse.txt",
        "prose_ko.txt",
        "prose_zh.txt",
    ] {
        let text = std::fs::read_to_string(prose_dir.join(name)).unwrap();
        let html = format!(
            "<html><head><title>Photosynthesis</title></head><body><article><h1>Photosynthesis</h1><p>{text}</p></article></body></html>"
        );
        let q = assess_response(&html_response(html)).unwrap();
        assert_eq!(q.verdict, Verdict::Ok, "{name}: {q:?}");
    }
}

#[test]
fn articles_that_mention_wall_phrases_in_prose_are_ok() {
    let para = "Engineers often describe an access denied page or a request to log in to continue as the \
        first sign of a gateway policy. We use cookies in this example, and a 404 Not Found response \
        is different from a soft error. Visitors who see page not found should check the address. ";
    let body = para.repeat(12);
    let html = format!(
        "<html><head><title>How gateways refuse requests</title></head><body><article><h1>How gateways refuse requests</h1><p>{body}</p></article></body></html>"
    );
    assert_eq!(
        assess_response(&html_response(html)).unwrap().verdict,
        Verdict::Ok
    );
}

#[test]
fn json_bodies_have_no_quality_verdict() {
    let mut r = html_response("{\"access\":\"denied\"}".into());
    r.headers
        .insert("content-type", HeaderValue::from_static("application/json"));
    assert!(assess_response(&r).is_none());
}

/// Real-style short pages whose title or body brushes a marker phrase. Every
/// one is ordinary content, so every one must be `ok`: go-search drops pages
/// by this label.
#[test]
fn short_pages_that_brush_marker_phrases_are_ok() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("quality_negative");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let html = std::fs::read_to_string(&path).unwrap();
        let q = assess_response(&html_response(html)).unwrap();
        assert_eq!(
            q.verdict,
            Verdict::Ok,
            "{}: {q:?}",
            path.file_name().unwrap().to_string_lossy()
        );
        seen += 1;
    }
    assert!(seen >= 12, "negative fixtures went missing ({seen})");
}

/// Title-only wall stubs: the `<title>` equals a wall phrase (after the site
/// suffix) and the body is nearly empty.
#[test]
fn title_only_wall_stubs_are_labelled() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("quality_positive");
    let table = [
        ("en_access_denied_stub", Verdict::AccessDenied),
        ("ru_dostup_zapreshchen_stub", Verdict::AccessDenied),
        ("en_just_a_moment_stub", Verdict::Challenge),
        ("en_attention_required_stub", Verdict::Challenge),
        ("en_page_not_found_stub", Verdict::Soft404),
        ("en_404_prefix_not_found_stub", Verdict::Soft404),
    ];
    for (name, want) in table {
        let html = std::fs::read_to_string(dir.join(format!("{name}.html"))).unwrap();
        let q = assess_response(&html_response(html)).unwrap();
        assert_eq!(q.verdict, want, "{name}: {q:?}");
    }
}

/// The wall labels are precision-first (a label drops the page downstream), so
/// some real captures are no longer labelled: their wall text is longer than the
/// 15-word stub budget, or their sign-in form is a small share of a full page.
/// Those misses are accepted; what must hold is that none of them is labelled
/// as a wall.
#[test]
fn accepted_misses_are_never_labelled_as_walls() {
    for name in [
        "login_github",
        "login_dropbox",
        "login_spotify",
        "notfound_apple_as_200",
        "notfound_mozilla_as_200",
        "notfound_paypal_as_200",
    ] {
        let v = quality(name);
        assert!(
            !matches!(
                v,
                Verdict::LoginRequired
                    | Verdict::AccessDenied
                    | Verdict::Challenge
                    | Verdict::Soft404
            ),
            "{name}: {v:?}"
        );
    }
}
