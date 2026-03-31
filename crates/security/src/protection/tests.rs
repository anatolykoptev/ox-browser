//! Unit tests for protection detection engine.

use std::collections::HashMap;

use crate::types::ScanMode;

use super::detect_protection;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn cookies(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| s.to_string()).collect()
}

// 1. Cloudflare CDN from headers
#[test]
fn detect_cloudflare_from_headers() {
    let hdrs = headers(&[("cf-ray", "abc123"), ("server", "cloudflare")]);
    let report = detect_protection(&hdrs, &[], "", "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "Cloudflare CDN");
    assert!(det.is_some(), "should detect Cloudflare CDN");
    assert!(report.summary.has_waf);
}

// 2. Cloudflare Bot Management from cookies
#[test]
fn detect_cloudflare_bot_mgmt_from_cookies() {
    let cks = cookies(&["cf_clearance", "__cf_bm"]);
    let report = detect_protection(&empty_headers(), &cks, "", "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "Cloudflare Bot Management");
    assert!(det.is_some(), "should detect Cloudflare Bot Management");
    assert!(report.summary.has_bot_detection);
}

// 3. Akamai Bot Manager from cookies
#[test]
fn detect_akamai_from_cookies() {
    let cks = cookies(&["_abck", "bm_sz"]);
    let report = detect_protection(&empty_headers(), &cks, "", "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "Akamai Bot Manager");
    assert!(det.is_some(), "should detect Akamai Bot Manager");
}

// 4. DataDome from header + cookie
#[test]
fn detect_datadome_from_header_and_cookie() {
    let hdrs = headers(&[("x-datadome-cid", "abc123")]);
    let cks = cookies(&["datadome"]);
    let report = detect_protection(&hdrs, &cks, "", "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "DataDome");
    assert!(det.is_some(), "should detect DataDome");
    assert!(det.unwrap().confidence >= 100);
}

// 5. PerimeterX / HUMAN from cookies
#[test]
fn detect_perimeterx_from_cookies() {
    let cks = cookies(&["_px3", "_pxhd"]);
    let report = detect_protection(&empty_headers(), &cks, "", "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "PerimeterX / HUMAN");
    assert!(det.is_some(), "should detect PerimeterX / HUMAN");
}

// 6. Imperva / Incapsula from cookie prefix
#[test]
fn detect_imperva_from_cookie_prefix() {
    let cks = cookies(&["incap_ses_1234", "visid_incap_5678"]);
    let report = detect_protection(&empty_headers(), &cks, "", "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "Imperva / Incapsula");
    assert!(det.is_some(), "should detect Imperva / Incapsula");
}

// 7. reCAPTCHA v2 from script + HTML
#[test]
fn detect_recaptcha_from_script() {
    let html = r#"
        <script src="https://google.com/recaptcha/api.js"></script>
        <div class="g-recaptcha" data-sitekey="abc"></div>
    "#;
    let report = detect_protection(&empty_headers(), &[], html, "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "reCAPTCHA v2");
    assert!(det.is_some(), "should detect reCAPTCHA v2");
    assert!(report.summary.has_captcha);
}

// 8. hCaptcha from script
#[test]
fn detect_hcaptcha_from_script() {
    let html = r#"<script src="https://js.hcaptcha.com/1/api.js"></script>"#;
    let report = detect_protection(&empty_headers(), &[], html, "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "hCaptcha");
    assert!(det.is_some(), "should detect hCaptcha");
}

// 9. Cloudflare Turnstile from HTML
#[test]
fn detect_turnstile_from_html() {
    let html = r#"
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
        <div class="cf-turnstile" data-sitekey="xxx"></div>
    "#;
    let report = detect_protection(&empty_headers(), &[], html, "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "Cloudflare Turnstile");
    assert!(det.is_some(), "should detect Cloudflare Turnstile");
}

// 10. FingerprintJS from script
#[test]
fn detect_fingerprintjs_from_script() {
    let html = r#"<script src="https://openfpcdn.io/fingerprintjs/v4/iife.min.js"></script>"#;
    let report = detect_protection(&empty_headers(), &[], html, "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "FingerprintJS");
    assert!(det.is_some(), "should detect FingerprintJS");
    assert!(report.summary.has_fingerprinting);
}

// 11. Fingerprint Pro from script
#[test]
fn detect_fingerprint_pro_from_script() {
    let html = r#"<script src="https://fpjscdn.net/v3/abc123"></script>"#;
    let report = detect_protection(&empty_headers(), &[], html, "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "Fingerprint Pro");
    assert!(det.is_some(), "should detect Fingerprint Pro");
}

// 12. AWS WAF from cookie
#[test]
fn detect_aws_waf_from_cookie() {
    let cks = cookies(&["aws-waf-token"]);
    let report = detect_protection(&empty_headers(), &cks, "", "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "AWS WAF");
    assert!(det.is_some(), "should detect AWS WAF");
}

// 13. Castle.io from HTML
#[test]
fn detect_castle_from_html() {
    let html = r#"<script>Castle.configure({pk: 'pk_abc123'})</script>"#;
    let report = detect_protection(&empty_headers(), &[], html, "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "Castle.io");
    assert!(det.is_some(), "should detect Castle.io");
}

// 14. Empty input detects nothing
#[test]
fn empty_input_detects_nothing() {
    let report = detect_protection(&empty_headers(), &[], "", "", ScanMode::Public);

    assert!(report.detections.is_empty());
    assert_eq!(report.summary.total_systems, 0);
}

// 15. Login mode warns about missing CAPTCHA
#[test]
fn login_mode_warns_no_captcha() {
    let report = detect_protection(&empty_headers(), &[], "", "", ScanMode::Login);

    let finding = report.findings.iter().find(|f| f.check == "no_captcha");
    assert!(finding.is_some(), "login mode should warn about missing CAPTCHA");
}

// 16. Login mode no warning when CAPTCHA present
#[test]
fn login_mode_no_warning_when_captcha_present() {
    let html = r#"<script src="https://js.hcaptcha.com/1/api.js"></script>"#;
    let report = detect_protection(&empty_headers(), &[], html, "", ScanMode::Login);

    let finding = report.findings.iter().find(|f| f.check == "no_captcha");
    assert!(finding.is_none(), "should not warn about CAPTCHA when hCaptcha is present");
}

// 17. Public mode emits no absence findings
#[test]
fn public_mode_no_absence_findings() {
    let report = detect_protection(&empty_headers(), &[], "", "", ScanMode::Public);

    assert!(report.findings.is_empty(), "public mode should have no absence findings");
}

// 18. Multiple systems detected simultaneously
#[test]
fn multiple_systems_detected() {
    let hdrs = headers(&[("cf-ray", "abc123"), ("server", "cloudflare")]);
    let cks = cookies(&["__cf_bm"]);
    let html = r#"<script src="https://google.com/recaptcha/api.js"></script>"#;

    let report = detect_protection(&hdrs, &cks, html, "", ScanMode::Public);

    assert!(report.summary.total_systems >= 3, "should detect at least 3 systems");
    assert!(report.summary.has_waf, "should detect WAF");
    assert!(report.summary.has_bot_detection, "should detect bot detection");
    assert!(report.summary.has_captcha, "should detect CAPTCHA");
}

// 19. Shape Security detected from header regex
#[test]
fn shape_security_detected_from_header_regex() {
    let hdrs = headers(&[("x-ab12cd34-a", "1"), ("x-ab12cd34-z", "2")]);
    let report = detect_protection(&hdrs, &[], "", "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "Shape Security / F5");
    assert!(det.is_some(), "should detect Shape Security / F5");
}

// 20. F5 BIG-IP detected from cookie regex
#[test]
fn f5_bigip_detected_from_cookie_regex() {
    let cks = cookies(&["TSabcdef123"]);
    let report = detect_protection(&empty_headers(), &cks, "", "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "F5 BIG-IP");
    assert!(det.is_some(), "should detect F5 BIG-IP");
}

// 21. ALTCHA PoW Challenge detected from HTML
#[test]
fn detect_altcha_pow_from_html() {
    let html = r#"<input type="hidden" name="challenge" value="abc"><input type="hidden" name="salt" value="def"><input type="hidden" name="sig" value="ghi">var CHALLENGE = SHA-256(salt + nonce)"#;
    let report = detect_protection(&empty_headers(), &[], html, "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "ALTCHA PoW Challenge");
    assert!(det.is_some(), "should detect ALTCHA PoW, got: {:?}", report.detections);
    assert!(report.summary.has_bot_detection);
}

// 22. NJS Antibot Gate detected from cookie
#[test]
fn detect_njs_antibot_from_cookie() {
    let cks = cookies(&["pn_antibot"]);
    let report = detect_protection(&empty_headers(), &cks, "", "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "NJS Antibot Gate");
    assert!(det.is_some(), "should detect NJS Antibot Gate");
    assert!(report.summary.has_bot_detection);
}

// 23. NJS Antibot Gate detected from challenge page HTML
#[test]
fn detect_njs_antibot_from_challenge_html() {
    let html = r#"<title>Проверка браузера</title><div>Проверяем ваш браузер...</div>"#;
    let report = detect_protection(&empty_headers(), &[], html, "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "NJS Antibot Gate");
    assert!(det.is_some(), "should detect NJS Antibot from challenge page");
}

// 24. Qrator detected from cookies
#[test]
fn detect_qrator_from_cookies() {
    let cks = cookies(&["qrator_jsid"]);
    let report = detect_protection(&empty_headers(), &cks, "", "", ScanMode::Public);

    let det = report.detections.iter().find(|d| d.name == "Qrator");
    assert!(det.is_some(), "should detect Qrator");
    assert!(report.summary.has_waf);
}

// 25. Login mode: PoW suppresses no_captcha finding
#[test]
fn login_mode_pow_suppresses_no_captcha() {
    let html = r#"<input name="challenge" value="x"><input name="salt" value="y"><input name="sig" value="z">SHA-256("#;
    let report = detect_protection(&empty_headers(), &[], html, "", ScanMode::Login);

    assert!(report.summary.has_bot_detection, "PoW should count as bot_detection");
    let no_captcha = report.findings.iter().find(|f| f.check == "no_captcha");
    assert!(no_captcha.is_none(), "PoW should suppress no_captcha finding");
    let no_bot = report.findings.iter().find(|f| f.check == "no_bot_detection");
    assert!(no_bot.is_none(), "PoW should suppress no_bot_detection finding");
}
