use super::*;

const URL: &str = "https://example.com";

#[test]
fn test_private_ip_in_body() {
    let r = scan_body("Server at 192.168.1.100 responded", URL);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].check, "private_ip");
}
#[test]
fn test_no_false_positive_public_ip() {
    let r = scan_body("DNS at 8.8.8.8", URL);
    assert!(r.findings.iter().all(|f| f.check != "private_ip"));
}
#[test]
fn test_java_stack_trace() {
    let r = scan_body("at com.example.App.main(App.java:42)", URL);
    assert_eq!(r.findings[0].check, "stack_trace");
    assert_eq!(r.findings[0].severity, Severity::High);
}
#[test]
fn test_python_traceback() {
    let r = scan_body("Traceback (most recent call last)", URL);
    assert_eq!(r.findings[0].check, "stack_trace");
}
#[test]
fn test_php_error() {
    let r = scan_body("Fatal error: something in /var/www/app.php:123", URL);
    assert_eq!(r.findings[0].check, "stack_trace");
}
#[test]
fn test_suspicious_comment() {
    let r = scan_body("<!-- TODO: remove hardcoded password=admin123 -->", URL);
    assert!(r.findings.iter().any(|f| f.check == "suspicious_comment"));
}
#[test]
fn test_normal_comment_no_finding() {
    let r = scan_body("<!-- Navigation section -->", URL);
    assert!(r.findings.iter().all(|f| f.check != "suspicious_comment"));
}
#[test]
fn test_meta_generator_version() {
    let r = scan_body(r#"<meta name="generator" content="WordPress 6.4.2">"#, URL);
    assert!(r.findings.iter().any(|f| f.check == "generator_version"));
}
#[test]
fn test_directory_listing() {
    let r = scan_body("<title>Index of /uploads</title>", URL);
    assert!(r.findings.iter().any(|f| f.check == "directory_listing"));
}
#[test]
fn test_session_id_in_url() {
    let r = scan_body("", "https://example.com/app;jsessionid=ABC123DEF456");
    assert!(r.findings.iter().any(|f| f.check == "session_in_url"));
}
#[test]
fn test_sensitive_param_in_url() {
    let r = scan_body("", "https://example.com/?token=abc123&password=secret");
    assert!(r.findings.iter().any(|f| f.check == "sensitive_url_param"));
}
#[test]
fn test_insecure_form_action() {
    let html = r#"<form action="http://evil.com/login" method="post">"#;
    let r = scan_body(html, URL);
    assert!(r.findings.iter().any(|f| f.check == "insecure_form_action"));
}
#[test]
fn test_loopback_ip_detected() {
    let r = scan_body("Connected to 127.0.0.1 on port 8080", URL);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].check, "private_ip");
    assert!(r.findings[0].detail.contains("127.0.0.1"));
}
#[test]
fn test_no_false_positive_near_private_ip() {
    let r = scan_body("Upstream server 11.0.0.1 responded OK", URL);
    assert!(r.findings.iter().all(|f| f.check != "private_ip"));
}
#[test]
fn test_clean_page() {
    let r = scan_body("<html><body><p>Hello world</p></body></html>", URL);
    assert!(r.findings.is_empty());
    assert_eq!(r.score_modifier, 0);
}
#[test]
fn test_xss_event_handler() {
    let html = r#"<img src="x" onerror="alert(1)">"#;
    let r = scan_body(html, URL);
    assert!(r.findings.iter().any(|f| f.check == "xss_event_handlers"));
}
#[test]
fn test_xss_javascript_url() {
    let html = r#"<a href="javascript:alert(1)">click</a>"#;
    let r = scan_body(html, URL);
    assert!(r.findings.iter().any(|f| f.check == "xss_javascript_url"));
}
#[test]
fn test_no_xss_in_clean_html() {
    let html = r#"<p>Hello <b>world</b></p>"#;
    let r = scan_body(html, URL);
    assert!(r.findings.iter().all(|f| !f.check.starts_with("xss_")));
}
#[test]
fn test_xss_multiple_handlers() {
    let html = r#"<div onclick="a()" onmouseover="b()"><img onerror="c()"></div>"#;
    let r = scan_body(html, URL);
    let f = r.findings.iter().find(|f| f.check == "xss_event_handlers").unwrap();
    assert!(f.detail.contains("3"));
}
#[test]
fn test_source_map_detected() {
    let html = r#"<script>var x=1;//# sourceMappingURL=app.js.map</script>"#;
    let r = scan_body(html, URL);
    assert!(r.findings.iter().any(|f| f.check == "exposed_source_map"));
}
#[test]
fn test_no_source_map() {
    let html = r#"<script>var x = 1;</script>"#;
    let r = scan_body(html, URL);
    assert!(r.findings.iter().all(|f| f.check != "exposed_source_map"));
}
