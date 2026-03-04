use ox_core::Page;

#[test]
fn test_page_title() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        "<html><head><title>Test</title></head><body>Hello</body></html>",
    );
    assert_eq!(page.title(), "Test");
}

#[test]
fn test_page_select() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<div class="a">1</div><div class="b">2</div>"#,
    );
    let sel = page.select(".b");
    assert_eq!(sel.text().to_string(), "2");
}

#[test]
fn test_page_links() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<a href="/about">About</a><a href="https://other.com">Other</a>"#,
    );
    let links = page.links();
    assert_eq!(links.len(), 2);
    assert_eq!(links[0].href, "/about");
    assert_eq!(links[0].text, "About");
    assert_eq!(links[1].href, "https://other.com");
    assert_eq!(links[1].text, "Other");
}

#[test]
fn test_page_meta_tags() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<meta name="description" content="A test page">"#,
    );
    let meta = page.meta_tags();
    assert!(meta
        .iter()
        .any(|m| m.name == "description" && m.content == "A test page"));
}

#[test]
fn test_page_text() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        "<html><body><p>Hello</p><p>World</p></body></html>",
    );
    let text = page.text();
    assert!(text.contains("Hello"));
    assert!(text.contains("World"));
}

#[test]
fn test_page_status() {
    let page = Page::new("https://example.com".into(), 404, "<html></html>");
    assert_eq!(page.status, 404);
}

#[test]
fn test_page_url() {
    let page = Page::new("https://example.com/page".into(), 200, "<html></html>");
    assert_eq!(page.url, "https://example.com/page");
}

#[test]
fn test_page_select_single_found() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<div id="target">Found</div>"#,
    );
    let sel = page.select_single("#target");
    assert!(sel.is_some());
    assert_eq!(sel.unwrap().text().to_string(), "Found");
}

#[test]
fn test_page_select_single_not_found() {
    let page = Page::new("https://example.com".into(), 200, "<div>No match</div>");
    let sel = page.select_single("#missing");
    assert!(sel.is_none());
}

#[test]
fn test_page_no_links() {
    let page = Page::new("https://example.com".into(), 200, "<p>No links here</p>");
    assert!(page.links().is_empty());
}

#[test]
fn test_page_forms_count() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form id="f1"><input name="a"></form>
           <form id="f2"><input name="b"></form>"#,
    );
    assert_eq!(page.forms().len(), 2);
}

#[test]
fn test_page_form_by_id() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form id="login" action="/login" method="post">
             <input name="user" value="">
           </form>"#,
    );
    let form = page.form_by_id("login");
    assert!(form.is_some());
    let form = form.unwrap();
    assert_eq!(form.action, "/login");
    assert_eq!(form.method, "POST");
}

#[test]
fn test_page_form_by_id_not_found() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        "<form><input name=\"x\"></form>",
    );
    assert!(page.form_by_id("missing").is_none());
}
