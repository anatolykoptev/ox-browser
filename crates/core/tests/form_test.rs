use ox_core::Page;

#[test]
fn test_extract_input_fields() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form action="/submit" method="post">
             <input type="text" name="username" value="alice">
             <input type="password" name="password" value="">
             <input type="submit" name="go" value="Login">
           </form>"#,
    );
    let forms = page.forms();
    assert_eq!(forms.len(), 1);
    let form = &forms[0];
    assert_eq!(form.action, "/submit");
    assert_eq!(form.method, "POST");
    assert_eq!(form.fields.len(), 3);

    assert_eq!(form.fields[0].name, "username");
    assert_eq!(form.fields[0].value, "alice");
    assert_eq!(form.fields[0].field_type, "text");
    assert!(!form.fields[0].disabled);

    assert_eq!(form.fields[1].name, "password");
    assert_eq!(form.fields[1].value, "");
    assert_eq!(form.fields[1].field_type, "password");
}

#[test]
fn test_extract_select_field() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form>
             <select name="color">
               <option value="red">Red</option>
               <option value="blue" selected>Blue</option>
               <option value="green">Green</option>
             </select>
           </form>"#,
    );
    let forms = page.forms();
    assert_eq!(forms.len(), 1);
    let form = &forms[0];

    let color_field = form.fields.iter().find(|f| f.name == "color");
    assert!(color_field.is_some());
    let color_field = color_field.unwrap();
    assert_eq!(color_field.value, "blue");
    assert_eq!(color_field.field_type, "select");
}

#[test]
fn test_extract_textarea_field() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form>
             <textarea name="message">Hello world</textarea>
           </form>"#,
    );
    let forms = page.forms();
    let form = &forms[0];

    let msg = form.fields.iter().find(|f| f.name == "message");
    assert!(msg.is_some());
    let msg = msg.unwrap();
    assert_eq!(msg.value, "Hello world");
    assert_eq!(msg.field_type, "textarea");
}

#[test]
fn test_set_field() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form>
             <input type="text" name="q" value="">
           </form>"#,
    );
    let mut forms = page.forms();
    let form = &mut forms[0];

    form.set_field("q", "rust browser");
    assert_eq!(form.fields[0].value, "rust browser");
}

#[test]
fn test_set_field_nonexistent() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form><input name="a" value="1"></form>"#,
    );
    let mut forms = page.forms();
    let form = &mut forms[0];

    // Setting a non-existent field should be a no-op
    form.set_field("missing", "value");
    assert_eq!(form.fields.len(), 1);
    assert_eq!(form.fields[0].name, "a");
    assert_eq!(form.fields[0].value, "1");
}

#[test]
fn test_serialize() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form>
             <input name="user" value="alice">
             <input name="pass" value="s3cret">
           </form>"#,
    );
    let forms = page.forms();
    let form = &forms[0];

    let serialized = form.serialize();
    assert_eq!(serialized, "user=alice&pass=s3cret");
}

#[test]
fn test_serialize_url_encoding() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form>
             <input name="q" value="hello world">
             <input name="tag" value="a&b">
           </form>"#,
    );
    let forms = page.forms();
    let form = &forms[0];

    let serialized = form.serialize();
    assert_eq!(serialized, "q=hello+world&tag=a%26b");
}

#[test]
fn test_serialize_excludes_disabled() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form>
             <input name="enabled" value="yes">
             <input name="disabled_field" value="no" disabled>
           </form>"#,
    );
    let forms = page.forms();
    let form = &forms[0];

    let serialized = form.serialize();
    assert_eq!(serialized, "enabled=yes");
}

#[test]
fn test_serialize_excludes_nameless() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form>
             <input name="real" value="data">
             <input value="nameless">
           </form>"#,
    );
    let forms = page.forms();
    let form = &forms[0];

    // Nameless inputs are excluded during extraction, so only 1 field
    assert_eq!(form.fields.len(), 1);
    assert_eq!(form.serialize(), "real=data");
}

#[test]
fn test_default_method_is_get() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form><input name="x" value="1"></form>"#,
    );
    let forms = page.forms();
    assert_eq!(forms[0].method, "GET");
}

#[test]
fn test_mixed_field_types() {
    let page = Page::new(
        "https://example.com".into(),
        200,
        r#"<form method="post" action="/save">
             <input type="text" name="title" value="My Post">
             <textarea name="body">Content here</textarea>
             <select name="category">
               <option value="tech" selected>Tech</option>
               <option value="life">Life</option>
             </select>
             <input type="hidden" name="csrf" value="tok123">
           </form>"#,
    );
    let forms = page.forms();
    let form = &forms[0];

    assert_eq!(form.method, "POST");
    assert_eq!(form.action, "/save");

    // 2 inputs + 1 textarea + 1 select = 4 fields
    assert_eq!(form.fields.len(), 4);

    let serialized = form.serialize();
    assert!(serialized.contains("title=My+Post"));
    assert!(serialized.contains("body=Content+here"));
    assert!(serialized.contains("category=tech"));
    assert!(serialized.contains("csrf=tok123"));
}
