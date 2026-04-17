use super::*;

#[test]
fn detect_fetch_endpoints() {
    let html = r#"<html><body>
        <script>
            fetch('/api/users');
            fetch("/api/posts");
            fetch("https://api.example.com/data");
        </script>
    </body></html>"#;
    let r = analyze(html);
    let urls: Vec<&str> = r.endpoints.iter().map(|e| e.url.as_str()).collect();
    assert!(urls.contains(&"/api/users"), "got: {:?}", urls);
    assert!(urls.contains(&"/api/posts"), "got: {:?}", urls);
    assert!(
        urls.contains(&"https://api.example.com/data"),
        "got: {:?}",
        urls
    );
    assert!(r.endpoints.iter().all(|e| e.source == "fetch"));
}

#[test]
fn detect_graphql() {
    let html = r#"<html><body>
        <script>
            fetch('/graphql', { method: 'POST', body: JSON.stringify({ query: '{ users { id } }' }) });
        </script>
    </body></html>"#;
    let r = analyze(html);
    assert!(r.graphql_detected, "expected graphql_detected=true");
    let urls: Vec<&str> = r.endpoints.iter().map(|e| e.url.as_str()).collect();
    assert!(urls.contains(&"/graphql"), "got: {:?}", urls);
}

#[test]
fn detect_next_data() {
    let html = r#"<html><body>
        <script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
    </body></html>"#;
    let r = analyze(html);
    assert!(r.next_data, "expected next_data=true");
    assert!(!r.nuxt_data);
}

#[test]
fn detect_form_actions() {
    let html = r##"<html><body>
        <form action="/login" method="post"><input type="submit"></form>
        <form action="#"><input type="submit"></form>
        <form action="/register"><input type="submit"></form>
        <form action=""><input type="submit"></form>
    </body></html>"##;
    let r = analyze(html);
    assert!(
        r.form_actions.contains(&"/login".to_string()),
        "got: {:?}",
        r.form_actions
    );
    assert!(
        r.form_actions.contains(&"/register".to_string()),
        "got: {:?}",
        r.form_actions
    );
    assert!(
        !r.form_actions.contains(&"#".to_string()),
        "# should be excluded"
    );
    assert_eq!(r.form_actions.len(), 2);
}

#[test]
fn detect_axios_endpoints() {
    let html = r#"<html><body>
        <script>
            axios.get('/api/items');
            axios.post('/api/create');
            axios.delete('/api/items/1');
        </script>
    </body></html>"#;
    let r = analyze(html);
    let get_ep = r.endpoints.iter().find(|e| e.url == "/api/items");
    let post_ep = r.endpoints.iter().find(|e| e.url == "/api/create");
    let del_ep = r.endpoints.iter().find(|e| e.url == "/api/items/1");
    assert!(get_ep.is_some());
    assert_eq!(get_ep.unwrap().method, "GET");
    assert_eq!(post_ep.unwrap().method, "POST");
    assert_eq!(del_ep.unwrap().method, "DELETE");
    assert!(r.endpoints.iter().all(|e| e.source == "axios"));
}

#[test]
fn deduplicate_endpoints() {
    let html = r#"<html><body>
        <script>
            fetch('/api/data');
            fetch('/api/data');
        </script>
    </body></html>"#;
    let r = analyze(html);
    let count = r.endpoints.iter().filter(|e| e.url == "/api/data").count();
    assert_eq!(count, 1, "duplicate endpoints should be deduplicated");
}

#[test]
fn detect_websocket_urls() {
    let html = r#"<html><body>
        <script>
            const ws = new WebSocket('wss://ws.example.com/socket');
        </script>
    </body></html>"#;
    let r = analyze(html);
    assert!(
        r.websocket_urls
            .contains(&"wss://ws.example.com/socket".to_string())
    );
}

#[test]
fn detect_webmcp_declarative_tools() {
    let html = r#"<html><body>
        <form toolname="searchFlights" tooldescription="Search available flights">
            <input name="origin" type="text" required>
            <input name="destination" type="text" required>
            <input name="date" type="date" required>
            <button type="submit">Search</button>
        </form>
        <form toolname="bookHotel" tooldescription="Book a hotel room">
            <input name="city" type="text">
            <select name="stars"><option>3</option></select>
        </form>
    </body></html>"#;
    let r = analyze(html);
    assert!(r.webmcp.supported);
    assert_eq!(r.webmcp.declarative_tools.len(), 2);
    assert_eq!(r.webmcp.tool_count, 2);
    let flight = r
        .webmcp
        .declarative_tools
        .iter()
        .find(|t| t.name == "searchFlights")
        .unwrap();
    assert_eq!(flight.description, "Search available flights");
    assert_eq!(flight.inputs, vec!["origin", "destination", "date"]);
    let hotel = r
        .webmcp
        .declarative_tools
        .iter()
        .find(|t| t.name == "bookHotel")
        .unwrap();
    assert_eq!(hotel.inputs, vec!["city", "stars"]);
}

#[test]
fn detect_webmcp_imperative() {
    let html = r#"<html><body>
        <script>
            navigator.modelContext.registerTool({
                name: "search",
                description: "Search products",
                async execute(params) { return {}; }
            });
        </script>
    </body></html>"#;
    let r = analyze(html);
    assert!(r.webmcp.supported);
    assert!(r.webmcp.imperative_detected);
}

#[test]
fn no_webmcp_on_normal_site() {
    let html = r#"<html><body>
        <form action="/login"><input name="user"><input name="pass"></form>
    </body></html>"#;
    let r = analyze(html);
    assert!(!r.webmcp.supported);
    assert!(r.webmcp.declarative_tools.is_empty());
    assert!(!r.webmcp.imperative_detected);
}

#[test]
fn detect_public_api_openapi_link() {
    let html = r#"<html><head>
        <link rel="service-desc" href="/api/openapi.json">
    </head><body>
        <a href="/swagger-ui/index.html">API Docs</a>
        <a href="/api/v2/openapi.yaml">OpenAPI Spec</a>
    </body></html>"#;
    let r = analyze(html);
    assert!(r.public_api.detected);
    assert!(
        r.public_api
            .api_links
            .contains(&"/api/openapi.json".to_string())
    );
    assert_eq!(
        r.public_api.openapi_url,
        Some("/api/v2/openapi.yaml".to_string())
    );
}

#[test]
fn detect_public_api_well_known() {
    let html = r#"<html><body>
        <script>
            fetch('/.well-known/openid-configuration');
            const plugin = '/.well-known/ai-plugin.json';
        </script>
    </body></html>"#;
    let r = analyze(html);
    assert!(r.public_api.detected);
    assert!(
        r.public_api
            .well_known
            .contains(&"/.well-known/openid-configuration".to_string())
    );
    assert!(
        r.public_api
            .well_known
            .contains(&"/.well-known/ai-plugin.json".to_string())
    );
}

#[test]
fn detect_public_api_swagger_ui() {
    let html = r#"<html><body>
        <div id="swagger-ui"></div>
        <script src="/swagger-ui-bundle.js"></script>
        <script>SwaggerUI({ url: "/api/v1/openapi.json" });</script>
    </body></html>"#;
    let r = analyze(html);
    assert!(r.public_api.detected);
    assert!(
        r.public_api
            .hints
            .contains(&"openapi_config_detected".to_string())
    );
}

#[test]
fn detect_public_api_graphql_playground() {
    let html = r#"<html><body>
        <div id="graphiql"></div>
        <script>GraphiQL.init();</script>
    </body></html>"#;
    let r = analyze(html);
    assert!(r.public_api.detected);
    assert!(
        r.public_api
            .hints
            .contains(&"graphql_playground".to_string())
    );
}

#[test]
fn no_public_api_on_normal_site() {
    let html = r#"<html><body><h1>Hello</h1></body></html>"#;
    let r = analyze(html);
    assert!(!r.public_api.detected);
    assert!(r.public_api.openapi_url.is_none());
    assert!(r.public_api.api_links.is_empty());
}
