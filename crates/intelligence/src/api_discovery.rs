//! API discovery: fetch/axios/XHR endpoints, GraphQL, Next.js/Nuxt data, forms, WebSockets.

use dom_query::Document;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct ApiReport {
    pub endpoints: Vec<ApiEndpoint>,
    pub graphql_detected: bool,
    pub next_data: bool,
    pub nuxt_data: bool,
    pub form_actions: Vec<String>,
    pub websocket_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiEndpoint {
    pub url: String,
    pub method: String,
    pub source: String,
}

fn extract_fetch_endpoints(script: &str) -> Vec<ApiEndpoint> {
    let re = Regex::new(r#"fetch\s*\(\s*['"]([^'"]+)['"]"#).expect("valid regex");
    re.captures_iter(script)
        .map(|cap| ApiEndpoint {
            url: cap[1].to_string(),
            method: "GET".to_string(),
            source: "fetch".to_string(),
        })
        .collect()
}

fn extract_axios_endpoints(script: &str) -> Vec<ApiEndpoint> {
    let re = Regex::new(r#"axios\.(\w+)\s*\(\s*['"]([^'"]+)['"]"#).expect("valid regex");
    re.captures_iter(script)
        .map(|cap| {
            let method = match cap[1].to_lowercase().as_str() {
                "post"   => "POST",
                "put"    => "PUT",
                "delete" => "DELETE",
                "patch"  => "PATCH",
                _        => "GET",
            };
            ApiEndpoint {
                url: cap[2].to_string(),
                method: method.to_string(),
                source: "axios".to_string(),
            }
        })
        .collect()
}

fn extract_websocket_urls(script: &str) -> Vec<String> {
    let re = Regex::new(r#"new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]"#).expect("valid regex");
    re.captures_iter(script)
        .map(|cap| cap[1].to_string())
        .collect()
}

/// Analyze HTML and return an `ApiReport`.
pub fn analyze(html: &str) -> ApiReport {
    let doc = Document::from(html);

    let mut endpoints: Vec<ApiEndpoint> = Vec::new();
    let mut graphql_detected = false;
    let mut websocket_urls: Vec<String> = Vec::new();

    // Scan inline scripts (no src attribute)
    for node in doc.select("script:not([src])").iter() {
        let script = node.text().to_string();

        endpoints.extend(extract_fetch_endpoints(&script));
        endpoints.extend(extract_axios_endpoints(&script));
        websocket_urls.extend(extract_websocket_urls(&script));

        if script.contains("/graphql") || script.contains("__schema") {
            graphql_detected = true;
        }
    }

    // Deduplicate endpoints by URL
    let mut seen_urls = std::collections::HashSet::new();
    endpoints.retain(|ep| seen_urls.insert(ep.url.clone()));

    // Deduplicate websocket URLs
    websocket_urls.dedup();

    // Next.js: <script id="__NEXT_DATA__">
    let next_data = doc.select("script#__NEXT_DATA__").iter().next().is_some();

    // Nuxt: __NUXT__ anywhere in HTML
    let nuxt_data = html.contains("__NUXT__");

    // Form actions: <form action="..."> (skip empty and "#")
    let form_actions: Vec<String> = doc
        .select("form[action]")
        .iter()
        .filter_map(|n| {
            let action = n.attr("action")?.to_string();
            if action.is_empty() || action == "#" {
                None
            } else {
                Some(action)
            }
        })
        .collect();

    ApiReport {
        endpoints,
        graphql_detected,
        next_data,
        nuxt_data,
        form_actions,
        websocket_urls,
    }
}

#[cfg(test)]
mod tests {
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
        assert!(urls.contains(&"https://api.example.com/data"), "got: {:?}", urls);
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
        // Use ## delimiter because action="#" would terminate r#"..."#
        let html = r##"<html><body>
            <form action="/login" method="post"><input type="submit"></form>
            <form action="#"><input type="submit"></form>
            <form action="/register"><input type="submit"></form>
            <form action=""><input type="submit"></form>
        </body></html>"##;
        let r = analyze(html);
        assert!(r.form_actions.contains(&"/login".to_string()), "got: {:?}", r.form_actions);
        assert!(r.form_actions.contains(&"/register".to_string()), "got: {:?}", r.form_actions);
        assert!(!r.form_actions.contains(&"#".to_string()), "# should be excluded");
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
        assert!(r.websocket_urls.contains(&"wss://ws.example.com/socket".to_string()), "got: {:?}", r.websocket_urls);
    }
}
