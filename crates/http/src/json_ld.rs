//! JSON-LD extraction from raw HTML.
//!
//! Parses `<script type="application/ld+json">` blocks before readability strips them.

/// Extract all JSON-LD blocks from raw HTML.
pub fn extract_json_ld(html: &str) -> Vec<serde_json::Value> {
    let doc = dom_query::Document::from(html);
    let mut results = Vec::new();
    for node in doc.select("script[type='application/ld+json']").iter() {
        let text = node.text().to_string();
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(val) => results.push(val),
            Err(e) => tracing::debug!(error = %e, "skipping malformed JSON-LD"),
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_single_json_ld() {
        let html = r#"<html><head>
            <script type="application/ld+json">{"@type":"LocalBusiness","name":"Кафе Тест"}</script>
        </head><body>text</body></html>"#;
        let ld = extract_json_ld(html);
        assert_eq!(ld.len(), 1);
        assert_eq!(ld[0]["name"], "Кафе Тест");
    }

    #[test]
    fn extracts_multiple_json_ld() {
        let html = r#"<html><head>
            <script type="application/ld+json">{"@type":"Restaurant","name":"A"}</script>
            <script type="application/ld+json">{"@type":"Bar","name":"B"}</script>
        </head><body>text</body></html>"#;
        let ld = extract_json_ld(html);
        assert_eq!(ld.len(), 2);
    }

    #[test]
    fn skips_malformed_json_ld() {
        let html = r#"<html><head>
            <script type="application/ld+json">not json</script>
            <script type="application/ld+json">{"@type":"OK","name":"Valid"}</script>
        </head><body>text</body></html>"#;
        let ld = extract_json_ld(html);
        assert_eq!(ld.len(), 1);
        assert_eq!(ld[0]["name"], "Valid");
    }

    #[test]
    fn empty_html_returns_empty() {
        assert!(extract_json_ld("").is_empty());
        assert!(extract_json_ld("<html><body></body></html>").is_empty());
    }
}
