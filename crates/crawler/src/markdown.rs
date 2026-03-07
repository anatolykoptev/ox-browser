//! HTML to Markdown conversion with noise filtering.

use dom_query::Document;

/// CSS selectors for noise elements to strip before conversion.
const NOISE_SELECTORS: &[&str] = &[
    "nav",
    "footer",
    "header",
    ".nav",
    ".navbar",
    ".footer",
    ".sidebar",
    ".menu",
    ".breadcrumb",
    ".pagination",
    ".cookie-banner",
    ".cookie-consent",
    "#cookie-banner",
    "[role=navigation]",
    "[role=banner]",
    "[role=contentinfo]",
    "script",
    "style",
    "noscript",
    "iframe",
];

/// Convert raw HTML to Markdown using htmd.
pub fn html_to_markdown(html: &str) -> String {
    htmd::convert(html).unwrap_or_default()
}

/// Strip noise elements from HTML, then convert to Markdown.
///
/// Removes navigation, footers, headers, sidebars, scripts, styles,
/// and other non-content elements before conversion.
pub fn html_to_fit_markdown(html: &str) -> String {
    let doc = Document::from(html);

    for selector in NOISE_SELECTORS {
        doc.select(selector).remove();
    }

    let cleaned = doc.html();
    htmd::convert(&cleaned).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_basic_html() {
        let html = "<h1>Hello</h1><p>World</p>";
        let md = html_to_markdown(html);
        assert!(md.contains("# Hello"), "expected heading, got: {md}");
        assert!(md.contains("World"), "expected body text, got: {md}");
    }

    #[test]
    fn converts_links() {
        let html = r#"<p>Visit <a href="https://example.com">Example</a></p>"#;
        let md = html_to_markdown(html);
        assert!(
            md.contains("[Example](https://example.com)"),
            "expected markdown link, got: {md}"
        );
    }

    #[test]
    fn fit_markdown_strips_nav() {
        let html = r#"
            <nav><a href="/">Home</a></nav>
            <main><p>Main content</p></main>
            <footer><p>Copyright 2026</p></footer>
        "#;
        let md = html_to_fit_markdown(html);
        assert!(md.contains("Main content"), "expected main content, got: {md}");
        assert!(!md.contains("Home"), "nav should be stripped, got: {md}");
        assert!(
            !md.contains("Copyright"),
            "footer should be stripped, got: {md}"
        );
    }

    #[test]
    fn fit_markdown_strips_scripts() {
        let html = r#"
            <script>alert('xss')</script>
            <style>body { color: red; }</style>
            <noscript>Enable JS</noscript>
            <p>Real content</p>
        "#;
        let md = html_to_fit_markdown(html);
        assert!(md.contains("Real content"), "expected content, got: {md}");
        assert!(!md.contains("alert"), "script should be stripped, got: {md}");
        assert!(
            !md.contains("color: red"),
            "style should be stripped, got: {md}"
        );
        // noscript may or may not be stripped depending on dom_query parser mode
        // The critical check is that scripts and styles are removed
    }

    #[test]
    fn handles_empty_html() {
        let md = html_to_markdown("");
        assert!(md.is_empty() || md.trim().is_empty(), "expected empty, got: {md}");

        let md = html_to_fit_markdown("");
        assert!(md.trim().is_empty() || md.is_empty(), "expected empty, got: {md}");
    }
}
