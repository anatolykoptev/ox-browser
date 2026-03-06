//! Helper functions for SEO HTML extraction.

use dom_query::Document;

/// Extract `content` from `<meta property="og:*">`.
pub(crate) fn meta_property(doc: &Document, property: &str) -> String {
    let sel = format!("meta[property=\"{property}\"]");
    doc.select(&sel)
        .iter()
        .next()
        .and_then(|n| n.attr("content"))
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// Extract `content` from `<meta name="*">`.
pub(crate) fn meta_name(doc: &Document, name: &str) -> String {
    let sel = format!("meta[name=\"{name}\"]");
    doc.select(&sel)
        .iter()
        .next()
        .and_then(|n| n.attr("content"))
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// Extract `href` from `<link rel="*">`.
pub(crate) fn link_href(doc: &Document, rel: &str) -> Option<String> {
    let sel = format!("link[rel=\"{rel}\"]");
    doc.select(&sel)
        .iter()
        .next()
        .and_then(|n| n.attr("href"))
        .map(|s| s.to_string())
}
