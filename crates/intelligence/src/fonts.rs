//! Font analysis: Google Fonts, Adobe Fonts, @font-face declarations.

use dom_query::Document;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct FontsReport {
    pub google_fonts: Vec<String>,
    pub adobe_fonts: bool,
    pub font_face_count: u32,
    pub font_families: Vec<String>,
}

/// Parse all `family=` query parameters from a Google Fonts URL.
/// Handles CSS1 pipe-separated (`family=Foo|Bar`) and CSS2 multi-param
/// (`family=Foo:wght@400&family=Bar`) formats, plus variant specs.
fn parse_google_families(href: &str) -> Vec<String> {
    let query = href.split('?').nth(1).unwrap_or("");

    // Collect every family= param value (CSS2 can have multiple)
    let family_values: Vec<&str> = query
        .split('&')
        .filter(|p| p.starts_with("family="))
        .map(|p| &p["family=".len()..])
        .collect();

    family_values
        .into_iter()
        // CSS1: single param may contain pipe-separated families
        .flat_map(|val| val.split('|'))
        .map(|part| {
            // Strip variant specs: "Roboto:wght@400" → "Roboto"
            let name = part.split(':').next().unwrap_or(part);
            name.replace('+', " ").replace("%20", " ").trim().to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// Extract font-family names from @font-face blocks in raw CSS text.
fn extract_font_face_families(css: &str) -> Vec<String> {
    let re_block = Regex::new(r"(?i)@font-face\s*\{([^}]*)\}").expect("valid regex");
    let re_family =
        Regex::new(r#"(?i)font-family\s*:\s*['"]?([^;'"]+)['"]?"#).expect("valid regex");

    re_block
        .captures_iter(css)
        .filter_map(|cap| {
            let block = cap.get(1)?.as_str();
            let fam = re_family
                .captures(block)?
                .get(1)?
                .as_str()
                .trim()
                .trim_matches(|c| c == '\'' || c == '"')
                .to_string();
            if fam.is_empty() { None } else { Some(fam) }
        })
        .collect()
}

/// Analyze HTML and return a `FontsReport`.
pub fn analyze(html: &str) -> FontsReport {
    let doc = Document::from(html);

    // Google Fonts: <link href="*fonts.googleapis.com*">
    let mut google_fonts: Vec<String> = Vec::new();
    for node in doc.select("link[href]").iter() {
        let href = node.attr("href").map(|s| s.to_string()).unwrap_or_default();
        if href.contains("fonts.googleapis.com") {
            google_fonts.extend(parse_google_families(&href));
        }
    }
    google_fonts.dedup();

    // Adobe Fonts: <link href="*use.typekit.net*">
    let adobe_fonts = doc
        .select("link[href]")
        .iter()
        .any(|n| n.attr("href").map(|h| h.contains("use.typekit.net")).unwrap_or(false));

    // @font-face in inline <style> tags
    let mut font_face_count: u32 = 0;
    let mut font_families: Vec<String> = Vec::new();

    let re_face = Regex::new(r"(?i)@font-face").expect("valid regex");
    for node in doc.select("style").iter() {
        let css = node.text().to_string();
        let count = re_face.find_iter(&css).count() as u32;
        font_face_count += count;
        font_families.extend(extract_font_face_families(&css));
    }
    font_families.dedup();

    FontsReport {
        google_fonts,
        adobe_fonts,
        font_face_count,
        font_families,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_google_fonts() {
        // CSS2 API: multiple family= params with variant specs
        let html = r#"<html><head>
            <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Open+Sans&display=swap">
        </head></html>"#;
        let r = analyze(html);
        assert!(
            r.google_fonts.contains(&"Roboto".to_string()),
            "expected Roboto, got: {:?}",
            r.google_fonts
        );
        assert!(
            r.google_fonts.contains(&"Open Sans".to_string()),
            "expected Open Sans, got: {:?}",
            r.google_fonts
        );
        assert!(!r.adobe_fonts);
    }

    #[test]
    fn detect_font_face() {
        let html = r#"<html><head>
            <style>
                @font-face {
                    font-family: 'MyFont';
                    src: url('/fonts/myfont.woff2') format('woff2');
                }
                @font-face {
                    font-family: "AnotherFont";
                    src: url('/fonts/another.woff') format('woff');
                }
            </style>
        </head></html>"#;
        let r = analyze(html);
        assert_eq!(r.font_face_count, 2);
        assert!(
            r.font_families.contains(&"MyFont".to_string()),
            "expected MyFont, got: {:?}",
            r.font_families
        );
        assert!(
            r.font_families.contains(&"AnotherFont".to_string()),
            "expected AnotherFont, got: {:?}",
            r.font_families
        );
    }

    #[test]
    fn detect_adobe_fonts() {
        let html = r#"<html><head>
            <link rel="stylesheet" href="https://use.typekit.net/abc1234.css">
        </head></html>"#;
        let r = analyze(html);
        assert!(r.adobe_fonts);
        assert!(r.google_fonts.is_empty());
    }

    #[test]
    fn empty_html_returns_defaults() {
        let r = analyze("");
        assert!(r.google_fonts.is_empty());
        assert!(!r.adobe_fonts);
        assert_eq!(r.font_face_count, 0);
        assert!(r.font_families.is_empty());
    }
}
