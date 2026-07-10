//! SEO analysis: OG tags, Twitter Cards, JSON-LD, canonical, hreflang, robots.

use crate::seo_helpers::{link_href, meta_name, meta_property};

use dom_query::Document;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct OgTags {
    pub title: String,
    pub description: String,
    pub image: String,
    pub og_type: String,
    pub url: String,
    pub site_name: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TwitterCard {
    pub card: String,
    pub title: String,
    pub description: String,
    pub image: String,
    pub site: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct JsonLd {
    pub schema_type: String,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct HreflangEntry {
    pub lang: String,
    pub href: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SeoReport {
    pub score: u8,
    pub og: OgTags,
    pub twitter: TwitterCard,
    pub json_ld: Vec<JsonLd>,
    pub canonical: Option<String>,
    pub hreflang: Vec<HreflangEntry>,
    pub robots: String,
    pub description: String,
    pub keywords: String,
    pub favicon: Option<String>,
}

/// Analyze HTML and return an `SeoReport` with completeness score 0–100.
pub fn analyze(html: &str) -> SeoReport {
    let doc = Document::from(html);

    let og = OgTags {
        title: meta_property(&doc, "og:title"),
        description: meta_property(&doc, "og:description"),
        image: meta_property(&doc, "og:image"),
        og_type: meta_property(&doc, "og:type"),
        url: meta_property(&doc, "og:url"),
        site_name: meta_property(&doc, "og:site_name"),
    };

    let twitter = TwitterCard {
        card: meta_name(&doc, "twitter:card"),
        title: meta_name(&doc, "twitter:title"),
        description: meta_name(&doc, "twitter:description"),
        image: meta_name(&doc, "twitter:image"),
        site: meta_name(&doc, "twitter:site"),
    };

    let canonical = link_href(&doc, "canonical");

    let hreflang: Vec<HreflangEntry> = doc
        .select("link[rel=\"alternate\"][hreflang]")
        .iter()
        .filter_map(|n| {
            let lang = n.attr("hreflang")?.to_string();
            let href = n.attr("href")?.to_string();
            Some(HreflangEntry { lang, href })
        })
        .collect();

    let robots = meta_name(&doc, "robots");
    let description = meta_name(&doc, "description");
    let keywords = meta_name(&doc, "keywords");
    let favicon = link_href(&doc, "icon").or_else(|| link_href(&doc, "shortcut icon"));

    let json_ld: Vec<JsonLd> = doc
        .select("script[type=\"application/ld+json\"]")
        .iter()
        .map(|n| {
            let raw_full = n.text().to_string();
            let schema_type = serde_json::from_str::<serde_json::Value>(&raw_full)
                .ok()
                .and_then(|v| {
                    v.get("@type")
                        .and_then(|t| t.as_str())
                        .map(String::from)
                        .or_else(|| {
                            v.get("@graph")
                                .and_then(|g| g.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|item| item.get("@type"))
                                .and_then(|t| t.as_str())
                                .map(String::from)
                        })
                })
                .unwrap_or_default();
            let raw = if raw_full.len() > 2048 {
                let end = raw_full
                    .char_indices()
                    .take_while(|(i, _)| *i <= 2048)
                    .last()
                    .map(|(i, c)| i + c.len_utf8())
                    .unwrap_or(0);
                format!(
                    "{}... ({} bytes truncated)",
                    &raw_full[..end],
                    raw_full.len() - end
                )
            } else {
                raw_full
            };
            JsonLd { schema_type, raw }
        })
        .collect();

    let score = compute_score(
        &og,
        &twitter,
        &canonical,
        &json_ld,
        &favicon,
        &hreflang,
        &description,
    );
    SeoReport {
        score,
        og,
        twitter,
        json_ld,
        canonical,
        hreflang,
        robots,
        description,
        keywords,
        favicon,
    }
}

#[allow(clippy::too_many_arguments)] // SEO score over independent meta/OG/Twitter/hreflang signals
fn compute_score(
    og: &OgTags,
    twitter: &TwitterCard,
    canonical: &Option<String>,
    json_ld: &[JsonLd],
    favicon: &Option<String>,
    hreflang: &[HreflangEntry],
    description: &str,
) -> u8 {
    let mut score: u8 = 0;
    if !description.is_empty() {
        score += 15;
    }
    if !og.title.is_empty() {
        score += 15;
    }
    if !og.description.is_empty() {
        score += 10;
    }
    if !og.image.is_empty() {
        score += 10;
    }
    if !twitter.card.is_empty() {
        score += 10;
    }
    if canonical.is_some() {
        score += 15;
    }
    if !json_ld.is_empty() {
        score += 15;
    }
    if favicon.is_some() {
        score += 5;
    }
    if !hreflang.is_empty() {
        score += 5;
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_og_tags() {
        let html = r#"<html><head>
            <meta property="og:title" content="My Title">
            <meta property="og:description" content="My Desc">
            <meta property="og:image" content="https://example.com/img.png">
            <meta property="og:type" content="article">
            <meta property="og:url" content="https://example.com/">
            <meta property="og:site_name" content="Example">
        </head></html>"#;
        let r = analyze(html);
        assert_eq!(r.og.title, "My Title");
        assert_eq!(r.og.description, "My Desc");
        assert_eq!(r.og.image, "https://example.com/img.png");
        assert_eq!(r.og.og_type, "article");
        assert_eq!(r.og.url, "https://example.com/");
        assert_eq!(r.og.site_name, "Example");
    }

    #[test]
    fn parse_twitter_cards() {
        let html = r#"<html><head>
            <meta name="twitter:card" content="summary_large_image">
            <meta name="twitter:title" content="TW Title">
            <meta name="twitter:description" content="TW Desc">
            <meta name="twitter:image" content="https://example.com/tw.png">
            <meta name="twitter:site" content="@example">
        </head></html>"#;
        let r = analyze(html);
        assert_eq!(r.twitter.card, "summary_large_image");
        assert_eq!(r.twitter.title, "TW Title");
        assert_eq!(r.twitter.site, "@example");
    }

    #[test]
    fn parse_canonical_and_robots() {
        let html = r#"<html><head>
            <link rel="canonical" href="https://example.com/page">
            <meta name="robots" content="noindex,nofollow">
        </head></html>"#;
        let r = analyze(html);
        assert_eq!(r.canonical.as_deref(), Some("https://example.com/page"));
        assert_eq!(r.robots, "noindex,nofollow");
    }

    #[test]
    fn parse_jsonld() {
        let html = r#"<html><head>
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Article","name":"Test"}</script>
        </head></html>"#;
        let r = analyze(html);
        assert_eq!(r.json_ld.len(), 1);
        assert_eq!(r.json_ld[0].schema_type, "Article");
        assert!(r.json_ld[0].raw.contains("Article"));
    }

    #[test]
    fn parse_hreflang() {
        let html = r#"<html><head>
            <link rel="alternate" hreflang="en" href="https://example.com/en/">
            <link rel="alternate" hreflang="fr" href="https://example.com/fr/">
        </head></html>"#;
        let r = analyze(html);
        assert_eq!(r.hreflang.len(), 2);
        assert!(r.hreflang.iter().any(|e| e.lang == "en"));
        assert!(r.hreflang.iter().any(|e| e.lang == "fr"));
    }

    #[test]
    fn completeness_score_partial() {
        let html = r#"<html><head>
            <meta name="description" content="Desc">
            <meta property="og:title" content="OG Title">
            <link rel="canonical" href="https://example.com/">
        </head></html>"#;
        let r = analyze(html);
        // description=15, og:title=15, canonical=15 → 45
        assert_eq!(r.score, 45);
    }

    #[test]
    fn completeness_score_full() {
        let html = r#"<html><head>
            <meta name="description" content="Desc">
            <meta property="og:title" content="T">
            <meta property="og:description" content="D">
            <meta property="og:image" content="I">
            <meta name="twitter:card" content="summary">
            <link rel="canonical" href="https://example.com/">
            <script type="application/ld+json">{"@type":"WebPage"}</script>
            <link rel="icon" href="/favicon.ico">
            <link rel="alternate" hreflang="en" href="https://example.com/en/">
        </head></html>"#;
        let r = analyze(html);
        assert_eq!(r.score, 100);
    }

    #[test]
    fn jsonld_raw_truncated() {
        let big_json = format!(
            r#"{{"@context":"https://schema.org","@type":"Article","text":"{}"}}"#,
            "x".repeat(5000)
        );
        let html = format!(
            r#"<html><head><script type="application/ld+json">{big_json}</script></head></html>"#
        );
        let r = analyze(&html);
        assert_eq!(r.json_ld.len(), 1);
        assert_eq!(r.json_ld[0].schema_type, "Article");
        assert!(
            r.json_ld[0].raw.len() <= 2100,
            "raw should be truncated, got {}",
            r.json_ld[0].raw.len()
        );
    }

    #[test]
    fn jsonld_graph_type_extraction() {
        let html = r#"<html><head><script type="application/ld+json">
            {"@context":"https://schema.org","@graph":[{"@type":"Organization","name":"Test"}]}
        </script></head></html>"#;
        let r = analyze(html);
        assert_eq!(r.json_ld[0].schema_type, "Organization");
    }

    #[test]
    fn empty_html_score_zero() {
        let r = analyze("");
        assert_eq!(r.score, 0);
        assert!(r.canonical.is_none());
        assert!(r.json_ld.is_empty());
        assert!(r.hreflang.is_empty());
    }
}
