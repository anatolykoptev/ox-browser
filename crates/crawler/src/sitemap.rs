//! Sitemap XML parser and auto-discovery.

use anyhow::Result;

/// A single URL entry from a sitemap urlset.
#[derive(Debug, Clone)]
pub struct SitemapEntry {
    pub url: String,
    pub lastmod: Option<String>,
    pub priority: Option<f32>,
    pub changefreq: Option<String>,
}

/// Parsed sitemap content — either an index or a urlset.
#[derive(Debug)]
pub enum SitemapContent {
    /// Sitemap index containing URLs of nested sitemaps.
    Index(Vec<String>),
    /// URL set containing page entries.
    UrlSet(Vec<SitemapEntry>),
}

/// Parse a sitemap XML document (either index or urlset).
pub fn parse_sitemap(_xml: &[u8]) -> Result<SitemapContent> {
    todo!()
}
