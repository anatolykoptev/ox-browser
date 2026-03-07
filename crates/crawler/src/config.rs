//! Crawler configuration.

use std::collections::HashMap;

use serde::Deserialize;

use crate::scope::CrawlScope;

/// Runtime configuration for a single crawl job.
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    /// Maximum link-follow depth from the seed URL.
    pub max_depth: u32,
    /// Maximum number of pages to crawl.
    pub max_pages: usize,
    /// Number of concurrent fetches.
    pub concurrency: usize,
    /// URL scope filter.
    pub scope: CrawlScope,
    /// Per-domain page budget (domain → max pages).
    pub budget: HashMap<String, usize>,
    /// Whether to honour robots.txt directives.
    pub respect_robots: bool,
    /// Whether to convert HTML to Markdown in results.
    pub include_markdown: bool,
    /// Polite delay between requests in milliseconds.
    pub delay_ms: u64,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_pages: 100,
            concurrency: 5,
            scope: CrawlScope::default(),
            budget: HashMap::new(),
            respect_robots: true,
            include_markdown: true,
            delay_ms: 200,
        }
    }
}

/// TOML-friendly section for deserializing crawler defaults from a config
/// file.  Fields use `serde(default)` so partial configs are accepted.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct CrawlerSection {
    pub default_max_depth: u32,
    pub default_max_pages: usize,
    pub default_concurrency: usize,
    pub default_delay_ms: u64,
    pub respect_robots: bool,
    pub include_markdown: bool,
}

impl Default for CrawlerSection {
    fn default() -> Self {
        Self {
            default_max_depth: 3,
            default_max_pages: 100,
            default_concurrency: 5,
            default_delay_ms: 200,
            respect_robots: true,
            include_markdown: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = CrawlConfig::default();
        assert_eq!(cfg.max_depth, 3);
        assert_eq!(cfg.max_pages, 100);
        assert_eq!(cfg.concurrency, 5);
        assert_eq!(cfg.delay_ms, 200);
        assert!(cfg.respect_robots);
        assert!(cfg.include_markdown);
        assert!(cfg.budget.is_empty());
    }

    #[test]
    fn crawler_section_deserializes() {
        let toml_str = r#"
            default_max_depth = 5
            default_concurrency = 10
        "#;
        let section: CrawlerSection =
            toml::from_str(toml_str).expect("valid TOML");
        assert_eq!(section.default_max_depth, 5);
        assert_eq!(section.default_concurrency, 10);
        // defaults for omitted fields
        assert_eq!(section.default_max_pages, 100);
        assert_eq!(section.default_delay_ms, 200);
        assert!(section.respect_robots);
        assert!(section.include_markdown);
    }
}
