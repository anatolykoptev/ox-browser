//! Per-domain robots.txt cache.

use std::collections::HashMap;

use texting_robots::Robot;

/// Cached robots.txt entry for a single host.
enum RobotsEntry {
    /// Successfully parsed robots.txt.
    Loaded(Robot),
    /// Host was checked but robots.txt was unavailable (404, timeout, etc.).
    Unavailable,
}

/// Thread-safe per-domain robots.txt cache.
pub struct RobotsCache {
    user_agent: String,
    entries: HashMap<String, RobotsEntry>,
}

impl RobotsCache {
    /// Create a new cache with the given crawler user-agent string.
    pub fn new(user_agent: &str) -> Self {
        Self {
            user_agent: user_agent.to_string(),
            entries: HashMap::new(),
        }
    }

    /// Insert a successfully fetched robots.txt body for a host.
    ///
    /// Parses the body immediately and caches the result. If parsing
    /// fails the entry is stored as `Unavailable`.
    pub fn insert(&mut self, host: &str, robots_txt_body: &[u8]) {
        let entry = match Robot::new(&self.user_agent, robots_txt_body) {
            Ok(robot) => RobotsEntry::Loaded(robot),
            Err(_) => RobotsEntry::Unavailable,
        };
        self.entries.insert(host.to_string(), entry);
    }

    /// Mark a host as having no usable robots.txt (e.g. 404, network error).
    pub fn insert_unavailable(&mut self, host: &str) {
        self.entries
            .insert(host.to_string(), RobotsEntry::Unavailable);
    }

    /// Check whether the given URL is allowed for crawling.
    ///
    /// Returns `true` if:
    /// - no robots.txt is cached for the host (permissive default),
    /// - the cached entry is `Unavailable`, or
    /// - the parsed robots.txt allows the URL.
    pub fn is_allowed(&self, host: &str, url: &str) -> bool {
        match self.entries.get(host) {
            None | Some(RobotsEntry::Unavailable) => true,
            Some(RobotsEntry::Loaded(robot)) => robot.allowed(url),
        }
    }

    /// Check whether we already have an entry (loaded or unavailable) for a host.
    pub fn has_host(&self, host: &str) -> bool {
        self.entries.contains_key(host)
    }

    /// Return the crawl-delay (seconds) specified in robots.txt, if any.
    pub fn crawl_delay(&self, host: &str) -> Option<f64> {
        match self.entries.get(host) {
            Some(RobotsEntry::Loaded(robot)) => robot.delay.map(|d| d as f64),
            _ => None,
        }
    }
}

/// Extract `Sitemap:` URLs from a robots.txt body.
pub fn extract_sitemaps(robots_txt: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(robots_txt);
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.len() > 8 && line[..8].eq_ignore_ascii_case("sitemap:") {
                Some(line[8..].trim().to_string())
            } else {
                None
            }
        })
        .filter(|url| !url.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const UA: &str = "ox-crawler";

    #[test]
    fn allows_when_no_robots() {
        let cache = RobotsCache::new(UA);
        assert!(cache.is_allowed("example.com", "https://example.com/page"));
    }

    #[test]
    fn allows_when_unavailable() {
        let mut cache = RobotsCache::new(UA);
        cache.insert_unavailable("example.com");
        assert!(cache.is_allowed("example.com", "https://example.com/secret"));
    }

    #[test]
    fn blocks_disallowed_path() {
        let mut cache = RobotsCache::new(UA);
        let body = b"User-agent: *\nDisallow: /private/\n";
        cache.insert("example.com", body);
        assert!(!cache.is_allowed(
            "example.com",
            "https://example.com/private/data"
        ));
        assert!(cache.is_allowed("example.com", "https://example.com/public"));
    }

    #[test]
    fn has_host_tracking() {
        let mut cache = RobotsCache::new(UA);
        assert!(!cache.has_host("example.com"));
        cache.insert("example.com", b"User-agent: *\nAllow: /\n");
        assert!(cache.has_host("example.com"));
    }

    #[test]
    fn parses_crawl_delay() {
        let mut cache = RobotsCache::new(UA);
        let body = b"User-agent: *\nCrawl-delay: 2.5\n";
        cache.insert("example.com", body);
        let delay = cache.crawl_delay("example.com");
        assert!(delay.is_some());
        assert!((delay.unwrap() - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn no_crawl_delay_when_absent() {
        let mut cache = RobotsCache::new(UA);
        let body = b"User-agent: *\nAllow: /\n";
        cache.insert("example.com", body);
        assert!(cache.crawl_delay("example.com").is_none());
    }

    #[test]
    fn extracts_sitemap_urls() {
        let body = b"User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml\nSitemap: https://example.com/sitemap2.xml\n";
        let urls = extract_sitemaps(body);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://example.com/sitemap.xml");
        assert_eq!(urls[1], "https://example.com/sitemap2.xml");
    }

    #[test]
    fn no_sitemaps_in_robots() {
        let body = b"User-agent: *\nDisallow: /private/\n";
        let urls = extract_sitemaps(body);
        assert!(urls.is_empty());
    }
}
