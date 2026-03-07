//! URL scope filtering for crawl boundaries.

use regex::Regex;
use url::Url;

/// Defines which URLs are in-scope for crawling.
#[derive(Debug, Clone)]
pub enum CrawlScope {
    /// Allow any URL sharing the same registrable domain (e.g. sub.example.com
    /// matches example.com).
    SameDomain,
    /// Allow only URLs with an exact host match.
    SameHost,
    /// Custom allow/block regex lists. A URL must match at least one allow
    /// pattern and none of the block patterns.
    Custom {
        allow: Vec<Regex>,
        block: Vec<Regex>,
    },
}

impl Default for CrawlScope {
    fn default() -> Self {
        Self::SameDomain
    }
}

impl CrawlScope {
    /// Check whether `candidate` is allowed given the `origin` URL.
    pub fn is_allowed(&self, origin: &Url, candidate: &Url) -> bool {
        match self {
            Self::SameDomain => {
                let origin_domain = registrable_domain(origin);
                let candidate_domain = registrable_domain(candidate);
                !origin_domain.is_empty()
                    && !candidate_domain.is_empty()
                    && origin_domain == candidate_domain
            }
            Self::SameHost => {
                origin.host_str() == candidate.host_str()
            }
            Self::Custom { allow, block } => {
                let s = candidate.as_str();
                let matched_allow = allow.is_empty()
                    || allow.iter().any(|r| r.is_match(s));
                let matched_block = block.iter().any(|r| r.is_match(s));
                matched_allow && !matched_block
            }
        }
    }
}

/// Extract a rough registrable domain (eTLD+1) by taking the last two
/// dot-separated labels.  This is a lightweight heuristic — it does not
/// consult the Public Suffix List but works for the vast majority of
/// practical cases (e.g. `foo.example.com` → `example.com`).
pub fn registrable_domain(url: &Url) -> String {
    let host = match url.host_str() {
        Some(h) => h,
        None => return String::new(),
    };
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn same_domain_allows_subdomains() {
        let scope = CrawlScope::SameDomain;
        let origin = parse("https://www.example.com/page");
        assert!(scope.is_allowed(
            &origin,
            &parse("https://blog.example.com/post"),
        ));
        assert!(scope.is_allowed(
            &origin,
            &parse("https://example.com/"),
        ));
        assert!(!scope.is_allowed(
            &origin,
            &parse("https://other.com/"),
        ));
    }

    #[test]
    fn same_host_strict() {
        let scope = CrawlScope::SameHost;
        let origin = parse("https://www.example.com/");
        assert!(scope.is_allowed(
            &origin,
            &parse("https://www.example.com/about"),
        ));
        assert!(!scope.is_allowed(
            &origin,
            &parse("https://blog.example.com/"),
        ));
    }

    #[test]
    fn custom_allow_list() {
        let scope = CrawlScope::Custom {
            allow: vec![Regex::new(r"https://docs\.example\.com").unwrap()],
            block: vec![],
        };
        let origin = parse("https://example.com/");
        assert!(scope.is_allowed(
            &origin,
            &parse("https://docs.example.com/guide"),
        ));
        assert!(!scope.is_allowed(
            &origin,
            &parse("https://blog.example.com/"),
        ));
    }

    #[test]
    fn custom_block_list() {
        let scope = CrawlScope::Custom {
            allow: vec![],
            block: vec![Regex::new(r"/admin").unwrap()],
        };
        let origin = parse("https://example.com/");
        assert!(scope.is_allowed(
            &origin,
            &parse("https://example.com/page"),
        ));
        assert!(!scope.is_allowed(
            &origin,
            &parse("https://example.com/admin/settings"),
        ));
    }

    #[test]
    fn custom_allow_and_block() {
        let scope = CrawlScope::Custom {
            allow: vec![Regex::new(r"https://example\.com").unwrap()],
            block: vec![Regex::new(r"/private").unwrap()],
        };
        let origin = parse("https://example.com/");
        assert!(scope.is_allowed(
            &origin,
            &parse("https://example.com/public"),
        ));
        assert!(!scope.is_allowed(
            &origin,
            &parse("https://example.com/private/data"),
        ));
        assert!(!scope.is_allowed(
            &origin,
            &parse("https://other.com/page"),
        ));
    }
}
