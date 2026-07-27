// Parallel multi-engine reverse image search with dedup and stock detection.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use tokio::task::JoinSet;

use crate::{ReverseEngine, ReverseResult, is_stock_domain};
use ox_http::HttpClient;

/// Multi-engine reverse image search with parallel execution.
pub struct ReverseSearchEngine {
    engines: Vec<Arc<dyn ReverseEngine>>,
}

impl ReverseSearchEngine {
    pub fn new(engines: Vec<Arc<dyn ReverseEngine>>) -> Self {
        Self { engines }
    }

    /// Search all engines in parallel, dedup, detect stock domains.
    pub async fn search(
        &self,
        client: Arc<HttpClient>,
        image_url: &str,
        max: usize,
    ) -> ReverseResult {
        let start = Instant::now();

        let engine_names: Vec<String> = self.engines.iter().map(|e| e.name().to_owned()).collect();

        let mut set = JoinSet::new();
        for engine in &self.engines {
            let engine = Arc::clone(engine);
            let client = Arc::clone(&client);
            let url = image_url.to_owned();
            set.spawn(async move {
                match engine.search(&client, &url, max).await {
                    Ok(results) => results,
                    Err(e) => {
                        tracing::warn!(
                            engine = engine.name(),
                            error = %e,
                            "reverse search failed"
                        );
                        Vec::new()
                    }
                }
            });
        }

        let mut all_matches = Vec::new();
        while let Some(Ok(results)) = set.join_next().await {
            all_matches.extend(results);
        }

        // Dedup by page_url, keep first occurrence.
        let mut seen = HashSet::new();
        let mut deduped = Vec::new();
        for m in all_matches {
            if seen.insert(m.page_url.clone()) {
                deduped.push(m);
            }
        }
        deduped.truncate(max);

        // Stock domain detection.
        let mut stock_domains = Vec::new();
        let mut stock_seen = HashSet::new();
        for m in &deduped {
            if is_stock_domain(&m.domain) && stock_seen.insert(m.domain.clone()) {
                stock_domains.push(m.domain.clone());
            }
        }

        ReverseResult {
            matches: deduped,
            is_stock: !stock_domains.is_empty(),
            stock_domains,
            engines_used: engine_names,
            elapsed_ms: start.elapsed().as_millis() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReverseMatch;

    fn make_match(url: &str, domain: &str, engine: &str) -> ReverseMatch {
        ReverseMatch {
            page_url: url.to_owned(),
            title: String::new(),
            thumbnail: None,
            domain: domain.to_owned(),
            engine: engine.to_owned(),
            description: None,
            image_size: None,
        }
    }

    #[test]
    fn dedup_by_page_url() {
        let mut seen = HashSet::new();
        let matches = vec![
            make_match("https://a.com/1", "a.com", "google_lens"),
            make_match("https://a.com/1", "a.com", "yandex"),
            make_match("https://b.com/2", "b.com", "yandex"),
        ];
        let mut deduped = Vec::new();
        for m in matches {
            if seen.insert(m.page_url.clone()) {
                deduped.push(m);
            }
        }
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].page_url, "https://a.com/1");
        assert_eq!(deduped[0].engine, "google_lens");
        assert_eq!(deduped[1].page_url, "https://b.com/2");
    }

    #[test]
    fn stock_detection() {
        let matches = vec![
            make_match(
                "https://shutterstock.com/img/123",
                "shutterstock.com",
                "google_lens",
            ),
            make_match("https://example.com/photo", "example.com", "yandex"),
        ];
        let mut stock_domains = Vec::new();
        let mut stock_seen = HashSet::new();
        for m in &matches {
            if is_stock_domain(&m.domain) && stock_seen.insert(m.domain.clone()) {
                stock_domains.push(m.domain.clone());
            }
        }
        assert!(!stock_domains.is_empty());
        assert_eq!(stock_domains, vec!["shutterstock.com"]);
    }

    #[test]
    fn empty_results() {
        let seen: HashSet<String> = HashSet::new();
        let matches: Vec<ReverseMatch> = Vec::new();
        let deduped: Vec<&ReverseMatch> = matches
            .iter()
            .filter(|m| {
                let mut s = seen.clone();
                s.insert(m.page_url.clone())
            })
            .collect();
        assert!(deduped.is_empty());

        let stock_domains: Vec<String> = Vec::new();
        // is_stock would be false (no stock domains)
        assert!(stock_domains.is_empty());
    }

    #[tokio::test]
    async fn search_with_no_engines() {
        let engine = ReverseSearchEngine::new(vec![]);
        let client = Arc::new(HttpClient::new(ox_http::HttpConfig::default()).unwrap());
        let result = engine.search(client, "https://img.com/1.jpg", 10).await;
        assert!(result.matches.is_empty());
        assert!(!result.is_stock);
        assert!(result.engines_used.is_empty());
    }

    // --- Hard red tests ---

    #[test]
    fn multiple_stock_domains_detected() {
        let matches = vec![
            make_match("https://shutterstock.com/1", "shutterstock.com", "yandex"),
            make_match("https://gettyimages.com/2", "gettyimages.com", "yandex"),
            make_match("https://example.com/3", "example.com", "yandex"),
            make_match("https://alamy.com/4", "alamy.com", "google_lens"),
        ];
        let mut stock_domains = Vec::new();
        let mut stock_seen = HashSet::new();
        for m in &matches {
            if is_stock_domain(&m.domain) && stock_seen.insert(m.domain.clone()) {
                stock_domains.push(m.domain.clone());
            }
        }
        assert_eq!(stock_domains.len(), 3);
        assert!(stock_domains.contains(&"shutterstock.com".to_owned()));
        assert!(stock_domains.contains(&"gettyimages.com".to_owned()));
        assert!(stock_domains.contains(&"alamy.com".to_owned()));
    }

    #[test]
    fn dedup_cross_engine_keeps_first() {
        let mut seen = HashSet::new();
        let matches = vec![
            make_match("https://shared.com/photo", "shared.com", "yandex"),
            make_match("https://shared.com/photo", "shared.com", "google_lens"),
            make_match("https://unique.com/img", "unique.com", "google_lens"),
        ];
        let mut deduped = Vec::new();
        for m in matches {
            if seen.insert(m.page_url.clone()) {
                deduped.push(m);
            }
        }
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].engine, "yandex"); // first occurrence wins
    }

    #[test]
    fn all_matches_are_stock() {
        let matches = vec![
            make_match("https://shutterstock.com/1", "shutterstock.com", "yandex"),
            make_match("https://gettyimages.com/2", "gettyimages.com", "yandex"),
        ];
        let mut stock_domains = Vec::new();
        let mut stock_seen = HashSet::new();
        for m in &matches {
            if is_stock_domain(&m.domain) && stock_seen.insert(m.domain.clone()) {
                stock_domains.push(m.domain.clone());
            }
        }
        assert!(!stock_domains.is_empty()); // is_stock = true
        assert_eq!(stock_domains.len(), 2);
    }

    #[test]
    fn stock_domain_dedup_same_domain() {
        // Multiple results from same stock domain — only listed once
        let matches = vec![
            make_match("https://shutterstock.com/1", "shutterstock.com", "yandex"),
            make_match("https://shutterstock.com/2", "shutterstock.com", "yandex"),
            make_match(
                "https://shutterstock.com/3",
                "shutterstock.com",
                "google_lens",
            ),
        ];
        let mut stock_domains = Vec::new();
        let mut stock_seen = HashSet::new();
        for m in &matches {
            if is_stock_domain(&m.domain) && stock_seen.insert(m.domain.clone()) {
                stock_domains.push(m.domain.clone());
            }
        }
        assert_eq!(stock_domains.len(), 1);
        assert_eq!(stock_domains[0], "shutterstock.com");
    }

    #[test]
    fn truncation_at_max() {
        let mut seen = HashSet::new();
        let matches: Vec<ReverseMatch> = (0..50)
            .map(|i| {
                make_match(
                    &format!("https://site{i}.com/p"),
                    &format!("site{i}.com"),
                    "yandex",
                )
            })
            .collect();
        let mut deduped = Vec::new();
        for m in matches {
            if seen.insert(m.page_url.clone()) {
                deduped.push(m);
            }
        }
        deduped.truncate(20);
        assert_eq!(deduped.len(), 20);
        assert_eq!(deduped[0].domain, "site0.com");
        assert_eq!(deduped[19].domain, "site19.com");
    }
}
