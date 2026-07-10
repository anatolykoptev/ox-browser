//! Discovery mode coordinator — finds and resolves sitemaps.

use std::collections::HashSet;
use std::sync::Arc;

use ox_http::HttpClient;
use url::Url;

use crate::config::CrawlConfig;
use crate::sitemap::{self, SitemapContent, SitemapEntry};

/// Result of sitemap discovery phase.
#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub entries: Vec<SitemapEntry>,
    pub sitemaps_found: usize,
    pub urls_total: usize,
    pub urls_filtered: usize,
}

/// Discover and resolve sitemaps for the given seed URL.
pub async fn discover_and_resolve(
    seed_url: &str,
    config: &CrawlConfig,
    http: &Arc<HttpClient>,
) -> DiscoveryResult {
    let sitemap_urls = find_sitemaps(seed_url, config, http).await;
    if sitemap_urls.is_empty() {
        tracing::info!("no sitemaps found");
        return DiscoveryResult::default();
    }

    let max_depth = if config.sitemap_max_depth == 0 {
        u32::MAX
    } else {
        config.sitemap_max_depth
    };

    let mut seen = HashSet::new();
    let mut all_entries = Vec::new();
    let mut sitemaps_found = 0usize;

    resolve_recursive(
        &sitemap_urls,
        0,
        max_depth,
        config.sitemap_max_files,
        &config.sitemap_filter,
        http,
        &mut seen,
        &mut all_entries,
        &mut sitemaps_found,
    )
    .await;

    let urls_total = all_entries.len();

    // Apply since filter
    let entries = match &config.sitemap_since {
        Some(since) => sitemap::filter_since(all_entries, since),
        None => all_entries,
    };
    let urls_filtered = urls_total - entries.len();

    tracing::info!(
        sitemaps_found,
        urls_total,
        urls_filtered,
        urls_kept = entries.len(),
        "sitemap discovery complete"
    );

    DiscoveryResult {
        entries,
        sitemaps_found,
        urls_total,
        urls_filtered,
    }
}

async fn find_sitemaps(
    seed_url: &str,
    config: &CrawlConfig,
    http: &Arc<HttpClient>,
) -> Vec<String> {
    // 1. Explicit URL
    if let Some(ref url) = config.sitemap_url {
        return vec![url.clone()];
    }

    let origin = match Url::parse(seed_url) {
        Ok(u) => format!("{}://{}", u.scheme(), u.host_str().unwrap_or("")),
        Err(_) => return Vec::new(),
    };

    // 2. Try robots.txt
    let robots_url = format!("{origin}/robots.txt");
    if let Ok(resp) = http.get(&robots_url).await
        && resp.status == 200
    {
        let urls = crate::robots::extract_sitemaps(resp.body.as_bytes());
        if !urls.is_empty() {
            tracing::info!(count = urls.len(), "found sitemaps in robots.txt");
            return urls;
        }
    }

    // 3. Try standard paths
    for path in ["/sitemap.xml", "/sitemap_index.xml"] {
        let url = format!("{origin}{path}");
        if let Ok(resp) = http.get(&url).await
            && resp.status == 200
            && resp.body.contains('<')
        {
            tracing::info!(url = %url, "found sitemap at standard path");
            return vec![url];
        }
    }

    Vec::new()
}

#[allow(clippy::too_many_arguments)]
async fn resolve_recursive(
    urls: &[String],
    depth: u32,
    max_depth: u32,
    max_files: usize,
    filter: &[String],
    http: &Arc<HttpClient>,
    seen: &mut HashSet<String>,
    entries: &mut Vec<SitemapEntry>,
    sitemaps_found: &mut usize,
) {
    for url in urls {
        if *sitemaps_found >= max_files {
            tracing::warn!(max_files, "sitemap file limit reached");
            return;
        }
        if !seen.insert(url.clone()) {
            continue; // cycle protection
        }

        let resp = match http.get(url).await {
            Ok(r) if r.status == 200 => r,
            _ => {
                tracing::warn!(url, "failed to fetch sitemap");
                continue;
            }
        };

        *sitemaps_found += 1;

        match sitemap::parse_sitemap(resp.body.as_bytes()) {
            Ok(SitemapContent::UrlSet(mut page_entries)) => {
                entries.append(&mut page_entries);
            }
            Ok(SitemapContent::Index(nested_urls)) => {
                if depth >= max_depth {
                    tracing::warn!(depth, max_depth, "sitemap index depth limit reached");
                    continue;
                }
                // Apply sitemap_filter
                let filtered: Vec<String> = if filter.is_empty() {
                    nested_urls
                } else {
                    nested_urls
                        .into_iter()
                        .filter(|u| filter.iter().any(|f| u.contains(f)))
                        .collect()
                };

                Box::pin(resolve_recursive(
                    &filtered,
                    depth + 1,
                    max_depth,
                    max_files,
                    filter,
                    http,
                    seen,
                    entries,
                    sitemaps_found,
                ))
                .await;
            }
            Err(e) => {
                tracing::warn!(url, error = %e, "failed to parse sitemap");
            }
        }
    }
}
