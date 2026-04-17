//! Core crawl engine — BFS crawl loop with streaming output.

use std::sync::Arc;
use std::time::Instant;

use ox_core::{Page, resolve_url};
use ox_http::HttpClient;
use tokio::sync::{Mutex, Semaphore, mpsc};
use url::Url;

use crate::budget::Budget;
use crate::config::CrawlConfig;
use crate::dedup::{ContentDedup, UrlDedup, is_cycle, normalize_url};
use crate::frontier::{EntrySource, Frontier};
use crate::markdown::html_to_fit_markdown;
use crate::result::CrawlResult;
use crate::robots::RobotsCache;
use crate::sitemap::SitemapEntry;

/// Site crawler with streaming results via mpsc channel.
pub struct Crawler {
    http: Arc<HttpClient>,
    config: CrawlConfig,
}

impl Crawler {
    pub fn new(http: Arc<HttpClient>, config: CrawlConfig) -> Self {
        Self { http, config }
    }

    /// Start crawling from a seed URL.
    ///
    /// Runs the discovery phase (sitemap/hybrid) before spawning the BFS loop.
    /// Returns a receiver for streaming results and the discovery stats.
    pub async fn crawl(
        &self,
        seed_url: &str,
    ) -> (
        mpsc::Receiver<CrawlResult>,
        crate::discovery::DiscoveryResult,
        Option<String>,
    ) {
        let (tx, rx) = mpsc::channel(self.config.concurrency * 2);
        let seed = seed_url.to_string();
        let http = Arc::clone(&self.http);
        let config = self.config.clone();

        // Discovery phase (runs before the BFS loop)
        let discovery = if config.discovery == "sitemap" || config.discovery == "hybrid" {
            crate::discovery::discover_and_resolve(&seed, &config, &http).await
        } else {
            crate::discovery::DiscoveryResult::default()
        };

        let discovery_entries = discovery.entries.clone();
        let follow_links = config.discovery != "sitemap";

        // Create output directory before spawning so callers can access it
        let output_dir = if config.save_to_file {
            let domain = url::Url::parse(&seed)
                .ok()
                .and_then(|u| u.host_str().map(String::from))
                .unwrap_or_else(|| "unknown".into());
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let dir = format!("/tmp/ox-browser/crawl/{}_{}", domain, ts);
            std::fs::create_dir_all(&dir).ok();
            Some(dir)
        } else {
            None
        };

        let output_dir_clone = output_dir.clone();
        tokio::spawn(async move {
            if let Err(e) = run_crawl(
                seed,
                http,
                config,
                tx,
                discovery_entries,
                follow_links,
                output_dir_clone,
            )
            .await
            {
                tracing::error!("crawl failed: {e}");
            }
        });

        (rx, discovery, output_dir)
    }
}

async fn run_crawl(
    seed: String,
    http: Arc<HttpClient>,
    config: CrawlConfig,
    tx: mpsc::Sender<CrawlResult>,
    discovery_entries: Vec<SitemapEntry>,
    follow_links: bool,
    output_dir: Option<String>,
) -> anyhow::Result<()> {
    let seed_url = Url::parse(&seed)?;
    let frontier = Arc::new(Mutex::new(Frontier::new(config.max_pages * 10)));
    let dedup = Arc::new(Mutex::new(UrlDedup::new()));
    let content_dedup = Arc::new(Mutex::new(ContentDedup::new()));
    let robots = Arc::new(Mutex::new(RobotsCache::new("ox-browser")));
    let budget = Arc::new(Mutex::new(Budget::new(config.budget.clone())));
    let pages_crawled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sem = Arc::new(Semaphore::new(config.concurrency));

    // Seed the frontier (skip in sitemap-only mode when we have sitemap entries)
    if follow_links || discovery_entries.is_empty() {
        let normalized = normalize_url(&seed).unwrap_or_else(|| seed.clone());
        let mut d = dedup.lock().await;
        d.insert(&normalized);
        let mut f = frontier.lock().await;
        f.push(seed, 0);
    }

    // Seed sitemap entries into frontier
    if !discovery_entries.is_empty() {
        let mut f = frontier.lock().await;
        let mut d = dedup.lock().await;
        for entry in &discovery_entries {
            if let Some(normalized) = normalize_url(&entry.url) {
                if d.insert(&normalized) {
                    let priority = entry.priority.unwrap_or(0.5);
                    let source = EntrySource::Sitemap {
                        lastmod: entry.lastmod.clone(),
                    };
                    f.push_with_priority(normalized, 0, priority, source);
                }
            }
        }
    }

    let page_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    loop {
        // Stop if receiver dropped (client disconnected).
        if tx.is_closed() {
            tracing::info!("receiver dropped, stopping crawl");
            break;
        }

        // Check page limit
        let crawled = pages_crawled.load(std::sync::atomic::Ordering::Relaxed);
        if crawled >= config.max_pages {
            tracing::info!("reached max_pages: {}", config.max_pages);
            break;
        }

        // Get next URL
        let entry = {
            let mut f = frontier.lock().await;
            f.pop()
        };

        let entry = match entry {
            Some(e) => e,
            None => {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let f = frontier.lock().await;
                if f.is_empty() && sem.available_permits() == config.concurrency {
                    break;
                }
                continue;
            }
        };

        let delay_ms = config.delay_ms;
        let permit = sem.clone().acquire_owned().await?;
        let http = Arc::clone(&http);
        let tx = tx.clone();
        let frontier = Arc::clone(&frontier);
        let dedup = Arc::clone(&dedup);
        let content_dedup = Arc::clone(&content_dedup);
        let robots = Arc::clone(&robots);
        let budget = Arc::clone(&budget);
        let seed_url = seed_url.clone();
        let task_config = config.clone();
        let pages_crawled = Arc::clone(&pages_crawled);
        let entry_source = entry.source.clone();
        let output_dir_clone = output_dir.clone();
        let page_counter = Arc::clone(&page_counter);

        tokio::spawn(async move {
            let _permit = permit;

            // Skip work if receiver already dropped.
            if tx.is_closed() {
                return;
            }

            let result = process_page(
                &entry.url,
                entry.depth,
                &http,
                &task_config,
                &seed_url,
                &frontier,
                &dedup,
                &content_dedup,
                &robots,
                &budget,
                &entry_source,
                follow_links,
                output_dir_clone,
                page_counter,
            )
            .await;

            if let Ok(ref r) = result {
                if r.error.is_none() {
                    pages_crawled.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }

            if let Ok(r) = result {
                let _ = tx.send(r).await;
            }
        });

        // Polite delay
        if delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }
    }

    // Wait for all in-flight tasks
    let _ = sem.acquire_many(config.concurrency as u32).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_page(
    url_str: &str,
    depth: u32,
    http: &HttpClient,
    config: &CrawlConfig,
    seed_url: &Url,
    frontier: &Mutex<Frontier>,
    dedup: &Mutex<UrlDedup>,
    content_dedup: &Mutex<ContentDedup>,
    robots: &Mutex<RobotsCache>,
    budget: &Mutex<Budget>,
    entry_source: &EntrySource,
    follow_links: bool,
    output_dir: Option<String>,
    page_counter: Arc<std::sync::atomic::AtomicUsize>,
) -> anyhow::Result<CrawlResult> {
    let start = Instant::now();

    // Check robots.txt (lazy load per host)
    if config.respect_robots {
        if let Ok(parsed) = Url::parse(url_str) {
            let host = parsed.host_str().unwrap_or("").to_string();
            let need_fetch = { !robots.lock().await.has_host(&host) };
            if need_fetch {
                let robots_url = format!("{}://{}/robots.txt", parsed.scheme(), host);
                let body = match http.get(&robots_url).await {
                    Ok(resp) if resp.status == 200 => Some(resp.body.into_bytes()),
                    _ => None,
                };
                let mut r = robots.lock().await;
                match body {
                    Some(b) => r.insert(&host, &b),
                    None => r.insert_unavailable(&host),
                }
            }
            if !robots.lock().await.is_allowed(&host, url_str) {
                return Ok(CrawlResult {
                    url: url_str.to_string(),
                    status: 0,
                    depth,
                    title: String::new(),
                    markdown: String::new(),
                    content_length: 0,
                    links_found: 0,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: Some("blocked by robots.txt".into()),
                    source: None,
                    sitemap_lastmod: None,
                    sitemap_priority: None,
                    file_path: None,
                });
            }
        }
    }

    // Fetch the page
    let resp = match http.get(url_str).await {
        Ok(r) => r,
        Err(e) => {
            return Ok(CrawlResult {
                url: url_str.to_string(),
                status: 0,
                depth,
                title: String::new(),
                markdown: String::new(),
                content_length: 0,
                links_found: 0,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some(format!("fetch error: {e}")),
                source: None,
                sitemap_lastmod: None,
                sitemap_priority: None,
                file_path: None,
            });
        }
    };

    // Content dedup
    {
        let mut cd = content_dedup.lock().await;
        if !cd.insert(resp.body.as_bytes()) {
            return Ok(CrawlResult {
                url: url_str.to_string(),
                status: resp.status,
                depth,
                title: String::new(),
                markdown: String::new(),
                content_length: 0,
                links_found: 0,
                elapsed_ms: start.elapsed().as_millis() as u64,
                error: Some("duplicate content".into()),
                source: None,
                sitemap_lastmod: None,
                sitemap_priority: None,
                file_path: None,
            });
        }
    }

    // Parse and extract links (scoped to drop Page before await points — Page is !Send)
    let (title, links) = {
        let page = Page::new(url_str.to_string(), resp.status, &resp.body);
        (page.title(), page.links())
    };
    let links_found = links.len();

    // Enqueue discovered links (depth check BEFORE dedup — katana pattern)
    if follow_links && depth < config.max_depth {
        for link in &links {
            if let Some(resolved) = resolve_url(url_str, &link.href) {
                if let Some(normalized) = normalize_url(&resolved) {
                    if let Ok(candidate) = Url::parse(&normalized) {
                        if candidate.scheme() != "http" && candidate.scheme() != "https" {
                            continue;
                        }
                        if !config.scope.is_allowed(seed_url, &candidate) {
                            continue;
                        }
                        if is_cycle(&normalized) {
                            continue;
                        }
                        {
                            let mut b = budget.lock().await;
                            if !b.try_consume(candidate.path()) {
                                continue;
                            }
                        }
                        {
                            let mut d = dedup.lock().await;
                            if !d.insert(&normalized) {
                                continue;
                            }
                        }
                        let mut f = frontier.lock().await;
                        f.push(normalized, depth + 1);
                    }
                }
            }
        }
    }

    // Capture status before consuming resp for markdown
    let status = resp.status;
    let content_length = resp.body.len();

    // Convert to markdown
    let markdown = if config.include_markdown {
        html_to_fit_markdown(&resp.body)
    } else {
        String::new()
    };

    // Save to file when output_dir is set
    use std::io::Write;

    let file_path = if let Some(ref dir) = output_dir {
        if !markdown.is_empty() {
            let seq = page_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let filename = format!("page_{:04}.md", seq);
            let path = format!("{}/{}", dir, filename);
            if std::fs::write(&path, &markdown).is_ok() {
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(format!("{}/index.jsonl", dir))
                {
                    let _ = writeln!(
                        f,
                        r#"{{"url":"{}","file":"{}","status":{}}}"#,
                        url_str, filename, status
                    );
                }
                Some(path)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // When saved to file, clear inline markdown
    let result_markdown = if file_path.is_some() {
        String::new()
    } else {
        markdown
    };

    Ok(CrawlResult {
        url: url_str.to_string(),
        status,
        depth,
        title,
        markdown: result_markdown,
        content_length,
        links_found,
        elapsed_ms: start.elapsed().as_millis() as u64,
        error: None,
        source: Some(match entry_source {
            EntrySource::Bfs => "bfs".into(),
            EntrySource::Sitemap { .. } => "sitemap".into(),
        }),
        sitemap_lastmod: match entry_source {
            EntrySource::Sitemap { lastmod } => lastmod.clone(),
            _ => None,
        },
        sitemap_priority: None,
        file_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::Budget;

    #[test]
    fn crawler_creates() {
        let config = CrawlConfig::default();
        let http = Arc::new(HttpClient::new(ox_http::HttpConfig::default()).unwrap());
        let _crawler = Crawler::new(http, config);
    }

    #[test]
    fn enqueue_respects_depth_before_dedup() {
        let mut dedup = UrlDedup::new();
        let mut frontier = Frontier::new(100);
        let max_depth = 2;
        let depth = 3;

        let url = "https://example.com/deep";
        if depth <= max_depth {
            let normalized = normalize_url(url).unwrap();
            if dedup.insert(&normalized) {
                frontier.push(normalized, depth);
            }
        }
        assert!(!dedup.contains(&normalize_url(url).unwrap()));
        assert!(frontier.is_empty());
    }

    #[test]
    fn full_pipeline_components_integrate() {
        let mut frontier = Frontier::new(100);
        let mut dedup = UrlDedup::new();
        let mut content_dedup = ContentDedup::new();
        let mut robots = RobotsCache::new("ox-browser");
        let mut budget = Budget::new([("*".to_string(), 10)].into());
        let scope = crate::CrawlScope::SameDomain;
        let seed = Url::parse("https://example.com").unwrap();

        let seed_url = "https://example.com/";
        dedup.insert(seed_url);
        frontier.push(seed_url.to_string(), 0);

        let links = vec![
            "https://example.com/about",
            "https://example.com/blog",
            "https://other.com/ext",
            "https://example.com/about",
        ];

        robots.insert("example.com", b"User-agent: *\nAllow: /\n");

        let mut enqueued = 0;
        for link in links {
            if let Some(normalized) = normalize_url(link) {
                if let Ok(candidate) = Url::parse(&normalized) {
                    if !scope.is_allowed(&seed, &candidate) {
                        continue;
                    }
                    if is_cycle(&normalized) {
                        continue;
                    }
                    if !budget.try_consume(candidate.path()) {
                        continue;
                    }
                    if !dedup.insert(&normalized) {
                        continue;
                    }
                    if !robots.is_allowed("example.com", &normalized) {
                        continue;
                    }
                    frontier.push(normalized, 1);
                    enqueued += 1;
                }
            }
        }

        assert_eq!(enqueued, 2);
        assert_eq!(frontier.len(), 3);
        assert!(content_dedup.insert(b"page content"));
        assert!(!content_dedup.insert(b"page content"));
    }

    #[tokio::test]
    async fn sitemap_mode_skips_seed_when_entries_exist() {
        let frontier = Frontier::new(100);
        let dedup = UrlDedup::new();
        let mut f = frontier;
        let mut d = dedup;

        let follow_links = false;
        let discovery_entries = vec![crate::sitemap::SitemapEntry {
            url: "https://example.com/page1".into(),
            lastmod: None,
            priority: Some(0.8),
            changefreq: None,
        }];

        if follow_links {
            d.insert("https://example.com/");
            f.push("https://example.com/".into(), 0);
        }

        for entry in &discovery_entries {
            if let Some(normalized) = normalize_url(&entry.url) {
                if d.insert(&normalized) {
                    f.push_with_priority(
                        normalized,
                        0,
                        entry.priority.unwrap_or(0.5),
                        EntrySource::Sitemap {
                            lastmod: entry.lastmod.clone(),
                        },
                    );
                }
            }
        }

        assert_eq!(f.len(), 1);
        let e = f.pop().unwrap();
        assert!(e.url.contains("page1"));
        assert!(matches!(e.source, EntrySource::Sitemap { .. }));
    }
}
