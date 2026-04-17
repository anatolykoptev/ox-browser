//! Parallel multi-engine image search with Weighted Reciprocal Rank fusion.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::task::JoinSet;

use crate::{ImageEngine, ImageResult};
use ox_http::HttpClient;

/// Constant for Reciprocal Rank Fusion scoring.
const RRF_K: f64 = 60.0;

/// Multi-engine image search with parallel execution and WRR fusion.
pub struct ImageSearchEngine {
    engines: Vec<Arc<dyn ImageEngine>>,
}

impl ImageSearchEngine {
    pub fn new(engines: Vec<Arc<dyn ImageEngine>>) -> Self {
        Self { engines }
    }

    /// Search all engines in parallel and fuse results via WRR.
    pub async fn search(
        &self,
        client: Arc<HttpClient>,
        query: &str,
        max: usize,
    ) -> Vec<ImageResult> {
        let mut set = JoinSet::new();

        for engine in &self.engines {
            let engine = Arc::clone(engine);
            let client = Arc::clone(&client);
            let query = query.to_owned();
            set.spawn(async move {
                match engine.search(&client, &query, max).await {
                    Ok(results) => results,
                    Err(e) => {
                        tracing::warn!(
                            engine = engine.name(),
                            error = %e,
                            "image search failed"
                        );
                        Vec::new()
                    }
                }
            });
        }

        let mut all_sets = Vec::new();
        while let Some(Ok(results)) = set.join_next().await {
            all_sets.push(results);
        }

        let mut fused = fuse_wrr(all_sets);
        fused.truncate(max);
        fused
    }
}

/// Weighted Reciprocal Rank Fusion: merge results from multiple engines,
/// dedup by URL, accumulate rank-based scores.
pub fn fuse_wrr(result_sets: Vec<Vec<ImageResult>>) -> Vec<ImageResult> {
    if result_sets.is_empty() {
        return Vec::new();
    }

    let mut scores: HashMap<String, (ImageResult, f64)> = HashMap::new();
    let mut order: Vec<String> = Vec::new();

    for set in &result_sets {
        for (rank, r) in set.iter().enumerate() {
            if r.url.is_empty() {
                continue;
            }
            let rrf = 1.0 / (RRF_K + rank as f64);
            if let Some(entry) = scores.get_mut(&r.url) {
                entry.1 += rrf;
            } else {
                order.push(r.url.clone());
                scores.insert(r.url.clone(), (r.clone(), rrf));
            }
        }
    }

    let mut merged: Vec<(ImageResult, f64)> = order
        .into_iter()
        .filter_map(|url| scores.remove(&url))
        .collect();
    merged.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    merged.into_iter().map(|(r, _)| r).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuse_wrr_dedup_by_url() {
        let set_a = vec![
            ImageResult {
                url: "https://a.com/1.jpg".into(),
                engine: "bing".into(),
                ..Default::default()
            },
            ImageResult {
                url: "https://a.com/2.jpg".into(),
                engine: "bing".into(),
                ..Default::default()
            },
        ];
        let set_b = vec![
            ImageResult {
                url: "https://a.com/1.jpg".into(),
                engine: "ddg".into(),
                title: "DDG title".into(),
                ..Default::default()
            },
            ImageResult {
                url: "https://b.com/3.jpg".into(),
                engine: "ddg".into(),
                ..Default::default()
            },
        ];
        let fused = fuse_wrr(vec![set_a, set_b]);
        assert_eq!(fused.len(), 3);
        // URL 1.jpg appears in both sets -> highest score -> first
        assert_eq!(fused[0].url, "https://a.com/1.jpg");
    }

    #[test]
    fn fuse_wrr_empty() {
        assert!(fuse_wrr(vec![]).is_empty());
        assert!(fuse_wrr(vec![vec![]]).is_empty());
    }

    #[test]
    fn fuse_wrr_single_set() {
        let set = vec![
            ImageResult {
                url: "https://a.jpg".into(),
                ..Default::default()
            },
            ImageResult {
                url: "https://b.jpg".into(),
                ..Default::default()
            },
        ];
        let fused = fuse_wrr(vec![set]);
        assert_eq!(fused.len(), 2);
        assert_eq!(fused[0].url, "https://a.jpg");
    }

    #[test]
    fn fuse_wrr_skips_empty_url() {
        let set = vec![
            ImageResult {
                url: "".into(),
                ..Default::default()
            },
            ImageResult {
                url: "https://real.jpg".into(),
                ..Default::default()
            },
        ];
        let fused = fuse_wrr(vec![set]);
        assert_eq!(fused.len(), 1);
        assert_eq!(fused[0].url, "https://real.jpg");
    }
}
