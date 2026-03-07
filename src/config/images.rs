//! Image search and extraction defaults.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ImagesSection {
    /// Default max results for /images/search. Caller can override per-request.
    pub default_max_results: usize,
    /// Default min width for /images/extract (pixels). Caller can override.
    pub default_min_width: u32,
    /// Minimum image dimension (px) to keep during extraction. Below this = filtered out.
    pub min_dimension: u32,
    /// Reciprocal Rank Fusion constant for multi-engine result merging.
    pub rrf_k: f64,
}

impl Default for ImagesSection {
    fn default() -> Self {
        Self {
            default_max_results: 10,
            default_min_width: 400,
            min_dimension: 200,
            rrf_k: 60.0,
        }
    }
}
