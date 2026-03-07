//! URL and content deduplication.
//!
//! - [`UrlDedup`] tracks seen URLs via xxHash (xxh3_64).
//! - [`ContentDedup`] tracks seen page bodies via blake3.
//! - [`normalize_url`] canonicalizes URLs for dedup comparison.
//! - [`is_cycle`] detects crawler traps (repeating paths, extreme length).

use std::collections::HashSet;

use url::Url;
use xxhash_rust::xxh3::xxh3_64;

// ---------------------------------------------------------------------------
// URL dedup
// ---------------------------------------------------------------------------

/// Fast URL deduplication backed by xxHash-64.
#[derive(Debug, Default)]
pub struct UrlDedup {
    seen: HashSet<u64>,
}

impl UrlDedup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a **normalized** URL. Returns `true` if it was new.
    pub fn insert(&mut self, normalized_url: &str) -> bool {
        let hash = xxh3_64(normalized_url.as_bytes());
        self.seen.insert(hash)
    }

    pub fn contains(&self, normalized_url: &str) -> bool {
        let hash = xxh3_64(normalized_url.as_bytes());
        self.seen.contains(&hash)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Content dedup
// ---------------------------------------------------------------------------

/// Content deduplication backed by blake3.
#[derive(Debug, Default)]
pub struct ContentDedup {
    seen: HashSet<[u8; 32]>,
}

impl ContentDedup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert content bytes. Returns `true` if the content was new.
    pub fn insert(&mut self, content: &[u8]) -> bool {
        let hash = blake3::hash(content);
        self.seen.insert(*hash.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// URL normalization
// ---------------------------------------------------------------------------

/// Normalize a URL for dedup comparison:
/// - Strip fragment (`#...`).
/// - Sort query parameters alphabetically.
/// - Lowercase scheme and host.
///
/// Returns `None` for unparseable URLs.
pub fn normalize_url(raw: &str) -> Option<String> {
    let mut parsed = Url::parse(raw).ok()?;

    // Strip fragment.
    parsed.set_fragment(None);

    // Sort query params.
    let mut pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    if pairs.is_empty() {
        parsed.set_query(None);
    } else {
        pairs.sort();
        let qs: Vec<String> = pairs
            .iter()
            .map(|(k, v)| {
                if v.is_empty() {
                    k.clone()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect();
        parsed.set_query(Some(&qs.join("&")));
    }

    Some(parsed.to_string())
}

// ---------------------------------------------------------------------------
// Cycle detection
// ---------------------------------------------------------------------------

const MAX_URL_LENGTH: usize = 2048;

/// Detect crawler traps:
/// - URL longer than 2048 bytes.
/// - Repeating path segments (e.g. `/a/b/a/b/a/b`).
pub fn is_cycle(url: &str) -> bool {
    if url.len() > MAX_URL_LENGTH {
        return true;
    }

    let path = match Url::parse(url) {
        Ok(u) => u.path().to_string(),
        Err(_) => return false,
    };

    let segments: Vec<&str> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if segments.len() < 4 {
        return false;
    }

    // Check for repeating patterns of length 1..=segments.len()/2.
    for pattern_len in 1..=segments.len() / 2 {
        if segments.len() % pattern_len != 0 {
            continue;
        }
        let pattern = &segments[..pattern_len];
        let repeats = segments
            .chunks(pattern_len)
            .all(|chunk| chunk == pattern);
        if repeats && segments.len() / pattern_len >= 2 {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_dedup_inserts_and_detects() {
        let mut d = UrlDedup::new();
        assert!(d.insert("https://example.com/"));
        assert!(!d.insert("https://example.com/"));
        assert!(d.insert("https://example.com/other"));
        assert_eq!(d.len(), 2);
        assert!(d.contains("https://example.com/"));
        assert!(!d.contains("https://never-seen.com/"));
    }

    #[test]
    fn content_dedup_detects_duplicates() {
        let mut d = ContentDedup::new();
        assert!(d.insert(b"hello world"));
        assert!(!d.insert(b"hello world"));
        assert!(d.insert(b"different content"));
    }

    #[test]
    fn normalize_strips_fragment() {
        let n = normalize_url("https://example.com/page#section").unwrap();
        assert_eq!(n, "https://example.com/page");
    }

    #[test]
    fn normalize_sorts_query_params() {
        let n = normalize_url("https://example.com/?z=1&a=2&m=3").unwrap();
        assert_eq!(n, "https://example.com/?a=2&m=3&z=1");
    }

    #[test]
    fn normalize_handles_invalid_url() {
        assert!(normalize_url("not a url at all").is_none());
    }

    #[test]
    fn cycle_detects_repeating_paths() {
        assert!(is_cycle("https://example.com/a/b/a/b"));
        assert!(is_cycle("https://example.com/x/y/z/x/y/z"));
        assert!(!is_cycle("https://example.com/a/b/c/d"));
    }

    #[test]
    fn cycle_detects_long_urls() {
        let long = format!("https://example.com/{}", "a".repeat(2100));
        assert!(is_cycle(&long));
    }
}
