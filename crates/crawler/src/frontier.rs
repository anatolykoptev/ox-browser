//! Priority URL frontier backed by [`BinaryHeap`].

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Source of a frontier entry.
#[derive(Debug, Clone)]
pub enum EntrySource {
    Bfs,
    Sitemap { lastmod: Option<String> },
}

/// A single entry in the crawl frontier.
#[derive(Debug, Clone)]
pub struct FrontierEntry {
    pub url: String,
    pub depth: u32,
    pub priority: f32,
    pub source: EntrySource,
    sequence: u64,
}

impl PartialEq for FrontierEntry {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}

impl Eq for FrontierEntry {}

impl PartialOrd for FrontierEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FrontierEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first; if equal, lower sequence (earlier) first
        self.priority
            .partial_cmp(&other.priority)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

/// Priority frontier with a maximum capacity.
#[derive(Debug)]
pub struct Frontier {
    heap: BinaryHeap<FrontierEntry>,
    max_size: usize,
    next_seq: u64,
}

impl Frontier {
    pub fn new(max_size: usize) -> Self {
        Self {
            heap: BinaryHeap::with_capacity(max_size.min(1024)),
            max_size,
            next_seq: 0,
        }
    }

    /// Push a URL with default priority (0.5) and BFS source.
    /// Backward-compatible with existing callers.
    pub fn push(&mut self, url: String, depth: u32) {
        self.push_with_priority(url, depth, 0.5, EntrySource::Bfs);
    }

    /// Push a URL with explicit priority and source.
    pub fn push_with_priority(
        &mut self,
        url: String,
        depth: u32,
        priority: f32,
        source: EntrySource,
    ) {
        if self.heap.len() >= self.max_size {
            return;
        }
        let sequence = self.next_seq;
        self.next_seq += 1;
        self.heap.push(FrontierEntry {
            url,
            depth,
            priority,
            source,
            sequence,
        });
    }

    /// Pop the highest-priority entry.
    pub fn pop(&mut self) -> Option<FrontierEntry> {
        self.heap.pop()
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bfs_order() {
        let mut f = Frontier::new(10);
        f.push("https://a.com".into(), 0);
        f.push("https://b.com".into(), 1);
        f.push("https://c.com".into(), 1);

        let first = f.pop().unwrap();
        assert_eq!(first.url, "https://a.com");
        assert_eq!(first.depth, 0);

        let second = f.pop().unwrap();
        assert_eq!(second.url, "https://b.com");
        assert_eq!(second.depth, 1);
    }

    #[test]
    fn respects_max_size() {
        let mut f = Frontier::new(2);
        f.push("https://a.com".into(), 0);
        f.push("https://b.com".into(), 0);
        f.push("https://c.com".into(), 0); // dropped
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn empty_frontier() {
        let mut f = Frontier::new(5);
        assert!(f.is_empty());
        assert!(f.pop().is_none());
    }

    #[test]
    fn priority_ordering() {
        let mut f = Frontier::new(10);
        f.push_with_priority("https://low.com".into(), 0, 0.3, EntrySource::Bfs);
        f.push_with_priority(
            "https://high.com".into(),
            0,
            0.9,
            EntrySource::Sitemap { lastmod: None },
        );
        f.push_with_priority("https://mid.com".into(), 0, 0.5, EntrySource::Bfs);

        let first = f.pop().unwrap();
        assert_eq!(first.url, "https://high.com");
        assert_eq!(first.priority, 0.9);

        let second = f.pop().unwrap();
        assert_eq!(second.url, "https://mid.com");
    }

    #[test]
    fn fifo_within_same_priority() {
        let mut f = Frontier::new(10);
        f.push_with_priority("https://first.com".into(), 0, 0.5, EntrySource::Bfs);
        f.push_with_priority("https://second.com".into(), 0, 0.5, EntrySource::Bfs);

        let first = f.pop().unwrap();
        assert_eq!(first.url, "https://first.com");
    }

    #[test]
    fn push_backward_compat() {
        let mut f = Frontier::new(10);
        f.push("https://a.com".into(), 0);
        let entry = f.pop().unwrap();
        assert_eq!(entry.priority, 0.5);
        assert!(matches!(entry.source, EntrySource::Bfs));
    }
}
