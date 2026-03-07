//! BFS URL frontier backed by [`VecDeque`].

use std::collections::VecDeque;

/// A single entry in the crawl frontier.
#[derive(Debug, Clone)]
pub struct FrontierEntry {
    pub url: String,
    pub depth: u32,
}

/// FIFO frontier with a maximum capacity.
#[derive(Debug)]
pub struct Frontier {
    queue: VecDeque<FrontierEntry>,
    max_size: usize,
}

impl Frontier {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(max_size.min(1024)),
            max_size,
        }
    }

    /// Push a URL at the given depth. Silently drops if at capacity.
    pub fn push(&mut self, url: String, depth: u32) {
        if self.queue.len() >= self.max_size {
            return;
        }
        self.queue.push_back(FrontierEntry { url, depth });
    }

    /// Pop the next entry (FIFO / BFS order).
    pub fn pop(&mut self) -> Option<FrontierEntry> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
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
}
