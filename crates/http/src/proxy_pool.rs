use std::sync::atomic::{AtomicUsize, Ordering};

/// A pool of proxy URLs that supports round-robin selection.
pub trait ProxyPool: Send + Sync {
    /// Returns the next proxy URL, or `None` if the pool is empty.
    fn next(&self) -> Option<String>;

    /// Returns the total number of proxies in the pool.
    fn len(&self) -> usize;

    /// Returns `true` if the pool contains no proxies.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A simple pool with a fixed list of proxies and round-robin rotation.
pub struct StaticPool {
    proxies: Vec<String>,
    counter: AtomicUsize,
}

impl StaticPool {
    /// Creates a new static proxy pool from the given list of proxy URLs.
    pub fn new(proxies: Vec<String>) -> Self {
        Self {
            proxies,
            counter: AtomicUsize::new(0),
        }
    }
}

impl ProxyPool for StaticPool {
    fn next(&self) -> Option<String> {
        if self.proxies.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.proxies.len();
        Some(self.proxies[idx].clone())
    }

    fn len(&self) -> usize {
        self.proxies.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_pool_round_robin() {
        let pool = StaticPool::new(vec![
            "http://proxy1:8080".into(),
            "http://proxy2:8080".into(),
            "http://proxy3:8080".into(),
        ]);

        assert_eq!(pool.len(), 3);
        assert!(!pool.is_empty());

        assert_eq!(pool.next().unwrap(), "http://proxy1:8080");
        assert_eq!(pool.next().unwrap(), "http://proxy2:8080");
        assert_eq!(pool.next().unwrap(), "http://proxy3:8080");
        // Wraps around.
        assert_eq!(pool.next().unwrap(), "http://proxy1:8080");
    }

    #[test]
    fn static_pool_empty() {
        let pool = StaticPool::new(vec![]);

        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
        assert!(pool.next().is_none());
    }

    #[test]
    fn static_pool_single_proxy() {
        let pool = StaticPool::new(vec!["http://single:1234".into()]);

        assert_eq!(pool.len(), 1);
        assert_eq!(pool.next().unwrap(), "http://single:1234");
        assert_eq!(pool.next().unwrap(), "http://single:1234");
    }
}
