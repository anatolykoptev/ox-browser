use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Semaphore;

use crate::Result;

pub struct Pool {
    sem: Semaphore,
    closed: AtomicBool,
}

impl Pool {
    pub fn new(size: usize) -> Self {
        Self {
            sem: Semaphore::new(size),
            closed: AtomicBool::new(false),
        }
    }

    pub async fn acquire(&self) -> Result<PoolGuard<'_>> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(crate::BrowserError::Navigate("pool closed".into()));
        }
        let permit = self
            .sem
            .acquire()
            .await
            .map_err(|_| crate::BrowserError::Navigate("pool closed".into()))?;
        Ok(PoolGuard { _permit: permit })
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.sem.close();
    }
}

pub struct PoolGuard<'a> {
    _permit: tokio::sync::SemaphorePermit<'a>,
}
