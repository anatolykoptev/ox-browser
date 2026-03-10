use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::download::media_dir;

const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600); // 7 days
const CLEANUP_INTERVAL: Duration = Duration::from_secs(24 * 3600); // 24h

/// Spawn a background task that deletes media files older than 7 days.
/// Runs every 24 hours.
pub fn spawn_cleanup_task() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(CLEANUP_INTERVAL).await;
            let dir = media_dir();
            cleanup_old_files(&dir, MAX_AGE);
        }
    });
}

fn cleanup_old_files(dir: &Path, max_age: Duration) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let now = SystemTime::now();
    let mut removed = 0u32;

    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        if let Ok(age) = now.duration_since(modified)
            && age > max_age
        {
            let _ = std::fs::remove_file(entry.path());
            removed += 1;
        }
    }

    if removed > 0 {
        tracing::info!(removed, "cleaned up old media files");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn cleanup_removes_old_files() {
        let dir = tempfile::tempdir().unwrap();
        let old_file = dir.path().join("old.mp4");
        let new_file = dir.path().join("new.mp4");

        fs::write(&old_file, b"old").unwrap();
        fs::write(&new_file, b"new").unwrap();

        // max_age=0 means all files are "old"
        cleanup_old_files(dir.path(), Duration::ZERO);

        assert!(!old_file.exists());
        assert!(!new_file.exists());
    }

    #[test]
    fn cleanup_keeps_recent_files() {
        let dir = tempfile::tempdir().unwrap();
        let recent = dir.path().join("recent.mp4");
        fs::write(&recent, b"fresh").unwrap();

        // max_age = 1 hour — file was just created so it should stay
        cleanup_old_files(dir.path(), Duration::from_secs(3600));

        assert!(recent.exists());
    }

    #[test]
    fn cleanup_handles_missing_dir() {
        // Should not panic on non-existent directory
        cleanup_old_files(Path::new("/tmp/nonexistent_ox_test_dir"), Duration::ZERO);
    }
}
