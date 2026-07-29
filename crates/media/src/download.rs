use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::StreamExt;
use ox_http::BrowserProfile;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use crate::MediaError;

const MEDIA_DIR: &str = "/tmp/ox-browser/media";
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Soft cap on the media tmpfs directory size. When `current + incoming +
/// MIN_FREE_BYTES` exceeds this, downloads are refused before any bytes are
/// written to disk (issue #30, resource_exhaustion).
const MEDIA_DIR_CAP_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GB

/// Headroom kept free on the tmpfs below the cap. A download is refused if it
/// would leave less than this free, so the container always has room for logs
/// and other runtime files.
const MIN_FREE_BYTES: u64 = 100 * 1024 * 1024; // 100 MB

/// Returns the base directory for media files.
pub fn media_dir() -> PathBuf {
    PathBuf::from(MEDIA_DIR)
}

/// Generates a deterministic file path: `{MEDIA_DIR}/{platform}_{sha256(url)[:8]}.{ext}`
pub fn media_path(platform: &str, url: &str, ext: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let hash = hex::encode(hasher.finalize());
    let short_hash = &hash[..8];
    media_dir().join(format!("{platform}_{short_hash}.{ext}"))
}

/// Streaming download with size limit.
///
/// Downloads to a `.part` file first, renames on success, cleans up on error.
/// Optional `proxy_url` for sites that block datacenter IPs.
/// Returns total bytes written.
///
/// `profile` is the browser identity the originating page fetch used (threaded
/// from `orchestrator::download` via `HttpClient::config().profile`, falling
/// back to `platform_matched_profile()`). The client carries the profile's
/// TLS/HTTP2 fingerprint, and the request carries the profile's headers
/// (User-Agent + client hints in Chrome wire order) via `browser_headers` —
/// so a WAF that saw Chrome fetch the page sees the same Chrome fetch the
/// images/video. There is no code path that sets a mismatched UA on this
/// request (issue #101 / PR #97's incoherence-unrepresentable property).
pub async fn download_to_file(
    url: &str,
    dest: &Path,
    max_size_bytes: u64,
    proxy_url: &str,
    profile: &BrowserProfile,
) -> Result<u64, MediaError> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| MediaError::DownloadFailed(format!("create dir: {e}")))?;

        // Refuse before any network I/O if the media tmpfs is already near its
        // cap — a burst of large downloads could fill tmpfs before the hourly
        // cleanup sweep fires (issue #30, resource_exhaustion).
        check_quota(parent, max_size_bytes, MEDIA_DIR_CAP_BYTES)?;
    }

    // Pre-resolve tier: catches a literal-IP or bad-scheme target before
    // even constructing the client. `crate::http::build_client` layers the
    // connect-time + redirect-hop guards on top (see its doc comment) — the
    // two together give this download path the same coverage as
    // `ox_http::HttpClient`'s middleware chain + wreq client combination.
    ox_http::validate_url(url)
        .map_err(|e| MediaError::DownloadFailed(format!("blocked target: {e}")))?;

    let part_path = dest.with_extension("part");

    let client = crate::http::build_client(profile, proxy_url, DOWNLOAD_TIMEOUT, "download")?;

    // Apply the profile's headers (UA + client hints in Chrome wire order).
    // The client carries the matching TLS/HTTP2 emulation, so the request is
    // a coherent browser fetch — same identity as the page fetch that
    // extracted this media URL.
    let mut request = client.get(url);
    for (name, value) in ox_http::browser_headers(profile) {
        request = request.header(name.as_str(), value.as_str());
    }

    let response = request
        .send()
        .await
        .map_err(|e| MediaError::DownloadFailed(format!("request: {e}")))?;

    if !response.status().is_success() {
        return Err(MediaError::DownloadFailed(format!(
            "HTTP {}",
            response.status()
        )));
    }

    // Check Content-Length if present
    if let Some(cl) = response.content_length() {
        if cl > max_size_bytes {
            return Err(MediaError::SizeExceeded(format!(
                "{cl} bytes exceeds limit of {max_size_bytes}"
            )));
        }
        debug!(content_length = cl, "starting download");
    }

    let result = stream_to_file(response, &part_path, max_size_bytes).await;

    match result {
        Ok(bytes) => {
            tokio::fs::rename(&part_path, dest)
                .await
                .map_err(|e| MediaError::DownloadFailed(format!("rename: {e}")))?;
            debug!(bytes, path = %dest.display(), "download complete");
            Ok(bytes)
        }
        Err(e) => {
            if let Err(rm_err) = tokio::fs::remove_file(&part_path).await {
                warn!("failed to remove partial file: {rm_err}");
            }
            Err(e)
        }
    }
}

/// Stream response body to file, checking size limit per chunk.
async fn stream_to_file(
    response: wreq::Response,
    path: &Path,
    max_size_bytes: u64,
) -> Result<u64, MediaError> {
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|e| MediaError::DownloadFailed(format!("create file: {e}")))?;

    let mut written: u64 = 0;

    // wreq 6.0.0-rc.29 dropped `Response::chunk()`. Stream via `bytes_stream()`.
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| MediaError::DownloadFailed(format!("read chunk: {e}")))?;
        written += chunk.len() as u64;
        if written > max_size_bytes {
            return Err(MediaError::SizeExceeded(format!(
                "{written} bytes exceeds limit of {max_size_bytes}"
            )));
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| MediaError::DownloadFailed(format!("write: {e}")))?;
    }

    file.flush()
        .await
        .map_err(|e| MediaError::DownloadFailed(format!("flush: {e}")))?;

    Ok(written)
}

/// Sum the sizes of all regular files under `dir` (recursive). Returns 0 if
/// the directory does not exist or cannot be read — a missing media dir is
/// not an error here, it just means zero bytes in use.
fn dir_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_file() {
            total += meta.len();
        } else if meta.is_dir() {
            total += dir_size(&entry.path());
        }
    }
    total
}

/// Check whether writing `incoming_bytes` into `dir` would breach the tmpfs
/// `cap_bytes`. Publishes the `oxbrowser_media_tmpfs_bytes` gauge with the
/// current dir size so operators can see near-capacity state (issue #30).
/// Returns `Ok(())` if there is room, or a `MediaError::DownloadFailed` with
/// a clear "storage full" message if the download would exhaust tmpfs.
fn check_quota(dir: &Path, incoming_bytes: u64, cap_bytes: u64) -> Result<(), MediaError> {
    let current = dir_size(dir);
    ox_http::metrics::set_gauge(&ox_http::metrics::MEDIA_TMPFS_BYTES, current);
    if current + incoming_bytes + MIN_FREE_BYTES > cap_bytes {
        warn!(
            current_bytes = current,
            incoming_bytes,
            cap_bytes,
            min_free_bytes = MIN_FREE_BYTES,
            "media tmpfs near capacity, refusing download to avoid exhaustion"
        );
        return Err(MediaError::DownloadFailed(format!(
            "storage full: media dir {current}/{cap_bytes} bytes, need {incoming_bytes} more, \
             refusing to avoid tmpfs exhaustion"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    /// Quota tests publish the shared process-global `MEDIA_TMPFS_BYTES`
    /// gauge. When run in parallel they race on that atomic, producing flaky
    /// assertions. This mutex serializes them so the gauge value is
    /// deterministic within each test — mirrors the T2 metrics gauge pattern.
    static QUOTA_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn media_path_generates_correct_format() {
        let path = media_path("yt", "https://youtube.com/watch?v=abc123", "mp4");
        assert!(
            path.to_str()
                .unwrap()
                .starts_with("/tmp/ox-browser/media/yt_")
        );
        assert!(path.to_str().unwrap().ends_with(".mp4"));
        // hash is deterministic
        let path2 = media_path("yt", "https://youtube.com/watch?v=abc123", "mp4");
        assert_eq!(path, path2);
        // different URL = different hash
        let path3 = media_path("yt", "https://youtube.com/watch?v=xyz789", "mp4");
        assert_ne!(path, path3);
    }

    #[test]
    fn media_path_different_platforms() {
        let yt = media_path("yt", "https://example.com/v", "mp4");
        let generic = media_path("generic", "https://example.com/v", "mp4");
        assert!(yt.to_str().unwrap().contains("yt_"));
        assert!(generic.to_str().unwrap().contains("generic_"));
    }

    #[test]
    fn dir_size_sums_all_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.mp4"), vec![0u8; 100]).unwrap();
        fs::write(dir.path().join("b.mp4"), vec![0u8; 250]).unwrap();
        // nested subdir is included (recursive)
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/c.mp4"), vec![0u8; 50]).unwrap();
        assert_eq!(dir_size(dir.path()), 400);
    }

    #[test]
    fn dir_size_missing_dir_is_zero() {
        assert_eq!(dir_size(Path::new("/tmp/nonexistent_ox_quota_test")), 0);
    }

    /// RED test for issue #30: pre-fill the media dir to a fake quota, attempt
    /// a download, assert it is refused with a clear "storage full" error.
    #[test]
    fn quota_check_refuses_when_near_capacity() {
        let _guard = QUOTA_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // cap = 1000 bytes, headroom = 100 (MIN_FREE_BYTES is const; use a
        // cap small enough that the pre-filled 900 + incoming 50 + 100 > 1000).
        // MIN_FREE_BYTES is 100 MB which dwarfs any tempdir test, so instead
        // verify the refusal logic with a cap that is itself under headroom:
        // current(900) + incoming(50) + MIN_FREE_BYTES > cap(1000) is always
        // true because MIN_FREE_BYTES alone exceeds 1000. That proves the
        // guard fires; the next test proves it does NOT fire when room exists.
        fs::write(dir.path().join("big.mp4"), vec![0u8; 900]).unwrap();
        let err = check_quota(dir.path(), 50, 1000).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("storage full"),
            "expected 'storage full' in error, got: {msg}"
        );
        assert!(
            msg.contains("900") && msg.contains("1000"),
            "error should report current/cap, got: {msg}"
        );
    }

    /// issue #30: when there is ample room the quota check must pass and the
    /// gauge must reflect the current dir size.
    #[test]
    fn quota_check_allows_when_room_available() {
        let _guard = QUOTA_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("small.mp4"), vec![0u8; 500]).unwrap();
        // cap well above current + incoming + headroom
        let cap = 500 + 10 + MIN_FREE_BYTES + 1;
        check_quota(dir.path(), 10, cap).unwrap();
        // gauge reflects current dir size
        assert_eq!(
            ox_http::metrics::MEDIA_TMPFS_BYTES.load(Ordering::Relaxed),
            500
        );
        // reset to avoid leaking state
        ox_http::metrics::set_gauge(&ox_http::metrics::MEDIA_TMPFS_BYTES, 0);
    }

    /// issue #30: the gauge must be published even when the download is
    /// refused, so operators can see the near-capacity state that triggered
    /// the refusal.
    #[test]
    fn quota_check_publishes_gauge_on_refusal() {
        let _guard = QUOTA_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("fill.mp4"), vec![0u8; 750]).unwrap();
        let _ = check_quota(dir.path(), 100, 1000);
        assert_eq!(
            ox_http::metrics::MEDIA_TMPFS_BYTES.load(Ordering::Relaxed),
            750,
            "gauge must reflect dir size even on refusal"
        );
        ox_http::metrics::set_gauge(&ox_http::metrics::MEDIA_TMPFS_BYTES, 0);
    }
}
