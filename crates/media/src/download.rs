use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use crate::MediaError;

const MEDIA_DIR: &str = "/tmp/ox-browser/media";
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

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
pub async fn download_to_file(
    url: &str,
    dest: &Path,
    max_size_bytes: u64,
    proxy_url: &str,
) -> Result<u64, MediaError> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| MediaError::DownloadFailed(format!("create dir: {e}")))?;
    }

    let part_path = dest.with_extension("part");

    let mut builder = wreq::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT);
    if !proxy_url.is_empty() {
        let proxy = wreq::Proxy::all(proxy_url)
            .map_err(|e| MediaError::DownloadFailed(format!("proxy: {e}")))?;
        builder = builder.proxy(proxy);
    }
    let client = builder
        .build()
        .map_err(|e| MediaError::DownloadFailed(format!("client: {e}")))?;

    let response = client
        .get(url)
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
    mut response: wreq::Response,
    path: &Path,
    max_size_bytes: u64,
) -> Result<u64, MediaError> {
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|e| MediaError::DownloadFailed(format!("create file: {e}")))?;

    let mut written: u64 = 0;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| MediaError::DownloadFailed(format!("read chunk: {e}")))?
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_path_generates_correct_format() {
        let path = media_path("yt", "https://youtube.com/watch?v=abc123", "mp4");
        assert!(path.to_str().unwrap().starts_with("/tmp/ox-browser/media/yt_"));
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
}
