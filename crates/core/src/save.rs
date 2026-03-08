//! Save fetch responses to files for LLM-friendly output.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

const DEFAULT_OUTPUT_DIR: &str = "/tmp/ox-browser";

/// Save response body to a file, return the file path.
///
/// File naming: `{domain}_{hash16}.html`
/// Directory: `OUTPUT_DIR` env var or `/tmp/ox-browser`.
pub fn save_response(url: &str, body: &str) -> std::io::Result<PathBuf> {
    let dir = output_dir();
    std::fs::create_dir_all(&dir)?;

    let domain = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_else(|| "unknown".into());

    let hash = {
        let mut h = DefaultHasher::new();
        url.hash(&mut h);
        format!("{:016x}", h.finish())
    };

    let filename = format!("{}_{}.html", sanitize_domain(&domain), hash);
    let path = dir.join(filename);
    std::fs::write(&path, body)?;

    tracing::debug!(path = %path.display(), bytes = body.len(), "saved response");
    Ok(path)
}

fn output_dir() -> PathBuf {
    std::env::var("OUTPUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(DEFAULT_OUTPUT_DIR).to_path_buf())
}

fn sanitize_domain(domain: &str) -> String {
    domain
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn save_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("OUTPUT_DIR", dir.path());

        let path = save_response("https://example.com/page", "<html>test</html>").unwrap();
        assert!(path.exists());
        assert_eq!(fs::read_to_string(&path).unwrap(), "<html>test</html>");
        assert!(path.file_name().unwrap().to_str().unwrap().starts_with("example.com_"));

        std::env::remove_var("OUTPUT_DIR");
    }

    #[test]
    fn sanitize_domain_works() {
        assert_eq!(sanitize_domain("example.com"), "example.com");
        assert_eq!(sanitize_domain("a/b:c"), "a_b_c");
    }
}
