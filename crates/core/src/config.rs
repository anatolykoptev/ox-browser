use std::time::Duration;

#[derive(Debug, Clone)]
pub struct BrowserConfig {
    pub timeout: Duration,
    pub user_agent: String,
    pub proxy_url: Option<String>,
    pub max_redirects: usize,
    pub concurrency: usize,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            user_agent: format!("ox-browser/{}", env!("CARGO_PKG_VERSION")),
            proxy_url: None,
            max_redirects: 10,
            concurrency: 3,
        }
    }
}
