use std::time::Duration;

pub struct HttpConfig {
    pub timeout: Duration,
    pub user_agent: String,
    pub proxy_url: Option<String>,
    pub max_redirects: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            user_agent: format!("ox-browser/{}", env!("CARGO_PKG_VERSION")),
            proxy_url: None,
            max_redirects: 10,
        }
    }
}
