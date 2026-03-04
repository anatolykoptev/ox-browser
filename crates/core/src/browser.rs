use crate::{BrowserConfig, Page, Pool, Result};
use ox_http::{HttpClient, HttpConfig};

pub struct Browser {
    http: HttpClient,
    pool: Pool,
    #[allow(dead_code)]
    config: BrowserConfig,
}

impl Browser {
    pub fn new(config: BrowserConfig) -> Result<Self> {
        let http_config = HttpConfig {
            timeout: config.timeout,
            user_agent: config.user_agent.clone(),
            proxy_url: config.proxy_url.clone(),
            max_redirects: config.max_redirects,
            ..HttpConfig::default()
        };
        let http = HttpClient::new(http_config)?;
        let pool = Pool::new(config.concurrency);

        Ok(Self { http, pool, config })
    }

    pub async fn page(&self, url: &str) -> Result<Page> {
        let _guard = self.pool.acquire().await?;
        let resp = self.http.get(url).await?;
        Ok(Page::new(resp.url, resp.status, &resp.body))
    }

    pub fn close(&self) {
        self.pool.close();
    }
}
