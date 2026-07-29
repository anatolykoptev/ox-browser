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
        // The profile is the single identity source of truth. HttpClient::new
        // derives the TLS/HTTP2 Emulation from it via profile_to_emulation —
        // no call site sets emulation independently. (Issue #81: one identity)
        let http_config = HttpConfig {
            timeout: config.timeout,
            user_agent: config.user_agent.clone(),
            proxy_url: config.proxy_url.clone(),
            max_redirects: config.max_redirects,
            profile: config.profile,
            proxy_pool: config.proxy_pool.clone(),
            retry: config.retry.clone(),
            debug: config.debug,
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

    /// Fetch a URL with a custom method, optional body, and optional
    /// content type. For plain GETs prefer [`page`](Self::page).
    ///
    /// The caller is responsible for method/body validation (e.g. rejecting
    /// a body with GET). The retry middleware gates retries on method
    /// idempotency — POST and PATCH are not retried (issue #114).
    pub async fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
    ) -> Result<Page> {
        let _guard = self.pool.acquire().await?;
        let resp = self
            .http
            .request(method, url, body, content_type, &[])
            .await?;
        Ok(Page::new(resp.url, resp.status, &resp.body))
    }

    pub fn close(&self) {
        self.pool.close();
    }
}
